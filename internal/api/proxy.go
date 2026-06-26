package api

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/adnope/quiver/internal/config"
)

type InjectableCollector interface {
	HandlePacket(ctx context.Context, sourceIP netip.Addr, sourceHost string, data []byte) error
}

type ProxyRecord struct {
	SourceIP   string    `json:"source_ip"`
	PacketData string    `json:"packet_data"`
	ReceivedAt time.Time `json:"received_at"`
}

type ProxyRequest struct {
	Records []ProxyRecord `json:"records"`
}

type ProxyHandler struct {
	maxBatchSize        int
	maxRequestBodyBytes int64
	collector           InjectableCollector
}

func NewProxyHandler(cfg config.Config, collector InjectableCollector) *ProxyHandler {
	maxRequestBodyBytes := cfg.API.MaxRequestBodyBytes
	if maxRequestBodyBytes <= 0 {
		maxRequestBodyBytes = config.DefaultMaxRequestBodyBytes
	}
	return &ProxyHandler{
		maxBatchSize:        config.DefaultMaxBatchSize,
		maxRequestBodyBytes: maxRequestBodyBytes,
		collector:           collector,
	}
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || principal.SourceHost == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","message":"invalid API key or missing source_host"}`))
		return
	}

	if h.collector == nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable, "netflow collector unavailable", nil)
		return
	}

	compressedBody := http.MaxBytesReader(w, r.Body, h.maxRequestBodyBytes)
	defer func() { _ = compressedBody.Close() }()
	var bodyReader io.Reader = compressedBody
	if r.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(compressedBody)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "invalid gzip encoding", nil)
			return
		}
		defer func() { _ = gzipReader.Close() }()
		decompressedBody := http.MaxBytesReader(w, io.NopCloser(gzipReader), h.maxRequestBodyBytes)
		defer func() { _ = decompressedBody.Close() }()
		bodyReader = decompressedBody
	}

	var req ProxyRequest
	decoder := json.NewDecoder(bodyReader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, r, http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "request body too large", nil)
			return
		}
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "invalid json body", nil)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "request body must contain one json object", nil)
		return
	}
	if len(req.Records) == 0 {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "records is required", nil)
		return
	}
	if len(req.Records) > h.maxBatchSize {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "batch contains too many records", nil)
		return
	}

	var accepted int
	var rejected int

	for _, rec := range req.Records {
		rawBytes, err := base64.StdEncoding.DecodeString(rec.PacketData)
		if err != nil {
			rejected++
			continue
		}
		sourceIP, err := netip.ParseAddr(rec.SourceIP)
		if err != nil {
			rejected++
			continue
		}

		if err := h.collector.HandlePacket(r.Context(), sourceIP, principal.SourceHost, rawBytes); err != nil {
			rejected++
		} else {
			accepted++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]int{
		"accepted": accepted,
		"rejected": rejected,
	})
}
