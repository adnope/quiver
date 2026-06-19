package api

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
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
	cfg        config.Config
	collectors []InjectableCollector
}

func NewProxyHandler(cfg config.Config, collectors []InjectableCollector) *ProxyHandler {
	return &ProxyHandler{
		cfg:        cfg,
		collectors: collectors,
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

	var bodyReader io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid gzip encoding"}`))
			return
		}
		defer func() { _ = gzipReader.Close() }()
		bodyReader = gzipReader
	}

	var req ProxyRequest
	if err := json.NewDecoder(bodyReader).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid JSON body"}`))
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

		var relayErr error
		for _, col := range h.collectors {
			if err := col.HandlePacket(r.Context(), sourceIP, principal.SourceHost, rawBytes); err != nil {
				relayErr = err
			}
		}

		if relayErr != nil {
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
