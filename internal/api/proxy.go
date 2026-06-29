package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/adnope/quiver/internal/collector"
	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/observability"
)

const (
	ProxyProtocolHeader  = "X-Quiver-Proxy-Protocol"
	ProxyProtocolV2      = "2"
	maxProxyClockSkew    = 5 * time.Minute
	maxProxyTimestampAge = 24 * time.Hour
)

type PacketRouter interface {
	HandlePacket(
		ctx context.Context,
		allowedCollectorIDs map[string]struct{},
		input collector.PacketInput,
	) (collector.PacketResult, error)
}

type ProxyRecord struct {
	SourceIP   string    `json:"source_ip"`
	PacketData string    `json:"packet_data"`
	ReceivedAt time.Time `json:"received_at"`

	receivedAtPresent bool
	receivedAtInvalid bool
}

func (r *ProxyRecord) UnmarshalJSON(data []byte) error {
	type wireRecord struct {
		SourceIP   string          `json:"source_ip"`
		PacketData string          `json:"packet_data"`
		ReceivedAt json.RawMessage `json:"received_at"`
	}
	var wire wireRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("proxy record must contain one json object")
	}

	r.SourceIP = wire.SourceIP
	r.PacketData = wire.PacketData
	r.receivedAtPresent = len(wire.ReceivedAt) > 0 && string(wire.ReceivedAt) != "null"
	if !r.receivedAtPresent {
		return nil
	}
	if err := json.Unmarshal(wire.ReceivedAt, &r.ReceivedAt); err != nil {
		r.receivedAtInvalid = true
		r.ReceivedAt = time.Time{}
	}
	return nil
}

type ProxyRequest struct {
	Records []ProxyRecord `json:"records"`
}

type ProxyResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}

type ProxyRecordResult struct {
	Index     int                    `json:"index"`
	Status    collector.PacketStatus `json:"status"`
	ErrorCode string                 `json:"error_code,omitempty"`
}

type ProxyV2Response struct {
	Accepted  int                 `json:"accepted"`
	Retryable int                 `json:"retryable"`
	Rejected  int                 `json:"rejected"`
	Results   []ProxyRecordResult `json:"results"`
}

type ProxyHandler struct {
	maxBatchSize        int
	maxRequestBodyBytes int64
	router              PacketRouter
	metrics             *observability.Registry
	now                 func() time.Time
}

func NewProxyHandler(cfg config.Config, router PacketRouter, metrics *observability.Registry) *ProxyHandler {
	maxRequestBodyBytes := cfg.API.MaxRequestBodyBytes
	if maxRequestBodyBytes <= 0 {
		maxRequestBodyBytes = config.DefaultMaxRequestBodyBytes
	}
	return &ProxyHandler{
		maxBatchSize:        config.DefaultMaxBatchSize,
		maxRequestBodyBytes: maxRequestBodyBytes,
		router:              router,
		metrics:             metrics,
		now:                 time.Now,
	}
}

// ServeHTTP proxies authenticated NetFlow datagrams to the configured version router.
// @Summary Proxy NetFlow packets
// @Description Accepts gzip or plain JSON batches. Set X-Quiver-Proxy-Protocol to 2 for per-record results.
// @Tags ingest
// @Accept json
// @Produce json
// @Param X-Quiver-Proxy-Protocol header string false "Response protocol version" Enums(2)
// @Param request body ProxyRequest true "NetFlow packet batch"
// @Success 202 {object} ProxyV2Response
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 413 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/ingest/proxy-netflow [post]
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || principal.SourceHost == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","message":"invalid API key or missing source_host"}`))
		return
	}

	if h.router == nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable, "netflow packet router unavailable", nil)
		return
	}

	req, ok := h.decodeRequest(w, r)
	if !ok {
		return
	}
	response := h.processRecords(r.Context(), principal, req.Records)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if r.Header.Get(ProxyProtocolHeader) == ProxyProtocolV2 {
		_ = json.NewEncoder(w).Encode(response)
		return
	}
	_ = json.NewEncoder(w).Encode(ProxyResponse{
		Accepted: response.Accepted,
		Rejected: response.Rejected + response.Retryable,
	})
}

func (h *ProxyHandler) decodeRequest(w http.ResponseWriter, r *http.Request) (ProxyRequest, bool) {
	compressedBody := http.MaxBytesReader(w, r.Body, h.maxRequestBodyBytes)
	defer func() { _ = compressedBody.Close() }()
	var bodyReader io.Reader = compressedBody
	if r.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(compressedBody)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "invalid gzip encoding", nil)
			return ProxyRequest{}, false
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
			return ProxyRequest{}, false
		}
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "invalid json body", nil)
		return ProxyRequest{}, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "request body must contain one json object", nil)
		return ProxyRequest{}, false
	}
	if len(req.Records) == 0 {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "records is required", nil)
		return ProxyRequest{}, false
	}
	if len(req.Records) > h.maxBatchSize {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "batch contains too many records", nil)
		return ProxyRequest{}, false
	}
	return req, true
}

func (h *ProxyHandler) processRecords(ctx context.Context, principal Principal, records []ProxyRecord) ProxyV2Response {
	response := ProxyV2Response{Results: make([]ProxyRecordResult, 0, len(records))}
	for index, record := range records {
		result := h.processRecord(ctx, principal, record)
		response.Results = append(response.Results, ProxyRecordResult{
			Index:     index,
			Status:    result.Status,
			ErrorCode: result.ErrorCode,
		})
		switch result.Status {
		case collector.PacketAccepted:
			response.Accepted++
		case collector.PacketRetryable:
			response.Retryable++
		case collector.PacketRejected:
			response.Rejected++
		default:
			response.Retryable++
		}
	}
	return response
}

func (h *ProxyHandler) processRecord(ctx context.Context, principal Principal, record ProxyRecord) collector.PacketResult {
	packet, err := base64.StdEncoding.DecodeString(record.PacketData)
	if err != nil {
		return h.trackPacketResult(packet, collector.PacketResult{Status: collector.PacketRejected, ErrorCode: "invalid_base64"})
	}
	sourceIP, err := netip.ParseAddr(record.SourceIP)
	if err != nil {
		return h.trackPacketResult(packet, collector.PacketResult{Status: collector.PacketRejected, ErrorCode: "invalid_source_ip"})
	}

	backendReceivedAt := h.now().UTC()
	proxyReceivedAt := h.validProxyTimestamp(record, backendReceivedAt)
	result, err := h.router.HandlePacket(ctx, principal.AllowedCollectorIDs, collector.PacketInput{
		SourceIP:        sourceIP.Unmap(),
		SourceHost:      principal.SourceHost,
		ReceivedAt:      backendReceivedAt,
		ProxyReceivedAt: proxyReceivedAt,
		Data:            packet,
	})
	if err != nil {
		if result.ErrorCode == "" {
			result.ErrorCode = "internal_error"
		}
		result.Status = collector.PacketRetryable
	}
	if result.Status == "" {
		result = collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "internal_error"}
	}
	return h.trackPacketResult(packet, result)
}

func (h *ProxyHandler) trackPacketResult(packet []byte, result collector.PacketResult) collector.PacketResult {
	if h.metrics == nil {
		return result
	}
	version := "unknown"
	if len(packet) >= 2 {
		version = strconv.Itoa(int(binary.BigEndian.Uint16(packet[:2])))
	}
	reason := result.ErrorCode
	if reason == "" {
		reason = "none"
	}
	h.metrics.Inc("proxy_netflow_packets_total", map[string]string{
		"version": version,
		"status":  string(result.Status),
		"reason":  reason,
	})
	return result
}

func (h *ProxyHandler) validProxyTimestamp(record ProxyRecord, backendReceivedAt time.Time) *time.Time {
	isPresent := record.receivedAtPresent || !record.ReceivedAt.IsZero()
	if !isPresent {
		return nil
	}
	receivedAt := record.ReceivedAt.UTC()
	isTooFarFuture := receivedAt.After(backendReceivedAt.Add(maxProxyClockSkew))
	isTooOld := receivedAt.Before(backendReceivedAt.Add(-maxProxyTimestampAge))
	if record.receivedAtInvalid || receivedAt.IsZero() || isTooFarFuture || isTooOld {
		if h.metrics != nil {
			h.metrics.Inc("proxy_netflow_invalid_timestamps_total", map[string]string{"reason": proxyTimestampReason(record, isTooFarFuture, isTooOld)})
		}
		return nil
	}
	return &receivedAt
}

func proxyTimestampReason(record ProxyRecord, isTooFarFuture bool, isTooOld bool) string {
	switch {
	case record.receivedAtInvalid || record.ReceivedAt.IsZero():
		return "invalid"
	case isTooFarFuture:
		return "future"
	case isTooOld:
		return "old"
	default:
		return "invalid"
	}
}
