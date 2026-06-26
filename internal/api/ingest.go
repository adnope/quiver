package api

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/validation"
)

type IngestHandler struct {
	collectorID         string
	maxBatchSize        int
	maxRequestBodyBytes int64
	publisher           kafka.RawEventPublisher
	now                 func() time.Time
}

type IngestRequest struct {
	SourceHost string         `json:"source_host,omitempty"`
	Records    []IngestRecord `json:"records"`
}

type IngestRecord struct {
	ExternalID          string         `json:"external_id,omitempty"`
	EventStartTime      string         `json:"event_start_time"`
	EventEndTime        string         `json:"event_end_time,omitempty"`
	SrcIP               string         `json:"src_ip"`
	DstIP               string         `json:"dst_ip"`
	SrcPort             *uint32        `json:"src_port,omitempty"`
	DstPort             *uint32        `json:"dst_port,omitempty"`
	TransportProtocol   string         `json:"transport_protocol"`
	ProtocolNumber      uint32         `json:"protocol_number"`
	Bytes               *uint64        `json:"bytes,omitempty"`
	Packets             *uint64        `json:"packets,omitempty"`
	ApplicationProtocol string         `json:"application_protocol,omitempty"`
	TCPFlags            *uint32        `json:"tcp_flags,omitempty"`
	SamplingRate        *uint32        `json:"sampling_rate,omitempty"`
	Attributes          map[string]any `json:"attributes,omitempty"`
}

type IngestResponse struct {
	Accepted int                 `json:"accepted"`
	Rejected int                 `json:"rejected"`
	Errors   []IngestRecordError `json:"errors"`
}

type IngestRecordError struct {
	Index   int    `json:"index"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewIngestHandler(cfg config.Config, publisher kafka.RawEventPublisher) *IngestHandler {
	return &IngestHandler{
		collectorID:         cfg.RestIngest.CollectorID,
		maxBatchSize:        cfg.RestIngest.MaxBatchSize,
		maxRequestBodyBytes: cfg.API.MaxRequestBodyBytes,
		publisher:           publisher,
		now:                 time.Now,
	}
}

// ServeHTTP godoc
// @Summary Ingest normalized-like flow records
// @Description Publishes valid REST records as flow.v1.RawFlowEventEnvelope protobuf messages after Kafka ACK. Requires X-API-Key with ingest scope.
// @Tags ingest
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param X-API-Key header string true "API key with ingest scope"
// @Param X-Request-ID header string false "Optional request ID"
// @Param request body IngestRequest true "REST ingest batch"
// @Success 202 {object} IngestResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 413 {object} ErrorResponse
// @Failure 429 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Router /api/v1/ingest/flows [post]
func (h *IngestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.publisher == nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable, "publisher unavailable", nil)
		return
	}
	if h.maxRequestBodyBytes <= 0 {
		writeError(w, r, http.StatusInternalServerError, CodeInternalError, "server is misconfigured", nil)
		return
	}
	body := http.MaxBytesReader(w, r.Body, h.maxRequestBodyBytes)
	defer func() {
		_ = body.Close()
	}()

	var request IngestRequest
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, r, http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "request body too large", nil)
			return
		}
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "malformed json body", nil)
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "request body must contain one json object", nil)
		return
	}
	if len(request.Records) == 0 {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "records is required", nil)
		return
	}
	if len(request.Records) > h.maxBatchSize {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "batch contains too many records", nil)
		return
	}

	principal, ok := PrincipalFromContext(r.Context())
	if !ok || strings.TrimSpace(principal.SourceHost) == "" {
		writeError(w, r, http.StatusForbidden, CodeInsufficientScope, "api key is not configured for rest ingest source identity", nil)
		return
	}

	type publishResult struct {
		valErr *recordValidationError
		pubErr error
	}

	results := make([]publishResult, len(request.Records))
	sem := make(chan struct{}, 50)
	var wg sync.WaitGroup
	ctx := r.Context()

	for index, record := range request.Records {
		wg.Add(1)
		go func(idx int, rec IngestRecord) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			event, valErr := h.recordToEvent(r.WithContext(ctx), principal.SourceHost, rec)
			if valErr != nil {
				results[idx] = publishResult{valErr: valErr}
				return
			}

			if err := h.publisher.PublishRaw(ctx, event); err != nil {
				results[idx] = publishResult{pubErr: err}
				return
			}
		}(index, record)
	}

	wg.Wait()

	// Check if there was any publisher error
	var queueFullErr error
	var otherPubErr error
	for _, res := range results {
		if res.pubErr != nil {
			if errors.Is(res.pubErr, kafka.ErrQueueFull) {
				queueFullErr = res.pubErr
			} else {
				otherPubErr = res.pubErr
			}
		}
	}

	if queueFullErr != nil {
		writeError(w, r, http.StatusTooManyRequests, CodeRateLimitExceeded, "publisher queue full", nil)
		return
	}
	if otherPubErr != nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable, "kafka unavailable", nil)
		return
	}

	response := IngestResponse{Errors: []IngestRecordError{}}
	for idx, res := range results {
		if res.valErr != nil {
			response.Rejected++
			response.Errors = append(response.Errors, IngestRecordError{
				Index:   idx,
				Code:    res.valErr.Code,
				Message: res.valErr.Message,
			})
		} else {
			response.Accepted++
		}
	}
	writeJSON(w, http.StatusAccepted, response)
}

type recordValidationError struct {
	Code    string
	Message string
}

func (h *IngestHandler) recordToEvent(r *http.Request, sourceHost string, record IngestRecord) (*flowv1.RawFlowEventEnvelope, *recordValidationError) {
	input, err := restRecordToProto(record)
	if err != nil {
		return nil, err
	}
	eventID, genErr := domain.NewUUIDv7(h.now())
	if genErr != nil {
		return nil, &recordValidationError{Code: "id_generation_failed", Message: "failed to generate event id"}
	}
	sourceIP := clientIP(r)
	source := &flowv1.SourceIdentity{
		CollectorId: h.collectorID,
		SourceType:  flowv1.SourceType_SOURCE_TYPE_REST_JSON,
		SourceHost:  sourceHost,
	}
	if sourceIP != "" {
		source.SourceIp = &sourceIP
	}
	event := &flowv1.RawFlowEventEnvelope{
		EventId:       eventID,
		SchemaVersion: domain.RawSchemaVersion,
		Source:        source,
		ReceivedAt:    timestamppb.New(h.now().UTC()),
		PartitionKey:  validation.PartitionKey(source),
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_RestFlow{RestFlow: input},
		},
	}
	if err := validation.ValidateRawEventEnvelope(event); err != nil {
		return nil, &recordValidationError{Code: "invalid_record", Message: err.Error()}
	}
	return event, nil
}

func restRecordToProto(record IngestRecord) (*flowv1.RestFlowInput, *recordValidationError) {
	start, err := parseRequiredTime(record.EventStartTime)
	if err != nil {
		return nil, &recordValidationError{Code: "invalid_event_start_time", Message: "event_start_time must be RFC3339"}
	}
	var end *timestamppb.Timestamp
	if strings.TrimSpace(record.EventEndTime) != "" {
		parsedEnd, err := time.Parse(time.RFC3339Nano, record.EventEndTime)
		if err != nil {
			return nil, &recordValidationError{Code: "invalid_event_end_time", Message: "event_end_time must be RFC3339"}
		}
		if parsedEnd.Before(start.AsTime()) {
			return nil, &recordValidationError{Code: "invalid_event_end_time", Message: "event_end_time must not be before event_start_time"}
		}
		end = timestamppb.New(parsedEnd.UTC())
	}
	src, err := netip.ParseAddr(record.SrcIP)
	if err != nil || !src.IsValid() {
		return nil, &recordValidationError{Code: "invalid_src_ip", Message: "src_ip must be a valid IPv4 or IPv6 address"}
	}
	dst, err := netip.ParseAddr(record.DstIP)
	if err != nil || !dst.IsValid() {
		return nil, &recordValidationError{Code: "invalid_dst_ip", Message: "dst_ip must be a valid IPv4 or IPv6 address"}
	}
	if record.ProtocolNumber > math.MaxUint8 {
		return nil, &recordValidationError{Code: "invalid_protocol_number", Message: "protocol_number must be within 0..255"}
	}
	protocol, ok := domain.ParseTransportProtocol(record.TransportProtocol)
	if !ok || protocol == domain.TransportProtocolUnknown {
		return nil, &recordValidationError{Code: "invalid_transport_protocol", Message: "transport_protocol is invalid"}
	}
	if requiresPorts(protocol) {
		if invalidPort(record.SrcPort) {
			return nil, &recordValidationError{Code: "invalid_src_port", Message: "src_port must be within 0..65535"}
		}
		if invalidPort(record.DstPort) {
			return nil, &recordValidationError{Code: "invalid_dst_port", Message: "dst_port must be within 0..65535"}
		}
	}
	attributes, err := structpb.NewStruct(record.Attributes)
	if err != nil {
		return nil, &recordValidationError{Code: "invalid_attributes", Message: "attributes must be a JSON object"}
	}

	input := &flowv1.RestFlowInput{
		EventStartTime: start,
		EventEndTime:   end,
		Tuple: &flowv1.NetworkTuple{
			SrcIp:             new(record.SrcIP),
			DstIp:             new(record.DstIP),
			SrcPort:           record.SrcPort,
			DstPort:           record.DstPort,
			TransportProtocol: protoTransportProtocol(protocol),
			ProtocolNumber:    record.ProtocolNumber,
		},
		Counters: &flowv1.CounterFields{
			Bytes:   record.Bytes,
			Packets: record.Packets,
		},
		Attributes: attributes,
	}
	if strings.TrimSpace(record.ExternalID) != "" {
		input.ExternalId = new(record.ExternalID)
	}
	if strings.TrimSpace(record.ApplicationProtocol) != "" {
		input.ApplicationProtocol = new(record.ApplicationProtocol)
	}
	input.TcpFlags = record.TCPFlags
	input.SamplingRate = record.SamplingRate
	return input, nil
}

func parseRequiredTime(value string) (*timestamppb.Timestamp, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, err
	}
	return timestamppb.New(parsed.UTC()), nil
}

func invalidPort(value *uint32) bool {
	return value == nil || *value > math.MaxUint16
}

func requiresPorts(protocol domain.TransportProtocol) bool {
	return protocol == domain.TransportProtocolTCP || protocol == domain.TransportProtocolUDP
}

func protoTransportProtocol(protocol domain.TransportProtocol) flowv1.TransportProtocol {
	switch protocol {
	case domain.TransportProtocolUnknown:
		return flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UNKNOWN
	case domain.TransportProtocolTCP:
		return flowv1.TransportProtocol_TRANSPORT_PROTOCOL_TCP
	case domain.TransportProtocolUDP:
		return flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UDP
	case domain.TransportProtocolICMP:
		return flowv1.TransportProtocol_TRANSPORT_PROTOCOL_ICMP
	case domain.TransportProtocolGRE:
		return flowv1.TransportProtocol_TRANSPORT_PROTOCOL_GRE
	case domain.TransportProtocolESP:
		return flowv1.TransportProtocol_TRANSPORT_PROTOCOL_ESP
	case domain.TransportProtocolOther:
		return flowv1.TransportProtocol_TRANSPORT_PROTOCOL_OTHER
	default:
		return flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UNKNOWN
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	if addr, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		return addr.String()
	}
	return ""
}
