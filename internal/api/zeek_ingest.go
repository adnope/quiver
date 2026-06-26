package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/adnope/quiver/internal/collector/zeek"
	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/validation"
)

type ZeekConnIngestHandler struct {
	collectorID         string
	maxBatchSize        int
	maxRequestBodyBytes int64
	deadLetterMaxBytes  int
	publisher           kafka.RawEventPublisher
	now                 func() time.Time
}

type ZeekConnIngestRequest struct {
	Records []json.RawMessage `json:"records"`
}

func NewZeekConnIngestHandler(cfg config.Config, publisher kafka.RawEventPublisher) *ZeekConnIngestHandler {
	return &ZeekConnIngestHandler{
		collectorID:         cfg.ZeekIngest.CollectorID,
		maxBatchSize:        cfg.ZeekIngest.MaxBatchSize,
		maxRequestBodyBytes: cfg.API.MaxRequestBodyBytes,
		deadLetterMaxBytes:  cfg.DeadLetter.MaxRawPacketBytes,
		publisher:           publisher,
		now:                 time.Now,
	}
}

// ServeHTTP godoc
// @Summary Ingest Zeek conn.log records
// @Description Accepts Zeek conn.log JSON object batches, or JSON strings containing raw Zeek JSON lines, from authenticated log shippers. Valid records publish as flow.v1.RawFlowEventEnvelope protobuf messages after Kafka ACK. Invalid records publish to the dead-letter topic.
// @Tags ingest
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param X-API-Key header string true "API key with ingest scope and source_host mapping"
// @Param X-Request-ID header string false "Optional request ID"
// @Param request body ZeekConnIngestRequest true "Zeek conn.log batch"
// @Success 202 {object} IngestResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 413 {object} ErrorResponse
// @Failure 429 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Router /api/v1/ingest/zeek/conn [post]
func (h *ZeekConnIngestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.publisher == nil {
		writeError(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable, "publisher unavailable", nil)
		return
	}
	if h.maxRequestBodyBytes <= 0 || strings.TrimSpace(h.collectorID) == "" {
		writeError(w, r, http.StatusInternalServerError, CodeInternalError, "server is misconfigured", nil)
		return
	}
	body := http.MaxBytesReader(w, r.Body, h.maxRequestBodyBytes)
	defer func() {
		_ = body.Close()
	}()

	var request ZeekConnIngestRequest
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
		writeError(w, r, http.StatusForbidden, CodeInsufficientScope, "api key is not configured for zeek ingest source identity", nil)
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

	for index, raw := range request.Records {
		wg.Add(1)
		go func(idx int, rawRecord json.RawMessage) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			line, recordErr := zeekRecordBytes(rawRecord)
			if recordErr != nil {
				results[idx] = publishResult{valErr: recordErr}
				return
			}

			event, recordErr := h.recordToEvent(r.WithContext(ctx), principal.SourceHost, line)
			if recordErr != nil {
				if err := h.publishDeadLetter(r.WithContext(ctx), principal.SourceHost, line, recordErr.Code, recordErr.Message); err != nil {
					results[idx] = publishResult{pubErr: err}
					return
				}
				results[idx] = publishResult{valErr: recordErr}
				return
			}

			if err := h.publisher.PublishRaw(ctx, event); err != nil {
				results[idx] = publishResult{pubErr: err}
				return
			}
		}(index, raw)
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
		writePublisherError(w, r, queueFullErr)
		return
	}
	if otherPubErr != nil {
		writePublisherError(w, r, otherPubErr)
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

func (h *ZeekConnIngestHandler) recordToEvent(
	r *http.Request,
	sourceHost string,
	line []byte,
) (*flowv1.RawFlowEventEnvelope, *recordValidationError) {
	flow, err := zeek.ParseConnLine(line)
	if err != nil {
		return nil, &recordValidationError{Code: "invalid_zeek_conn", Message: "invalid zeek conn record"}
	}
	eventID, genErr := domain.NewUUIDv7(h.now())
	if genErr != nil {
		return nil, &recordValidationError{Code: "id_generation_failed", Message: "failed to generate event id"}
	}
	sourceIP := clientIP(r)
	source := &flowv1.SourceIdentity{
		CollectorId: h.collectorID,
		SourceType:  flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON,
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
			Payload: &flowv1.RawEventPayload_ZeekConn{ZeekConn: flow},
		},
	}
	if err := validation.ValidateRawEventEnvelope(event); err != nil {
		return nil, &recordValidationError{Code: "invalid_record", Message: err.Error()}
	}
	return event, nil
}

func (h *ZeekConnIngestHandler) publishDeadLetter(
	r *http.Request,
	sourceHost string,
	line []byte,
	code string,
	message string,
) error {
	deadLetterID, err := domain.NewUUIDv7(h.now())
	if err != nil {
		return fmt.Errorf("generate dead-letter id: %w", err)
	}
	sourceIP := clientIP(r)
	source := &flowv1.SourceIdentity{
		CollectorId: h.collectorID,
		SourceType:  flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON,
		SourceHost:  sourceHost,
	}
	if sourceIP != "" {
		source.SourceIp = &sourceIP
	}
	payload, truncated := truncateDebugPayload(line, h.deadLetterMaxBytes)
	encoding := flowv1.PayloadEncoding_PAYLOAD_ENCODING_RAW_BYTES
	if truncated {
		encoding = flowv1.PayloadEncoding_PAYLOAD_ENCODING_TRUNCATED_RAW_BYTES
	}
	event := &flowv1.DeadLetterEvent{
		DeadLetterId:  deadLetterID,
		SchemaVersion: domain.RawSchemaVersion,
		Stage:         flowv1.IngestionStage_INGESTION_STAGE_PARSER,
		Source:        source,
		FailedAt:      timestamppb.New(h.now().UTC()),
		Error:         &flowv1.ErrorInfo{ErrorCode: code, ErrorMessage: message},
		RawPayloadDebug: &flowv1.RawPayloadDebug{
			Masked:            true,
			Encoding:          encoding,
			Data:              payload,
			Sha256:            sha256Hex(line),
			OriginalSizeBytes: uint64(len(line)),
			Truncated:         truncated,
		},
	}
	if err := validation.ValidateDeadLetterEvent(event); err != nil {
		return fmt.Errorf("validate dead-letter: %w", err)
	}
	if err := h.publisher.PublishDeadLetter(r.Context(), event); err != nil {
		return err
	}
	return nil
}

func zeekRecordBytes(raw json.RawMessage) ([]byte, *recordValidationError) {
	raw = bytesTrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, &recordValidationError{Code: "invalid_zeek_conn", Message: "record must be a Zeek JSON object or raw JSON line string"}
	}
	if raw[0] == '"' {
		var line string
		if err := json.Unmarshal(raw, &line); err != nil {
			return nil, &recordValidationError{Code: "invalid_zeek_conn", Message: "record string is invalid"}
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return nil, &recordValidationError{Code: "invalid_zeek_conn", Message: "record string is empty"}
		}
		return []byte(line), nil
	}
	return append([]byte(nil), raw...), nil
}

func bytesTrimSpace(data []byte) []byte {
	return []byte(strings.TrimSpace(string(data)))
}

func writePublisherError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, kafka.ErrQueueFull) {
		writeError(w, r, http.StatusTooManyRequests, CodeRateLimitExceeded, "publisher queue full", nil)
		return
	}
	writeError(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable, "kafka unavailable", nil)
}

func truncateDebugPayload(data []byte, maxBytes int) ([]byte, bool) {
	if maxBytes <= 0 {
		maxBytes = 1500
	}
	if len(data) <= maxBytes {
		return append([]byte(nil), data...), false
	}
	return append([]byte(nil), data[:maxBytes]...), true
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
