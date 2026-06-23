package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adnope/quiver/internal/config"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	kafkapub "github.com/adnope/quiver/internal/kafka"
)

func TestZeekConnIngestValidBatchPublishesRawEvents(t *testing.T) {
	t.Parallel()

	publisher := newImmediatePublisher()
	handler := newTestServer(t, validAPICfg(), publisher)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newZeekIngestRequest(t, zeekBody(validZeekObject()), "zeek-key"))

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response IngestResponse
	decodeJSON(t, recorder, &response)
	if response.Accepted != 1 || response.Rejected != 0 {
		t.Fatalf("response = %+v", response)
	}

	events := publisher.rawEvents()
	if len(events) != 1 {
		t.Fatalf("published event count = %d, want 1", len(events))
	}
	source := events[0].GetSource()
	if source.GetCollectorId() != "zeek-conn-http" {
		t.Fatalf("collector_id = %q", source.GetCollectorId())
	}
	if source.GetSourceType() != flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON {
		t.Fatalf("source_type = %s", source.GetSourceType())
	}
	if source.GetSourceHost() != "zeek-probe-01" {
		t.Fatalf("source_host = %q, want API-key mapped host", source.GetSourceHost())
	}
	if events[0].GetPayload().GetZeekConn().GetUid() != "Czeek001" {
		t.Fatalf("zeek uid not mapped")
	}
}

func TestZeekConnIngestAcceptsRawLineStrings(t *testing.T) {
	t.Parallel()

	rawLine, err := json.Marshal(validZeekObject())
	if err != nil {
		t.Fatalf("marshal zeek line: %v", err)
	}
	rawLineString, err := json.Marshal(string(rawLine))
	if err != nil {
		t.Fatalf("marshal zeek line string: %v", err)
	}

	publisher := newImmediatePublisher()
	handler := newTestServer(t, validAPICfg(), publisher)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newZeekIngestRequest(t, `{"records":[`+string(rawLineString)+`]}`, "zeek-key"))

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(publisher.rawEvents()) != 1 {
		t.Fatalf("published event count = %d, want 1", len(publisher.rawEvents()))
	}
}

func TestZeekConnIngestMalformedRecordPublishesDLQ(t *testing.T) {
	t.Parallel()

	malformedLine, err := json.Marshal("{bad-json")
	if err != nil {
		t.Fatalf("marshal malformed line: %v", err)
	}
	publisher := newImmediatePublisher()
	handler := newTestServer(t, validAPICfg(), publisher)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newZeekIngestRequest(t, `{"records":[`+validZeekJSON()+`,`+string(malformedLine)+`]}`, "zeek-key"))

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response IngestResponse
	decodeJSON(t, recorder, &response)
	if response.Accepted != 1 || response.Rejected != 1 || len(response.Errors) != 1 {
		t.Fatalf("response = %+v", response)
	}
	if response.Errors[0].Index != 1 || response.Errors[0].Code != "invalid_zeek_conn" {
		t.Fatalf("record error = %+v", response.Errors[0])
	}

	dlq := publisher.deadLetterEvents()
	if len(dlq) != 1 {
		t.Fatalf("dead-letter count = %d, want 1", len(dlq))
	}
	if dlq[0].GetSource().GetSourceHost() != "zeek-probe-01" {
		t.Fatalf("dlq source_host = %q", dlq[0].GetSource().GetSourceHost())
	}
	if dlq[0].GetError().GetErrorCode() != "invalid_zeek_conn" {
		t.Fatalf("dlq error code = %q", dlq[0].GetError().GetErrorCode())
	}
}

func TestZeekConnIngestAuthValidationAndPublisherFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		apiKey    string
		body      string
		publisher *testPublisher
		mutateCfg func(*config.Config)
		wantCode  int
		wantError string
	}{
		{name: "missing key", body: zeekBody(validZeekObject()), publisher: newImmediatePublisher(), wantCode: http.StatusUnauthorized, wantError: CodeMissingAPIKey},
		{name: "wrong scope", apiKey: "query-key", body: zeekBody(validZeekObject()), publisher: newImmediatePublisher(), wantCode: http.StatusForbidden, wantError: CodeInsufficientScope},
		{name: "malformed body", apiKey: "zeek-key", body: `{"records":`, publisher: newImmediatePublisher(), wantCode: http.StatusBadRequest, wantError: CodeInvalidRequest},
		{
			name:      "too many records",
			apiKey:    "zeek-key",
			body:      `{"records":[` + validZeekJSON() + `,` + validZeekJSON() + `]}`,
			publisher: newImmediatePublisher(),
			mutateCfg: func(cfg *config.Config) { cfg.ZeekIngest.MaxBatchSize = 1 },
			wantCode:  http.StatusBadRequest,
			wantError: CodeInvalidRequest,
		},
		{
			name:      "queue full",
			apiKey:    "zeek-key",
			body:      zeekBody(validZeekObject()),
			publisher: &testPublisher{err: kafkapub.ErrQueueFull},
			wantCode:  http.StatusTooManyRequests,
			wantError: CodeRateLimitExceeded,
		},
		{
			name:      "kafka unavailable",
			apiKey:    "zeek-key",
			body:      zeekBody(validZeekObject()),
			publisher: &testPublisher{err: errors.New("broker unavailable")},
			wantCode:  http.StatusServiceUnavailable,
			wantError: CodeServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validAPICfg()
			if tt.mutateCfg != nil {
				tt.mutateCfg(&cfg)
			}
			handler := newTestServer(t, cfg, tt.publisher)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, newZeekIngestRequest(t, tt.body, tt.apiKey))

			if recorder.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d, body = %s", recorder.Code, tt.wantCode, recorder.Body.String())
			}
			var response ErrorResponse
			decodeJSON(t, recorder, &response)
			if response.Error.Code != tt.wantError {
				t.Fatalf("error code = %q, want %q", response.Error.Code, tt.wantError)
			}
		})
	}
}

func newZeekIngestRequest(t *testing.T, body string, apiKey string) *http.Request {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/zeek/conn", strings.NewReader(body))
	request.RemoteAddr = "203.0.113.20:54321"
	request.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		request.Header.Set(APIKeyHeader, apiKey)
	}
	return request
}

func zeekBody(record map[string]any) string {
	return `{"records":[` + validZeekJSONFromMap(record) + `]}`
}

func validZeekJSON() string {
	return validZeekJSONFromMap(validZeekObject())
}

func validZeekJSONFromMap(record map[string]any) string {
	data, err := json.Marshal(record)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func validZeekObject() map[string]any {
	return map[string]any{
		"ts":         1718532921.25,
		"uid":        "Czeek001",
		"id.orig_h":  "192.168.1.50",
		"id.orig_p":  49152,
		"id.resp_h":  "8.8.8.8",
		"id.resp_p":  53,
		"proto":      "udp",
		"service":    "dns",
		"duration":   0.045,
		"orig_bytes": 42,
		"resp_bytes": 84,
		"orig_pkts":  1,
		"resp_pkts":  1,
		"conn_state": "SF",
	}
}
