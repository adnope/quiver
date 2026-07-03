package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	kafkapub "github.com/adnope/quiver/internal/kafka"
)

func TestRESTIngestValidBatchWaitsForKafkaACK(t *testing.T) {
	t.Parallel()

	publisher := newBlockingPublisher()
	handler := newTestServer(t, validAPICfg(), publisher)
	request := newIngestRequest(t, validRESTBody(), "ingest-key")
	request.Header.Set(RequestIDHeader, "req-client")

	responseDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		responseDone <- recorder
	}()

	publisher.waitStarted(t)
	assertNoHTTPResponse(t, responseDone)
	publisher.ack(nil)
	recorder := <-responseDone

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get(RequestIDHeader); got != "req-client" {
		t.Fatalf("request id header = %q", got)
	}
	var body IngestResponse
	decodeJSON(t, recorder, &body)
	if body.Accepted != 1 || body.Rejected != 0 {
		t.Fatalf("response = %+v", body)
	}

	events := publisher.rawEvents()
	if len(events) != 1 {
		t.Fatalf("published event count = %d, want 1", len(events))
	}
	source := events[0].GetSource()
	if source.GetSourceHost() != "rest-client-host" {
		t.Fatalf("source_host = %q, want API-key mapped host", source.GetSourceHost())
	}
	if events[0].GetPayload().GetRestFlow().GetExternalId() != "client-flow-0001" {
		t.Fatalf("external id not mapped")
	}
}

func TestRESTIngestPartialBatch(t *testing.T) {
	t.Parallel()

	publisher := newImmediatePublisher()
	handler := newTestServer(t, validAPICfg(), publisher)
	body := `{"source_host":"ignored-body-host","records":[` + validRESTRecord() + `,{"src_ip":"bad"}]}`

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newIngestRequest(t, body, "ingest-key"))

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response IngestResponse
	decodeJSON(t, recorder, &response)
	if response.Accepted != 1 || response.Rejected != 1 || len(response.Errors) != 1 {
		t.Fatalf("response = %+v", response)
	}
	if response.Errors[0].Index != 1 {
		t.Fatalf("error index = %d, want 1", response.Errors[0].Index)
	}
}

func TestRESTIngestAuthScopeRateLimitAndRequestID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		apiKey    string
		mutateCfg func(*config.Config)
		wantCode  int
		wantError string
	}{
		{name: "missing key", wantCode: http.StatusUnauthorized, wantError: CodeMissingAPIKey},
		{name: "invalid key", apiKey: "wrong", wantCode: http.StatusUnauthorized, wantError: CodeInvalidAPIKey},
		{name: "wrong scope", apiKey: "query-key", wantCode: http.StatusForbidden, wantError: CodeInsufficientScope},
		{
			name:   "rate limited",
			apiKey: "ingest-key",
			mutateCfg: func(cfg *config.Config) {
				cfg.API.RateLimits.Ingest.RequestsPerMinute = 0
			},
			wantCode:  http.StatusTooManyRequests,
			wantError: CodeRateLimitExceeded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validAPICfg()
			if tt.mutateCfg != nil {
				tt.mutateCfg(&cfg)
			}
			recorder := httptest.NewRecorder()
			handler := newTestServer(t, cfg, newImmediatePublisher())
			handler.ServeHTTP(recorder, newIngestRequest(t, validRESTBody(), tt.apiKey))

			if recorder.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d, body = %s", recorder.Code, tt.wantCode, recorder.Body.String())
			}
			if recorder.Header().Get(RequestIDHeader) == "" {
				t.Fatal("missing generated request id")
			}
			var response ErrorResponse
			decodeJSON(t, recorder, &response)
			if response.Error.Code != tt.wantError {
				t.Fatalf("error code = %q, want %q", response.Error.Code, tt.wantError)
			}
		})
	}
}

func TestRESTIngestRequestValidationAndPublisherFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		publisher *testPublisher
		mutateCfg func(*config.Config)
		wantCode  int
		wantError string
	}{
		{name: "malformed json", body: `{"records":`, publisher: newImmediatePublisher(), wantCode: http.StatusBadRequest, wantError: CodeInvalidRequest},
		{
			name:      "too many records",
			body:      `{"records":[` + validRESTRecord() + `,` + validRESTRecord() + `]}`,
			publisher: newImmediatePublisher(),
			mutateCfg: func(cfg *config.Config) { cfg.RestIngest.MaxBatchSize = 1 },
			wantCode:  http.StatusBadRequest,
			wantError: CodeInvalidRequest,
		},
		{
			name:      "body too large",
			body:      validRESTBody(),
			publisher: newImmediatePublisher(),
			mutateCfg: func(cfg *config.Config) { cfg.API.MaxRequestBodyBytes = 8 },
			wantCode:  http.StatusRequestEntityTooLarge,
			wantError: CodePayloadTooLarge,
		},
		{
			name:      "queue full",
			body:      validRESTBody(),
			publisher: &testPublisher{err: kafkapub.ErrQueueFull},
			wantCode:  http.StatusTooManyRequests,
			wantError: CodeRateLimitExceeded,
		},
		{
			name:      "kafka unavailable",
			body:      validRESTBody(),
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
			recorder := httptest.NewRecorder()
			handler := newTestServer(t, cfg, tt.publisher)
			handler.ServeHTTP(recorder, newIngestRequest(t, tt.body, "ingest-key"))

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

func TestRestRecordToProto(t *testing.T) {
	t.Parallel()

	input, err := restRecordToProto(IngestRecord{
		ExternalID:          "flow-1",
		EventStartTime:      "2026-06-16T10:15:20Z",
		EventEndTime:        "2026-06-16T10:15:25Z",
		SrcIP:               "192.168.1.10",
		DstIP:               "8.8.8.8",
		SrcPort:             new(uint32(51524)),
		DstPort:             new(uint32(53)),
		TransportProtocol:   "udp",
		ProtocolNumber:      17,
		Bytes:               new(uint64(420)),
		Packets:             new(uint64(3)),
		ApplicationProtocol: "dns",
		Attributes:          map[string]any{"integration": "demo-client"},
	})
	if err != nil {
		t.Fatalf("restRecordToProto() error = %+v", err)
	}
	if input.GetExternalId() != "flow-1" || input.GetTuple().GetSrcIp() != "192.168.1.10" ||
		input.GetCounters().GetBytes() != 420 || input.GetApplicationProtocol() != "dns" {
		t.Fatalf("mapped input = %+v", input)
	}
}

func newTestServer(t *testing.T, cfg config.Config, publisher kafkapub.RawEventPublisher) http.Handler {
	t.Helper()

	server, err := NewServer(cfg, publisher, envLookup())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	return server.Handler()
}

func validAPICfg() config.Config {
	cfg := config.Default()
	cfg.RestIngest.Enabled = true
	cfg.RestIngest.CollectorID = "rest-ingest-main"
	cfg.RestIngest.MaxBatchSize = 1000
	cfg.RestIngest.APIKeys = []config.RESTAPIKeyConfig{{
		Name:       "demo-client",
		SourceHost: "rest-client-host",
		KeyEnv:     "REST_KEY",
	}}
	cfg.ZeekIngest.Enabled = true
	cfg.ZeekIngest.CollectorID = "zeek-conn-http"
	cfg.ZeekIngest.MaxBatchSize = 1000
	cfg.QuiverClientGateways = []config.QuiverClientGatewayConfig{{
		Name:       "zeek-shipper",
		SourceHost: "zeek-probe-01",
		KeyEnv:     "ZEEK_KEY",
	}}
	cfg.API.Keys = []config.APIKeyConfig{
		{
			Name:   "query-only",
			KeyEnv: "QUERY_KEY",
			Scopes: []string{"query"},
		},
		{
			Name:   "metrics-only",
			KeyEnv: "METRICS_KEY",
			Scopes: []string{"metrics"},
		},
	}
	cfg.API.RateLimits.Ingest.RequestsPerMinute = 60
	cfg.API.RateLimits.Query.RequestsPerMinute = 120
	cfg.API.RateLimits.Metrics.RequestsPerMinute = 60
	return cfg
}

func envLookup() func(string) string {
	values := map[string]string{
		"REST_KEY":    "ingest-key",
		"ZEEK_KEY":    "zeek-key",
		"QUERY_KEY":   "query-key",
		"METRICS_KEY": "metrics-key",
	}
	return func(key string) string {
		return values[key]
	}
}

func newIngestRequest(t *testing.T, body string, apiKey string) *http.Request {
	t.Helper()

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/flows", strings.NewReader(body))
	request.RemoteAddr = "203.0.113.10:54321"
	request.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		request.Header.Set(APIKeyHeader, apiKey)
	}
	return request
}

func validRESTBody() string {
	return `{"source_host":"ignored","records":[` + validRESTRecord() + `]}`
}

func validRESTRecord() string {
	return `{"external_id":"client-flow-0001","event_start_time":"2026-06-16T10:15:20Z","event_end_time":"2026-06-16T10:15:25Z","src_ip":"192.168.1.10","dst_ip":"8.8.8.8","src_port":51524,"dst_port":53,"transport_protocol":"udp","protocol_number":17,"bytes":420,"packets":3,"application_protocol":"dns","attributes":{"integration":"demo-client"}}`
}

type testPublisher struct {
	mu      sync.Mutex
	raw     []*flowv1.RawFlowEventEnvelope
	dlq     []*flowv1.DeadLetterEvent
	started chan struct{}
	release chan error
	err     error
}

func newImmediatePublisher() *testPublisher {
	return &testPublisher{}
}

func newBlockingPublisher() *testPublisher {
	return &testPublisher{
		started: make(chan struct{}, 1),
		release: make(chan error, 1),
	}
}

func (p *testPublisher) PublishRaw(ctx context.Context, event *flowv1.RawFlowEventEnvelope) error {
	p.mu.Lock()
	p.raw = append(p.raw, event)
	p.mu.Unlock()
	if p.started != nil {
		p.started <- struct{}{}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-p.release:
			return err
		}
	}
	return p.err
}

func (p *testPublisher) PublishDeadLetter(ctx context.Context, event *flowv1.DeadLetterEvent) error {
	p.mu.Lock()
	p.dlq = append(p.dlq, event)
	p.mu.Unlock()
	if p.started != nil {
		p.started <- struct{}{}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-p.release:
			return err
		}
	}
	return p.err
}

func (p *testPublisher) Flush(context.Context) error {
	return nil
}

func (p *testPublisher) waitStarted(t *testing.T) {
	t.Helper()

	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for publisher")
	}
}

func (p *testPublisher) ack(err error) {
	p.release <- err
}

func (p *testPublisher) rawEvents() []*flowv1.RawFlowEventEnvelope {
	p.mu.Lock()
	defer p.mu.Unlock()
	events := make([]*flowv1.RawFlowEventEnvelope, len(p.raw))
	copy(events, p.raw)
	return events
}

func (p *testPublisher) deadLetterEvents() []*flowv1.DeadLetterEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	events := make([]*flowv1.DeadLetterEvent, len(p.dlq))
	copy(events, p.dlq)
	return events
}

func decodeJSON(t *testing.T, recorder *httptest.ResponseRecorder, target any) {
	t.Helper()

	if err := json.NewDecoder(bytes.NewReader(recorder.Body.Bytes())).Decode(target); err != nil {
		t.Fatalf("decode response %q: %v", recorder.Body.String(), err)
	}
}

func assertNoHTTPResponse(t *testing.T, done <-chan *httptest.ResponseRecorder) {
	t.Helper()

	select {
	case recorder := <-done:
		t.Fatalf("response returned before Kafka ACK: status=%d body=%s", recorder.Code, recorder.Body.String())
	case <-time.After(20 * time.Millisecond):
	}
}

func TestCursorCodecFromConfigAndServerConstructorBranches(t *testing.T) {
	t.Parallel()

	cfg := validAPICfg()
	codec, err := cursorCodecFromConfig(cfg, nil)
	if codec != nil || !errors.Is(err, errCursorSecretNotConfigured) {
		t.Fatalf("nil lookup codec=%v err=%v", codec, err)
	}
	cfg.API.Cursor.HMACSecretEnv = "CURSOR_SECRET"
	_, err = cursorCodecFromConfig(cfg, func(string) string { return "short" })
	if !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("short secret error = %v, want ErrInvalidCursor", err)
	}
	codec, err = cursorCodecFromConfig(cfg, envLookupWithCursor())
	if err != nil || codec == nil {
		t.Fatalf("valid cursor codec=%v err=%v", codec, err)
	}

	cfgWithoutCursor := validAPICfg()
	_, err = NewServerWithStores(cfgWithoutCursor, newImmediatePublisher(), &fakeFlowStore{}, nil, envLookup())
	if !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("NewServerWithStores without cursor error = %v, want ErrInvalidCursor", err)
	}

	badAuthCfg := validAPICfg()
	badAuthCfg.API.Keys = []config.APIKeyConfig{{Name: "missing", KeyEnv: "MISSING_KEY", Scopes: []string{"query"}}}
	_, err = NewServer(badAuthCfg, newImmediatePublisher(), envLookup())
	if err == nil {
		t.Fatal("NewServer() with missing API key env succeeded")
	}

	var nilServer *Server
	recorder := httptest.NewRecorder()
	nilServer.Handler().ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/missing", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("nil server status = %d, want 404", recorder.Code)
	}
}

func TestIngestAndZeekPureHelpers(t *testing.T) {
	t.Parallel()

	if _, err := parseRequiredTime("bad"); err == nil {
		t.Fatal("bad time should fail")
	}
	port := uint32(65535)
	badPort := uint32(65536)
	if invalidPort(&port) || !invalidPort(nil) || !invalidPort(&badPort) {
		t.Fatal("invalidPort returned unexpected values")
	}
	if !requiresPorts(domain.TransportProtocolTCP) || !requiresPorts(domain.TransportProtocolUDP) || requiresPorts(domain.TransportProtocolICMP) {
		t.Fatal("requiresPorts returned unexpected values")
	}
	if protoTransportProtocol(domain.TransportProtocolGRE) != flowv1.TransportProtocol_TRANSPORT_PROTOCOL_GRE ||
		protoTransportProtocol(domain.TransportProtocol("unknown-value")) != flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UNKNOWN {
		t.Fatal("protoTransportProtocol returned unexpected values")
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:54321"
	if clientIP(req) != "203.0.113.10" {
		t.Fatalf("clientIP with port = %q", clientIP(req))
	}
	req.RemoteAddr = "203.0.113.11"
	if clientIP(req) != "203.0.113.11" {
		t.Fatalf("clientIP without port = %q", clientIP(req))
	}
	req.RemoteAddr = "bad addr"
	if clientIP(req) != "" {
		t.Fatalf("clientIP bad addr = %q", clientIP(req))
	}
	if data, validationErr := zeekRecordBytes(json.RawMessage(`"{\"ts\":1}"`)); validationErr != nil || string(data) != `{"ts":1}` {
		t.Fatalf("zeek string bytes=%s err=%+v", data, validationErr)
	}
	if _, validationErr := zeekRecordBytes(json.RawMessage(`""`)); validationErr == nil || validationErr.Code != "invalid_zeek_conn" {
		t.Fatalf("empty zeek string validationErr = %+v", validationErr)
	}
	if string(bytesTrimSpace([]byte(" \n demo \t"))) != "demo" {
		t.Fatal("bytesTrimSpace did not trim ASCII whitespace")
	}
	truncated, wasTruncated := truncateDebugPayload([]byte("abcdef"), 3)
	if string(truncated) != "abc" || !wasTruncated {
		t.Fatalf("truncateDebugPayload = %q/%v", truncated, wasTruncated)
	}
	if hash := sha256Hex([]byte("demo")); len(hash) != 64 {
		t.Fatalf("sha256Hex length = %d", len(hash))
	}
}
