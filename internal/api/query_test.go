package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/domain"
	"github.com/adnope/quiver/internal/storage/postgres"
)

func TestFlowSearchValidationAndPagination(t *testing.T) {
	t.Parallel()

	store := &fakeFlowStore{
		searchResult: postgres.FlowSearchResult{
			Records: []domain.NormalizedFlowRecord{validFlowRecord()},
			HasMore: true,
		},
	}
	handler := newQueryTestServer(t, store, nil)

	tests := []struct {
		name      string
		target    string
		apiKey    string
		wantCode  int
		wantError string
	}{
		{name: "wrong scope", target: "/api/v1/flows", apiKey: "ingest-key", wantCode: http.StatusForbidden, wantError: CodeInsufficientScope},
		{name: "missing range", target: "/api/v1/flows", apiKey: "query-key", wantCode: http.StatusBadRequest, wantError: CodeMissingRequiredParameter},
		{
			name:      "window too large",
			target:    "/api/v1/flows?from=2026-06-16T00:00:00Z&to=2026-06-24T00:00:00Z",
			apiKey:    "query-key",
			wantCode:  http.StatusBadRequest,
			wantError: CodeQueryWindowTooLarge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, newQueryRequest(tt.target, tt.apiKey))

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

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest(
		"/api/v1/flows?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z&src_ip=192.168.1.10&limit=1&include=attributes",
		"query-key",
	))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response FlowSearchResponse
	decodeJSON(t, recorder, &response)
	if len(response.Items) != 1 || response.NextCursor == "" || response.Items[0].Attributes["env"] != "test" {
		t.Fatalf("response = %+v", response)
	}
	lastQuery := store.lastSearchQuery()
	if lastQuery.SrcIP == nil || lastQuery.SrcIP.String() != "192.168.1.10" || lastQuery.Limit != 1 {
		t.Fatalf("last query = %+v", lastQuery)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest(
		"/api/v1/flows?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z&cursor="+response.NextCursor,
		"query-key",
	))
	if recorder.Code != http.StatusOK {
		t.Fatalf("cursor status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if store.lastSearchQuery().Cursor == nil {
		t.Fatal("expected decoded cursor in query")
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest(
		"/api/v1/flows?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z&cursor=tampered",
		"query-key",
	))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("tampered status = %d", recorder.Code)
	}
	var errResponse ErrorResponse
	decodeJSON(t, recorder, &errResponse)
	if errResponse.Error.Code != CodeInvalidCursor {
		t.Fatalf("error code = %q", errResponse.Error.Code)
	}
}

func TestFlowLookup(t *testing.T) {
	t.Parallel()

	record := validFlowRecord()
	store := &fakeFlowStore{lookupRecord: record, lookupFound: true}
	handler := newQueryTestServer(t, store, nil)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest("/api/v1/flows/"+record.ID, "query-key"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response FlowResponse
	decodeJSON(t, recorder, &response)
	if response.ID != record.ID || response.IdempotencyKey == "" || response.RawEventID == "" {
		t.Fatalf("response = %+v", response)
	}

	store.lookupFound = false
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest("/api/v1/flows/"+record.ID, "query-key"))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("not found status = %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest("/api/v1/flows/not-a-uuid", "query-key"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid id status = %d", recorder.Code)
	}
}

func newQueryTestServer(t *testing.T, flowStore FlowStore, aggregationStore AggregationStore) http.Handler {
	t.Helper()

	cfg := validAPICfg()
	cfg.API.Cursor.HMACSecretEnv = "CURSOR_SECRET"
	server, err := NewServerWithStores(cfg, newImmediatePublisher(), flowStore, aggregationStore, envLookupWithCursor())
	if err != nil {
		t.Fatalf("NewServerWithStores() error = %v", err)
	}
	return server.Handler()
}

func envLookupWithCursor() func(string) string {
	base := envLookup()
	return func(key string) string {
		if key == "CURSOR_SECRET" {
			return "0123456789abcdef0123456789abcdef"
		}
		return base(key)
	}
}

func newQueryRequest(target string, apiKey string) *http.Request {
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if apiKey != "" {
		request.Header.Set(APIKeyHeader, apiKey)
	}
	return request
}

type fakeFlowStore struct {
	mu           sync.Mutex
	searchQuery  postgres.FlowSearchQuery
	searchResult postgres.FlowSearchResult
	lookupRecord domain.NormalizedFlowRecord
	lookupFound  bool
}

func (s *fakeFlowStore) SearchFlows(_ context.Context, query postgres.FlowSearchQuery) (postgres.FlowSearchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.searchQuery = query
	return s.searchResult, nil
}

func (s *fakeFlowStore) GetFlowByID(context.Context, string, *time.Time) (domain.NormalizedFlowRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookupRecord, s.lookupFound, nil
}

func (s *fakeFlowStore) lastSearchQuery() postgres.FlowSearchQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.searchQuery
}

func validFlowRecord() domain.NormalizedFlowRecord {
	sourceIP := netip.MustParseAddr("203.0.113.10")
	eventEnd := time.Date(2026, 6, 16, 10, 15, 25, 0, time.UTC)
	duration := int64(5000)
	srcPort := uint16(51524)
	dstPort := uint16(53)
	bytesValue := uint64(420)
	packets := uint64(3)
	app := "dns"
	return domain.NormalizedFlowRecord{
		ID:                  "01934d7c-79b4-7000-8b69-001122334455",
		SchemaVersion:       domain.FlowSchemaVersion,
		IdempotencyKey:      "sha256:" + strings.Repeat("a", 64),
		RawEventID:          "01934d7c-79b4-7000-8b69-001122334456",
		SourceType:          domain.SourceTypeRESTJSON,
		CollectorID:         "rest-ingest-main",
		SourceHost:          "rest-client-host",
		SourceIP:            &sourceIP,
		IngestedAt:          time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC),
		NormalizedAt:        time.Date(2026, 6, 16, 10, 15, 21, 0, time.UTC),
		EventStartTime:      time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC),
		EventEndTime:        &eventEnd,
		DurationMS:          &duration,
		SrcIP:               netip.MustParseAddr("192.168.1.10"),
		DstIP:               netip.MustParseAddr("8.8.8.8"),
		SrcPort:             &srcPort,
		DstPort:             &dstPort,
		IPVersion:           4,
		TransportProtocol:   domain.TransportProtocolUDP,
		ProtocolNumber:      17,
		Bytes:               &bytesValue,
		Packets:             &packets,
		Direction:           domain.DirectionOutbound,
		ApplicationProtocol: &app,
		NormalizationStatus: domain.NormalizationStatusOK,
		Attributes:          map[string]json.RawMessage{"env": json.RawMessage(`"test"`)},
	}
}

func TestFlowSearchValidationEdgeCases(t *testing.T) {
	t.Parallel()

	store := &fakeFlowStore{}
	handler := newQueryTestServer(t, store, nil)

	tests := []struct {
		name      string
		query     string
		wantError string
	}{
		{
			name:      "bad src_cidr",
			query:     "src_cidr=invalid",
			wantError: CodeInvalidParameter,
		},
		{
			name:      "bad src_port",
			query:     "src_port=999999",
			wantError: CodeInvalidParameter,
		},
		{
			name:      "bad protocol",
			query:     "protocol=999",
			wantError: CodeInvalidParameter,
		},
		{
			name:      "bad direction",
			query:     "direction=invalid",
			wantError: CodeInvalidParameter,
		},
		{
			name:      "bad limit negative",
			query:     "limit=-5",
			wantError: CodeInvalidParameter,
		},
		{
			name:      "bad limit too large",
			query:     "limit=99999",
			wantError: CodeInvalidParameter,
		},
		{
			name:      "bad destination port",
			query:     "dst_port=invalid",
			wantError: CodeInvalidParameter,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			target := "/api/v1/flows?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z&" + tt.query
			handler.ServeHTTP(recorder, newQueryRequest(target, "query-key"))

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body = %s", recorder.Code, recorder.Body.String())
			}
			var response ErrorResponse
			decodeJSON(t, recorder, &response)
			if response.Error.Code != tt.wantError {
				t.Fatalf("error code = %q, want %q", response.Error.Code, tt.wantError)
			}
		})
	}
}

func TestQueryHandlerStoreErrorsAndHelperBranches(t *testing.T) {
	t.Parallel()

	cfg := validAPICfg()
	cfg.API.Cursor.HMACSecretEnv = "CURSOR_SECRET"
	codec, err := cursorCodecFromConfig(cfg, envLookupWithCursor())
	if err != nil {
		t.Fatalf("cursor codec: %v", err)
	}
	nilHandler := NewQueryHandler(cfg, nil, codec)
	recorder := httptest.NewRecorder()
	nilHandler.Search(recorder, newQueryRequest("/api/v1/flows?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z", "query-key"))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil store search status = %d", recorder.Code)
	}

	errorStore := errorFlowStore{err: errors.New("database down")}
	errorHandler := NewQueryHandler(cfg, errorStore, codec)
	recorder = httptest.NewRecorder()
	errorHandler.Search(recorder, newQueryRequest("/api/v1/flows?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z", "query-key"))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("store error search status = %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	errorHandler.Lookup(recorder, newQueryRequest("/api/v1/flows/01934d7c-79b4-7000-8b69-001122334455?start_time=2026-06-16T10:00:00Z", "query-key"))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("store error lookup status = %d", recorder.Code)
	}

	if _, _, apiErr := parseRequiredRange("", "2026-06-16T11:00:00Z", time.Hour); apiErr == nil || apiErr.Code != CodeMissingRequiredParameter {
		t.Fatalf("missing from apiErr = %+v", apiErr)
	}
	if _, _, apiErr := parseRequiredRange("bad", "2026-06-16T11:00:00Z", time.Hour); apiErr == nil || apiErr.Code != CodeInvalidParameter {
		t.Fatalf("bad from apiErr = %+v", apiErr)
	}
	if _, _, apiErr := parseRequiredRange("2026-06-16T11:00:00Z", "2026-06-16T10:00:00Z", time.Hour); apiErr == nil || apiErr.Code != CodeInvalidParameter {
		t.Fatalf("reversed range apiErr = %+v", apiErr)
	}

	attrs := rawAttributesToAny(map[string]json.RawMessage{"ok": []byte(`"value"`), "bad": []byte(`{`)})
	if attrs["ok"] != "value" {
		t.Fatalf("decoded attributes = %+v", attrs)
	}
	if len(rawAttributesToAny(nil)) != 0 {
		t.Fatal("nil attributes should decode to an empty map")
	}
}

type errorFlowStore struct {
	err error
}

func (s errorFlowStore) SearchFlows(context.Context, postgres.FlowSearchQuery) (postgres.FlowSearchResult, error) {
	return postgres.FlowSearchResult{}, s.err
}

func (s errorFlowStore) GetFlowByID(context.Context, string, *time.Time) (domain.NormalizedFlowRecord, bool, error) {
	return domain.NormalizedFlowRecord{}, false, s.err
}
