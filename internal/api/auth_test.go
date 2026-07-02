package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/observability"
)

func TestRequireScopeMetersRateLimitRejections(t *testing.T) {
	t.Parallel()

	cfg := validAPICfg()
	cfg.API.RateLimits.Ingest.RequestsPerMinute = 1
	auth, err := NewAuthenticator(cfg, envLookup())
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	metrics := observability.NewRegistry()
	limiter := NewRateLimiter(cfg.API.RateLimits)
	handler := RequireScope(auth, limiter, metrics, ScopeIngest, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRecorder()
	firstReq := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/flows", nil)
	firstReq.Header.Set(APIKeyHeader, "ingest-key")
	handler.ServeHTTP(first, firstReq)
	if first.Code != http.StatusNoContent {
		t.Fatalf("first status = %d, want 204", first.Code)
	}

	second := httptest.NewRecorder()
	secondReq := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/flows", nil)
	secondReq.Header.Set(APIKeyHeader, "ingest-key")
	handler.ServeHTTP(second, secondReq)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429", second.Code)
	}

	for _, snapshot := range metrics.Snapshot() {
		if snapshot.Name == "rate_limit_rejections_total" &&
			snapshot.Labels["key"] == "demo-client" &&
			snapshot.Labels["scope"] == string(ScopeIngest) &&
			snapshot.Value == 1 {
			return
		}
	}
	t.Fatalf("rate_limit_rejections_total snapshot not found: %+v", metrics.Snapshot())
}

func TestRateLimiterAndContextHelpers(t *testing.T) {
	t.Parallel()

	if !(*RateLimiter)(nil).Allow("key", ScopeQuery) {
		t.Fatal("nil rate limiter should allow requests")
	}
	var nilCtx context.Context
	if _, ok := PrincipalFromContext(nilCtx); ok {
		t.Fatal("nil context returned a principal")
	}
	if RequestIDFromContext(nilCtx) != "" {
		t.Fatal("nil context returned request id")
	}

	cfg := validAPICfg()
	cfg.API.RateLimits.Query.RequestsPerMinute = 2
	cfg.API.RateLimits.Metrics.RequestsPerMinute = 0
	limiter := NewRateLimiter(cfg.API.RateLimits)
	now := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	firstAllowed := limiter.Allow("demo", ScopeQuery)
	secondAllowed := limiter.Allow("demo", ScopeQuery)
	if !firstAllowed || !secondAllowed {
		t.Fatal("first two requests should be allowed")
	}
	if limiter.Allow("demo", ScopeQuery) {
		t.Fatal("third request should be rate limited")
	}
	now = now.Add(time.Minute)
	if !limiter.Allow("demo", ScopeQuery) {
		t.Fatal("new window should allow request")
	}
	if limiter.Allow("demo", ScopeMetrics) {
		t.Fatal("zero metrics limit should reject request")
	}
}

func TestRequestIDMiddlewareAndWriteError(t *testing.T) {
	t.Parallel()

	handler := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := RequestIDFromContext(r.Context()); got != "client-request-id" {
			t.Fatalf("request id from context = %q", got)
		}
		writeError(w, r, http.StatusTeapot, CodeInvalidRequest, "bad request", map[string]any{"field": "demo"})
	}))
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	request.Header.Set(RequestIDHeader, " client-request-id ")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTeapot || recorder.Header().Get(RequestIDHeader) != "client-request-id" {
		t.Fatalf("status/header = %d/%q", recorder.Code, recorder.Header().Get(RequestIDHeader))
	}
	var response ErrorResponse
	decodeJSON(t, recorder, &response)
	if response.RequestID != "client-request-id" || response.Error.Details["field"] != "demo" {
		t.Fatalf("response = %+v", response)
	}

	recorder = httptest.NewRecorder()
	RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(RequestIDFromContext(r.Context()), "req_") {
			t.Fatalf("generated request id = %q", RequestIDFromContext(r.Context()))
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if recorder.Code != http.StatusNoContent || !strings.HasPrefix(recorder.Header().Get(RequestIDHeader), "req_") {
		t.Fatalf("generated status/header = %d/%q", recorder.Code, recorder.Header().Get(RequestIDHeader))
	}
}
