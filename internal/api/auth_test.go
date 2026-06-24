package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
	firstReq := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/flows", nil)
	firstReq.Header.Set(APIKeyHeader, "ingest-key")
	handler.ServeHTTP(first, firstReq)
	if first.Code != http.StatusNoContent {
		t.Fatalf("first status = %d, want 204", first.Code)
	}

	second := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/flows", nil)
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
