package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adnope/quiver/internal/observability"
)

func TestHealthRoute(t *testing.T) {
	t.Parallel()

	cfg := validAPICfg()
	cfg.API.Health.AuthRequired = false
	server, err := NewServerWithObservability(cfg, newImmediatePublisher(), nil, nil, envLookup(), observability.NewRegistry(), StaticHealthChecker{Value: HealthOK})
	if err != nil {
		t.Fatalf("NewServerWithObservability() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.TrimSpace(recorder.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("body = %q", recorder.Body.String())
	}
}

func TestHealthRouteFailureStatus(t *testing.T) {
	t.Parallel()

	cfg := validAPICfg()
	server, err := NewServerWithObservability(cfg, newImmediatePublisher(), nil, nil, envLookup(), nil, StaticHealthChecker{Value: HealthFail})
	if err != nil {
		t.Fatalf("NewServerWithObservability() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
}

func TestMetricsRouteRequiresMetricsScope(t *testing.T) {
	t.Parallel()

	cfg := validAPICfg()
	cfg.API.Metrics.AuthRequired = true
	metrics := observability.NewRegistry()
	server, err := NewServerWithObservability(cfg, newImmediatePublisher(), nil, nil, envLookup(), metrics, StaticHealthChecker{Value: HealthOK})
	if err != nil {
		t.Fatalf("NewServerWithObservability() error = %v", err)
	}

	missing := httptest.NewRecorder()
	server.Handler().ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing key status = %d, want 401", missing.Code)
	}

	wrongScope := httptest.NewRecorder()
	wrongRequest := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	wrongRequest.Header.Set(APIKeyHeader, "query-key")
	server.Handler().ServeHTTP(wrongScope, wrongRequest)
	if wrongScope.Code != http.StatusForbidden {
		t.Fatalf("wrong scope status = %d, want 403", wrongScope.Code)
	}

	ok := httptest.NewRecorder()
	okRequest := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	okRequest.Header.Set(APIKeyHeader, "metrics-key")
	server.Handler().ServeHTTP(ok, okRequest)
	if ok.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200 body=%s", ok.Code, ok.Body.String())
	}
	body := ok.Body.String()
	if !strings.Contains(body, `api_http_requests_total{method="GET",route="GET /metrics",status="401"} 1`) {
		t.Fatalf("metrics body missing HTTP counter:\n%s", body)
	}
	if strings.Contains(body, "query-key") || strings.Contains(body, "metrics-key") {
		t.Fatalf("metrics body leaked API key:\n%s", body)
	}
}
