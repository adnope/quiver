package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
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

type mockPublisher struct {
	healthy bool
}

func (m *mockPublisher) PublishRaw(ctx context.Context, event *flowv1.RawFlowEventEnvelope) error {
	return nil
}
func (m *mockPublisher) PublishDeadLetter(ctx context.Context, event *flowv1.DeadLetterEvent) error {
	return nil
}
func (m *mockPublisher) Flush(ctx context.Context) error {
	return nil
}
func (m *mockPublisher) Healthy() bool {
	return m.healthy
}

func TestCompositeHealthChecker(t *testing.T) {
	t.Parallel()

	// 1. Success case
	checker := &CompositeHealthChecker{
		DB:        nil, // skipped ping if nil
		Publisher: &mockPublisher{healthy: true},
		CollectorStatus: func() map[string]string {
			return map[string]string{
				"zeek_json":  "running",
				"netflow_v5": "running",
			}
		},
	}

	if checker.Status() != HealthOK {
		t.Fatalf("expected HealthOK, got %s", checker.Status())
	}
	detailed := checker.DetailedStatus(context.Background())
	if detailed.Status != HealthOK {
		t.Fatalf("expected DetailedStatus HealthOK, got %s", detailed.Status)
	}
	if detailed.Kafka != HealthOK {
		t.Fatalf("expected detailed.Kafka HealthOK, got %s", detailed.Kafka)
	}
	if detailed.Collectors["zeek_json"] != HealthOK {
		t.Fatalf("expected zeek_json HealthOK, got %s", detailed.Collectors["zeek_json"])
	}

	// 2. Degraded case (collector stopped)
	checkerDegraded := &CompositeHealthChecker{
		DB:        nil,
		Publisher: &mockPublisher{healthy: true},
		CollectorStatus: func() map[string]string {
			return map[string]string{
				"zeek_json":  "stopped",
				"netflow_v5": "running",
			}
		},
	}
	if checkerDegraded.Status() != HealthDegraded {
		t.Fatalf("expected HealthDegraded, got %s", checkerDegraded.Status())
	}
	detailedDegraded := checkerDegraded.DetailedStatus(context.Background())
	if detailedDegraded.Status != HealthDegraded {
		t.Fatalf("expected DetailedStatus HealthDegraded, got %s", detailedDegraded.Status)
	}
	if detailedDegraded.Collectors["zeek_json"] != HealthFail {
		t.Fatalf("expected zeek_json HealthFail, got %s", detailedDegraded.Collectors["zeek_json"])
	}

	// 3. Failed case (publisher unhealthy)
	checkerFailed := &CompositeHealthChecker{
		DB:        nil,
		Publisher: &mockPublisher{healthy: false},
		CollectorStatus: func() map[string]string {
			return map[string]string{
				"zeek_json":  "running",
				"netflow_v5": "running",
			}
		},
	}
	if checkerFailed.Status() != HealthFail {
		t.Fatalf("expected HealthFail, got %s", checkerFailed.Status())
	}
	detailedFailed := checkerFailed.DetailedStatus(context.Background())
	if detailedFailed.Status != HealthFail {
		t.Fatalf("expected DetailedStatus HealthFail, got %s", detailedFailed.Status)
	}
	if detailedFailed.Kafka != HealthFail {
		t.Fatalf("expected detailed.Kafka HealthFail, got %s", detailedFailed.Kafka)
	}
}

func TestDetailedHealthRoute(t *testing.T) {
	t.Parallel()

	cfg := validAPICfg()
	cfg.API.Health.AuthRequired = false

	checker := &CompositeHealthChecker{
		DB:        nil,
		Publisher: &mockPublisher{healthy: true},
		CollectorStatus: func() map[string]string {
			return map[string]string{
				"zeek_json": "running",
			}
		},
	}

	server, err := NewServerWithObservability(cfg, newImmediatePublisher(), nil, nil, envLookup(), nil, checker)
	if err != nil {
		t.Fatalf("NewServerWithObservability() error = %v", err)
	}

	// 1. Unauthenticated request should return generic response only
	recorderUnauth := httptest.NewRecorder()
	reqUnauth := httptest.NewRequest(http.MethodGet, "/health", nil)
	server.Handler().ServeHTTP(recorderUnauth, reqUnauth)

	if recorderUnauth.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorderUnauth.Code)
	}
	if strings.TrimSpace(recorderUnauth.Body.String()) != `{"status":"ok"}` {
		t.Fatalf("expected simple body, got %q", recorderUnauth.Body.String())
	}

	// 2. Authenticated request with metrics scope should return detailed response
	recorderAuth := httptest.NewRecorder()
	reqAuth := httptest.NewRequest(http.MethodGet, "/health", nil)
	reqAuth.Header.Set(APIKeyHeader, "metrics-key")
	server.Handler().ServeHTTP(recorderAuth, reqAuth)

	if recorderAuth.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", recorderAuth.Code, recorderAuth.Body.String())
	}
	body := recorderAuth.Body.String()
	if !strings.Contains(body, `"database":"ok"`) || !strings.Contains(body, `"kafka":"ok"`) || !strings.Contains(body, `"zeek_json":"ok"`) {
		t.Fatalf("expected detailed response, got %s", body)
	}
}
