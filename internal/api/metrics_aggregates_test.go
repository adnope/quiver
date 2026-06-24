package api

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
)

func TestMetricsAggregatesHandlerValidation(t *testing.T) {
	t.Parallel()

	db := sql.OpenDB(apiErrorConnector{})
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.Default().Observability
	handler := MetricsAggregatesHandler(db, cfg)

	tests := []struct {
		name      string
		query     string
		wantCode  int
		wantError string
	}{
		{
			name:      "missing from",
			query:     "to=2026-06-24T10:00:00Z&step=5s",
			wantCode:  http.StatusBadRequest,
			wantError: CodeInvalidParameter,
		},
		{
			name:      "bad to",
			query:     "from=2026-06-24T09:00:00Z&to=bad&step=5s",
			wantCode:  http.StatusBadRequest,
			wantError: CodeInvalidParameter,
		},
		{
			name:      "to before from",
			query:     "from=2026-06-24T10:00:00Z&to=2026-06-24T09:00:00Z&step=5s",
			wantCode:  http.StatusBadRequest,
			wantError: CodeInvalidParameter,
		},
		{
			name:      "step too small",
			query:     "from=2026-06-24T09:00:00Z&to=2026-06-24T10:00:00Z&step=1s",
			wantCode:  http.StatusBadRequest,
			wantError: CodeInvalidParameter,
		},
		{
			name:      "step not multiple",
			query:     "from=2026-06-24T09:00:00Z&to=2026-06-24T10:00:00Z&step=7s",
			wantCode:  http.StatusBadRequest,
			wantError: CodeInvalidParameter,
		},
		{
			name:      "too many points",
			query:     "from=2026-06-24T09:00:00Z&to=2026-06-24T10:30:00Z&step=5s",
			wantCode:  http.StatusBadRequest,
			wantError: CodeQueryWindowTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/aggregates?"+tt.query, nil)
			handler.ServeHTTP(recorder, request)
			if recorder.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d body=%s", recorder.Code, tt.wantCode, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), tt.wantError) {
				t.Fatalf("body %q does not contain %q", recorder.Body.String(), tt.wantError)
			}
		})
	}
}

func TestMetricsAggregatesRouteRequiresMetricsScope(t *testing.T) {
	t.Parallel()

	cfg := validAPICfg()
	cfg.API.Metrics.AuthRequired = true
	server, err := NewServerWithObservability(cfg, newImmediatePublisher(), nil, nil, envLookup(), nil, StaticHealthChecker{Value: HealthOK})
	if err != nil {
		t.Fatalf("NewServerWithObservability() error = %v", err)
	}

	requestURL := "/api/v1/metrics/aggregates?from=2026-06-24T09:00:00Z&to=2026-06-24T10:00:00Z&step=5s"
	missing := httptest.NewRecorder()
	server.Handler().ServeHTTP(missing, httptest.NewRequest(http.MethodGet, requestURL, nil))
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing key status = %d, want 401", missing.Code)
	}

	wrongScope := httptest.NewRecorder()
	wrongRequest := httptest.NewRequest(http.MethodGet, requestURL, nil)
	wrongRequest.Header.Set(APIKeyHeader, "query-key")
	server.Handler().ServeHTTP(wrongScope, wrongRequest)
	if wrongScope.Code != http.StatusForbidden {
		t.Fatalf("wrong scope status = %d, want 403", wrongScope.Code)
	}
}

func TestMetricAggregateRollupUsesHistogramPercentiles(t *testing.T) {
	t.Parallel()

	from := time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC)
	query := metricAggregatesQuery{From: from, Step: 20 * time.Second}
	labels := map[string]string{"status": "ok"}
	key := rollupKeyFor(from.Add(5*time.Second), "storage_insert_duration", labels, from, query.Step)
	rollup := newAggregateRollup(key, MetricAggregatePoint{
		BucketStart: from,
		MetricName:  "storage_insert_duration",
		Labels:      labels,
		MetricKind:  "duration",
		Count:       4,
		Sum:         floatPtr(18),
		Min:         floatPtr(1),
		Max:         floatPtr(10),
	}, query.Step)
	rollup.addRow(MetricAggregatePoint{
		BucketStart: from,
		MetricName:  "storage_insert_duration",
		Labels:      labels,
		MetricKind:  "duration",
		Count:       4,
		Sum:         floatPtr(18),
		Min:         floatPtr(1),
		Max:         floatPtr(10),
	})
	rollup.histogramByBucket = map[int]uint64{0: 1, 1: 1, 2: 1, 3: 1}
	rollup.hasHistogramCounts = true

	point := rollup.toPoint()
	if point.BucketStart != from || point.BucketWidthSeconds != 20 {
		t.Fatalf("unexpected bucket metadata: %+v", point)
	}
	if valueOrZero(point.Avg) != 4.5 || valueOrZero(point.P95) != 10 || valueOrZero(point.P99) != 10 {
		t.Fatalf("unexpected rollup point: %+v", point)
	}
}

func valueOrZero(value *float64) float64 {
	if value == nil {
		return 0
	}
	return *value
}

type apiErrorConnector struct{}

func (apiErrorConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("expected test connector failure")
}

func (apiErrorConnector) Driver() driver.Driver { return apiErrorDriver{} }

type apiErrorDriver struct{}

func (apiErrorDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("expected test driver failure")
}
