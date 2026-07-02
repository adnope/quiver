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
			request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/metrics/aggregates?"+tt.query, nil)
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
	server.Handler().ServeHTTP(missing, httptest.NewRequestWithContext(context.Background(), http.MethodGet, requestURL, nil))
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing key status = %d, want 401", missing.Code)
	}

	wrongScope := httptest.NewRecorder()
	wrongRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, requestURL, nil)
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
		Sum:         new(float64(18)),
		Min:         new(float64(1)),
		Max:         new(float64(10)),
	}, query.Step)
	rollup.addRow(MetricAggregatePoint{
		BucketStart: from,
		MetricName:  "storage_insert_duration",
		Labels:      labels,
		MetricKind:  "duration",
		Count:       4,
		Sum:         new(float64(18)),
		Min:         new(float64(1)),
		Max:         new(float64(10)),
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

func TestMetricAggregateRollupCounterRates(t *testing.T) {
	t.Parallel()

	from := time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC)
	query := metricAggregatesQuery{From: from, Step: 20 * time.Second}
	labels := map[string]string{"source_type": "rest_json"}
	key := rollupKeyFor(from.Add(5*time.Second), "flow_records_normalized_total", labels, from, query.Step)

	rollup := newAggregateRollup(key, MetricAggregatePoint{
		BucketStart:        from,
		BucketWidthSeconds: 5,
		MetricName:         "flow_records_normalized_total",
		Labels:             labels,
		MetricKind:         "counter",
	}, query.Step)

	// Add first base bucket: 5 seconds, delta 30000 (rate = 6000)
	rollup.addRow(MetricAggregatePoint{
		BucketStart:        from,
		BucketWidthSeconds: 5,
		MetricName:         "flow_records_normalized_total",
		Labels:             labels,
		MetricKind:         "counter",
		Delta:              newFloat(30000),
	})

	// Add second base bucket: 5 seconds, delta 0 (rate = 0)
	rollup.addRow(MetricAggregatePoint{
		BucketStart:        from.Add(5 * time.Second),
		BucketWidthSeconds: 5,
		MetricName:         "flow_records_normalized_total",
		Labels:             labels,
		MetricKind:         "counter",
		Delta:              newFloat(0),
	})

	point := rollup.toPoint()
	if point.BucketWidthSeconds != 20 {
		t.Fatalf("unexpected bucket width: %d", point.BucketWidthSeconds)
	}
	if valueOrZero(point.Delta) != 30000 {
		t.Fatalf("unexpected total delta: %v, want 30000", valueOrZero(point.Delta))
	}
	if valueOrZero(point.RateAvg) != 1500 {
		t.Fatalf("unexpected average rate: %v, want 1500", valueOrZero(point.RateAvg))
	}
	if valueOrZero(point.RatePeak) != 6000 {
		t.Fatalf("unexpected peak rate: %v, want 6000", valueOrZero(point.RatePeak))
	}
}

//nolint:modernize
func newFloat(val float64) *float64 {
	return &val
}

func TestMetricsAggregateParsingAndPureHelpers(t *testing.T) {
	t.Parallel()

	cfg := config.ObservabilityConfig{
		MetricsAggregateBucketWidth: config.Duration(5 * time.Second),
		MetricsAggregateMaxPoints:   2,
	}
	validTarget := "/api/v1/metrics/aggregates?from=2026-06-16T10:00:00Z&to=2026-06-16T10:00:10Z&step=5s&metric=%20ingest%20&metric=&metric=latency"
	recorder := httptest.NewRecorder()
	query, ok := parseMetricAggregatesQuery(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, validTarget, nil), cfg)
	if !ok || len(query.Metrics) != 2 || query.Step != 5*time.Second || query.BaseBucketWidth != 5*time.Second {
		t.Fatalf("query=%+v ok=%v body=%s", query, ok, recorder.Body.String())
	}

	tests := []string{
		"/api/v1/metrics/aggregates?to=2026-06-16T10:00:10Z",
		"/api/v1/metrics/aggregates?from=bad&to=2026-06-16T10:00:10Z",
		"/api/v1/metrics/aggregates?from=2026-06-16T10:00:10Z&to=2026-06-16T10:00:00Z",
		"/api/v1/metrics/aggregates?from=2026-06-16T10:00:00Z&to=2026-06-16T10:00:10Z&step=bad",
		"/api/v1/metrics/aggregates?from=2026-06-16T10:00:00Z&to=2026-06-16T10:00:10Z&step=1s",
		"/api/v1/metrics/aggregates?from=2026-06-16T10:00:00Z&to=2026-06-16T10:00:10Z&step=6s",
		"/api/v1/metrics/aggregates?from=2026-06-16T10:00:00Z&to=2026-06-16T10:00:20Z&step=5s",
	}
	for _, target := range tests {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			recorder := httptest.NewRecorder()
			_, ok := parseMetricAggregatesQuery(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil), cfg)
			if ok || recorder.Code != http.StatusBadRequest {
				t.Fatalf("target=%s ok=%v status=%d body=%s", target, ok, recorder.Code, recorder.Body.String())
			}
		})
	}

	if _, err := parseRequiredRFC3339(" "); err == nil {
		t.Fatal("empty timestamp should fail")
	}
	if got := ceilDurationDiv(11*time.Second, 5*time.Second); got != 3 {
		t.Fatalf("ceilDurationDiv = %d, want 3", got)
	}
	if labels, err := decodeMetricLabels(nil); err != nil || len(labels) != 0 {
		t.Fatalf("empty labels = %+v err=%v", labels, err)
	}
	if labels, err := decodeMetricLabels([]byte("null")); err != nil || len(labels) != 0 {
		t.Fatalf("null labels = %+v err=%v", labels, err)
	}
	if _, err := decodeMetricLabels([]byte("{")); err == nil {
		t.Fatal("invalid labels should fail")
	}
	if nonNegativeInt64(-1) != 0 || nonNegativeInt64(7) != 7 {
		t.Fatal("nonNegativeInt64 returned unexpected values")
	}
	if nullFloatPtr(sql.NullFloat64{}) != nil {
		t.Fatal("invalid sql.NullFloat64 should become nil")
	}
	validFloat := nullFloatPtr(sql.NullFloat64{Float64: 1.5, Valid: true})
	if validFloat == nil || *validFloat != 1.5 {
		t.Fatalf("valid float ptr = %v", validFloat)
	}
	from := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	if alignToQueryStart(from.Add(16*time.Second), from, 10*time.Second) != from.Add(10*time.Second) {
		t.Fatal("alignToQueryStart did not floor to query step")
	}
	if labelsStableKey(nil) != "{}" || labelsStableKey(map[string]string{"b": "2", "a": "1"}) != `{"a":"1","b":"2"}` {
		t.Fatal("labelsStableKey returned unexpected value")
	}
	if counts := histogramCountsSlice(map[int]uint64{2: 5, -1: 9}); len(counts) != 3 || counts[2] != 5 {
		t.Fatalf("histogramCountsSlice = %+v", counts)
	}
	if counts := histogramCountsSlice(nil); counts != nil {
		t.Fatalf("empty histogram counts = %+v", counts)
	}
	if table, width := selectMetricAggregatesTableAndWidth(from, from.Add(time.Hour)); table != "quiver.system_metric_aggregates" || width != 5 {
		t.Fatalf("short table=%s width=%d", table, width)
	}
	if table, width := selectMetricAggregatesTableAndWidth(from, from.Add(24*time.Hour)); table != "quiver.system_metric_5m_aggregates" || width != 300 {
		t.Fatalf("medium table=%s width=%d", table, width)
	}
	if table, width := selectMetricHistogramsTableAndWidth(from, from.Add(8*24*time.Hour)); table != "quiver.system_metric_1h_histogram_buckets" || width != 3600 {
		t.Fatalf("long table=%s width=%d", table, width)
	}
}
