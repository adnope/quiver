package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/observability"
)

type HealthStatus string

const (
	HealthOK       HealthStatus = "ok"
	HealthDegraded HealthStatus = "degraded"
	HealthFail     HealthStatus = "fail"
)

type HealthChecker interface {
	Status() HealthStatus
}

type StaticHealthChecker struct {
	Value HealthStatus
}

func (c StaticHealthChecker) Status() HealthStatus {
	if c.Value == "" {
		return HealthOK
	}
	return c.Value
}

type HealthResponse struct {
	Status HealthStatus `json:"status"`
}

type DetailedHealthResponse struct {
	Status     HealthStatus            `json:"status"`
	Database   HealthStatus            `json:"database"`
	Kafka      HealthStatus            `json:"kafka"`
	Collectors map[string]HealthStatus `json:"collectors"`
}

type DetailedHealthChecker interface {
	HealthChecker
	DetailedStatus(ctx context.Context) DetailedHealthResponse
}

type CompositeHealthChecker struct {
	DB              *sql.DB
	Publisher       kafka.RawEventPublisher
	CollectorStatus func() map[string]string
}

func (c *CompositeHealthChecker) Status() HealthStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if c.DB != nil {
		if err := c.DB.PingContext(ctx); err != nil {
			return HealthFail
		}
	}
	if c.Publisher != nil {
		type healthy interface {
			Healthy() bool
		}
		if h, ok := c.Publisher.(healthy); ok {
			if !h.Healthy() {
				return HealthFail
			}
		}
	}
	if c.CollectorStatus != nil {
		for _, status := range c.CollectorStatus() {
			if status == "stopped" || status == "failed" {
				return HealthDegraded
			}
		}
	}
	return HealthOK
}

func (c *CompositeHealthChecker) DetailedStatus(ctx context.Context) DetailedHealthResponse {
	res := DetailedHealthResponse{
		Status:     HealthOK,
		Database:   HealthOK,
		Kafka:      HealthOK,
		Collectors: map[string]HealthStatus{},
	}

	pingCtx, pingCancel := context.WithTimeout(ctx, 2*time.Second)
	defer pingCancel()

	if c.DB != nil {
		if err := c.DB.PingContext(pingCtx); err != nil {
			res.Database = HealthFail
			res.Status = HealthFail
		}
	}

	if c.Publisher != nil {
		type healthy interface {
			Healthy() bool
		}
		if h, ok := c.Publisher.(healthy); ok {
			if !h.Healthy() {
				res.Kafka = HealthFail
				res.Status = HealthFail
			}
		}
	}

	if c.CollectorStatus != nil {
		for id, status := range c.CollectorStatus() {
			cStat := HealthOK
			if status == "stopped" || status == "failed" {
				cStat = HealthFail
				if res.Status != HealthFail {
					res.Status = HealthDegraded
				}
			}
			res.Collectors[id] = cStat
		}
	}

	return res
}

func HealthHandler(checker HealthChecker, auth *Authenticator) http.Handler {
	if checker == nil {
		checker = StaticHealthChecker{Value: HealthOK}
	}
	return http.HandlerFunc(serveHealth(checker, auth))
}

// @Summary Health status
// @Description Returns a top-level process health status. If X-API-Key with metrics scope is provided, detailed status is returned.
// @Tags health
// @Produce json
// @Success 200 {object} HealthResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 503 {object} HealthResponse
// @Router /health [get]
func serveHealth(checker HealthChecker, auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get(APIKeyHeader)
		hasMetricsScope := false
		if auth != nil && apiKey != "" {
			if principal, err := auth.Authenticate(apiKey); err == nil {
				if principal.HasScope(ScopeMetrics) {
					hasMetricsScope = true
				}
			}
		}

		if hasMetricsScope {
			if detailedChecker, ok := checker.(DetailedHealthChecker); ok {
				res := detailedChecker.DetailedStatus(r.Context())
				code := http.StatusOK
				if res.Status == HealthFail {
					code = http.StatusServiceUnavailable
				}
				writeJSON(w, code, res)
				return
			}
		}

		status := checker.Status()
		code := http.StatusOK
		if status == HealthFail {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, HealthResponse{Status: status})
	}
}

func MetricsHandler(registry *observability.Registry) http.Handler {
	return http.HandlerFunc(serveMetrics(registry))
}

// serveMetrics godoc
// @Summary Prometheus metrics
// @Description Returns Prometheus text exposition metrics. Requires X-API-Key with metrics scope when metrics auth is enabled.
// @Tags metrics
// @Produce plain
// @Security ApiKeyAuth
// @Param X-API-Key header string true "API key with metrics scope when metrics auth is enabled"
// @Success 200 {string} string "Prometheus text exposition"
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 429 {object} ErrorResponse
// @Router /metrics [get]
func serveMetrics(registry *observability.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(registry.WritePrometheus())
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func instrumentHTTP(registry *observability.Registry, route string, next http.Handler) http.Handler {
	if registry == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		labels := map[string]string{
			"method": r.Method,
			"route":  route,
			"status": strconv.Itoa(recorder.status),
		}
		registry.Inc("api_http_requests_total", labels)
		registry.ObserveDuration("api_http_request_duration", labels, start)
	})
}

type LiveMetricsResponse struct {
	Metrics []observability.MetricSnapshot `json:"metrics"`
}

// LiveMetricsHandler godoc
// @Summary Live Prometheus metrics in JSON format
// @Description Returns the current in-memory metrics registry snapshots as structured JSON.
// @Tags metrics
// @Produce json
// @Security ApiKeyAuth
// @Param X-API-Key header string true "API key with metrics scope when metrics auth is enabled"
// @Success 200 {object} LiveMetricsResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Router /api/v1/metrics/live [get]
func LiveMetricsHandler(registry *observability.Registry, db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		recordDBConnectionStats(registry, db)

		snapshots := registry.Snapshot()
		writeJSON(w, http.StatusOK, LiveMetricsResponse{Metrics: snapshots})
	})
}

func recordDBConnectionStats(registry *observability.Registry, db *sql.DB) {
	if registry == nil || db == nil {
		return
	}

	stats := db.Stats()
	registry.Set("db_connections_open", nil, uint64(stats.OpenConnections))        //nolint:gosec
	registry.Set("db_connections_in_use", nil, uint64(stats.InUse))                //nolint:gosec
	registry.Set("db_connections_max_open", nil, uint64(stats.MaxOpenConnections)) //nolint:gosec
}

type MetricHistoryPoint struct {
	Timestamp time.Time         `json:"timestamp"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
	Value     float64           `json:"value"`
	Delta     float64           `json:"delta"`
}

type MetricHistoryResponse struct {
	Points []MetricHistoryPoint `json:"points"`
}

// MetricsHistoryHandler godoc
// @Summary Historical metrics timeseries
// @Description Returns downsampled system metrics from TimescaleDB based on range parameter (1m, 1h, 12h, 24h, 1w, 30d).
// @Tags metrics
// @Produce json
// @Security ApiKeyAuth
// @Param X-API-Key header string true "API key with metrics scope when metrics auth is enabled"
// @Param range query string false "Metrics range window" Enums(1m, 1h, 12h, 24h, 1w, 30d) default(1h)
// @Success 200 {object} MetricHistoryResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/metrics/history [get]
func MetricsHistoryHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timeRange := r.URL.Query().Get("range")
		if timeRange == "" {
			timeRange = "1h"
		}

		var interval time.Duration
		var since time.Time
		now := time.Now().UTC()

		switch timeRange {
		case "1m":
			interval = 1 * time.Second
			since = now.Add(-1 * time.Minute)
		case "1h":
			interval = 1 * time.Minute
			since = now.Add(-1 * time.Hour)
		case "12h":
			interval = 10 * time.Minute
			since = now.Add(-12 * time.Hour)
		case "24h":
			interval = 20 * time.Minute
			since = now.Add(-24 * time.Hour)
		case "1w":
			interval = 1 * time.Hour
			since = now.Add(-7 * 24 * time.Hour)
		case "30d":
			interval = 8 * time.Hour
			since = now.Add(-30 * 24 * time.Hour)
		default:
			interval = 1 * time.Minute
			since = now.Add(-1 * time.Hour)
		}

		rows, err := db.QueryContext(r.Context(), `
			SELECT 
				time_bucket($1, timestamp) AS bucket,
				metric_name,
				labels,
				COALESCE(MAX(value) - MIN(value), 0) AS delta,
				COALESCE(AVG(value), 0) AS val
			FROM quiver.system_metrics
			WHERE timestamp >= $2
			GROUP BY bucket, metric_name, labels
			ORDER BY bucket ASC
		`, interval, since)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, CodeInternalError, "failed to query metrics history", nil)
			return
		}
		defer func() { _ = rows.Close() }()

		points := make([]MetricHistoryPoint, 0)
		for rows.Next() {
			var p MetricHistoryPoint
			var labelsJSON []byte
			err := rows.Scan(&p.Timestamp, &p.Name, &labelsJSON, &p.Delta, &p.Value)
			if err != nil {
				writeError(w, r, http.StatusInternalServerError, CodeInternalError, "failed to read metrics history", nil)
				return
			}
			if len(labelsJSON) > 0 {
				var labels map[string]string
				if err := json.Unmarshal(labelsJSON, &labels); err == nil {
					p.Labels = labels
				}
			}
			points = append(points, p)
		}

		writeJSON(w, http.StatusOK, MetricHistoryResponse{Points: points})
	})
}
