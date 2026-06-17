package api

import (
	"context"
	"database/sql"
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
