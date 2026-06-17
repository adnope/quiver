package api

import (
	"net/http"
	"strconv"
	"time"

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

func HealthHandler(checker HealthChecker) http.Handler {
	if checker == nil {
		checker = StaticHealthChecker{Value: HealthOK}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		status := checker.Status()
		code := http.StatusOK
		if status == HealthFail {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, HealthResponse{Status: status})
	})
}

func MetricsHandler(registry *observability.Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(registry.WritePrometheus())
	})
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
