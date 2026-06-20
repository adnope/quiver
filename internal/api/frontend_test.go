package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/adnope/quiver/internal/observability"
)

func TestFrontendHandlerServesIndexAndAssets(t *testing.T) {
	t.Parallel()

	handler := FrontendHandler(testFrontendFS())

	tests := []struct {
		name        string
		path        string
		wantStatus  int
		wantBody    string
		contentType string
	}{
		{
			name:        "root index",
			path:        "/",
			wantStatus:  http.StatusOK,
			wantBody:    "Quiver UI",
			contentType: "text/html",
		},
		{
			name:        "spa fallback",
			path:        "/flows/abc",
			wantStatus:  http.StatusOK,
			wantBody:    "Quiver UI",
			contentType: "text/html",
		},
		{
			name:        "static asset",
			path:        "/assets/app.js",
			wantStatus:  http.StatusOK,
			wantBody:    "console.log",
			contentType: "text/javascript",
		},
		{
			name:       "missing asset",
			path:       "/assets/missing.js",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "reserved api path",
			path:       "/api/v1/unknown",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d body=%s", recorder.Code, tt.wantStatus, recorder.Body.String())
			}
			if tt.wantBody != "" && !strings.Contains(recorder.Body.String(), tt.wantBody) {
				t.Fatalf("body = %q, want substring %q", recorder.Body.String(), tt.wantBody)
			}
			if tt.contentType != "" && !strings.Contains(recorder.Header().Get("Content-Type"), tt.contentType) {
				t.Fatalf("content-type = %q, want %q", recorder.Header().Get("Content-Type"), tt.contentType)
			}
		})
	}
}

func TestServerPreservesBackendRoutePrecedence(t *testing.T) {
	t.Parallel()

	cfg := validAPICfg()
	cfg.API.Health.AuthRequired = false
	server, err := NewServerWithObservability(
		cfg,
		newImmediatePublisher(),
		nil,
		nil,
		envLookup(),
		observability.NewRegistry(),
		StaticHealthChecker{Value: HealthOK},
	)
	if err != nil {
		t.Fatalf("NewServerWithObservability() error = %v", err)
	}

	health := httptest.NewRecorder()
	server.Handler().ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("/health status = %d, want 200 body=%s", health.Code, health.Body.String())
	}
	if !strings.Contains(health.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("/health content-type = %q, want json", health.Header().Get("Content-Type"))
	}

	api := httptest.NewRecorder()
	server.Handler().ServeHTTP(api, httptest.NewRequest(http.MethodGet, "/api/v1/unknown", nil))
	if api.Code != http.StatusNotFound {
		t.Fatalf("/api unknown status = %d, want 404", api.Code)
	}
}

func testFrontendFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html": {
			Data: []byte("<!doctype html><title>Quiver UI</title>"),
		},
		"assets/app.js": {
			Data: []byte("console.log('quiver')"),
		},
	}
}
