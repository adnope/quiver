package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogsHandlerMethodNotAllowed(t *testing.T) {
	t.Parallel()
	handler := NewLogsHandler(nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/admin/logs", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestLogsHandlerNoDB(t *testing.T) {
	t.Parallel()
	handler := NewLogsHandler(nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/admin/logs", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
	if body := w.Body.String(); body != "[]" {
		t.Errorf("expected empty array, got %q", body)
	}
}
