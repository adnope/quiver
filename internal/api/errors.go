package api

import (
	"encoding/json"
	"net/http"
)

const (
	CodeMissingAPIKey            = "missing_api_key"
	CodeInvalidAPIKey            = "invalid_api_key"
	CodeInsufficientScope        = "insufficient_scope"
	CodeRateLimitExceeded        = "rate_limit_exceeded"
	CodeInvalidRequest           = "invalid_request"
	CodeInvalidParameter         = "invalid_parameter"
	CodeMissingRequiredParameter = "missing_required_parameter"
	CodeQueryWindowTooLarge      = "query_window_too_large"
	CodeInvalidCursor            = "invalid_cursor"
	CodeNotFound                 = "not_found"
	CodePayloadTooLarge          = "payload_too_large"
	CodeDatabaseUnavailable      = "database_unavailable"
	CodeServiceUnavailable       = "service_unavailable"
	CodeInternalError            = "internal_error"
)

type ErrorResponse struct {
	Error     APIError `json:"error"`
	RequestID string   `json:"request_id"`
}

type APIError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code string, message string, details map[string]any) {
	writeJSON(w, status, ErrorResponse{
		Error: APIError{
			Code:    code,
			Message: message,
			Details: details,
		},
		RequestID: RequestIDFromContext(r.Context()),
	})
}
