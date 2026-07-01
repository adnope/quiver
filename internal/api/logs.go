package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type SystemLogLine struct {
	Timestamp  time.Time       `json:"timestamp"`
	Level      string          `json:"level"`
	Message    string          `json:"message"`
	Attributes json.RawMessage `json:"attributes" swaggertype:"object"`
}

type LogsHandler struct {
	db *sql.DB
}

func NewLogsHandler(db *sql.DB) *LogsHandler {
	return &LogsHandler{db: db}
}

// ServeHTTP godoc
// @Summary Search persisted backend logs
// @Description Returns newest-first best-effort backend log rows. Invalid time and limit values fall back to defaults.
// @Tags admin
// @Produce json
// @Security ApiKeyAuth
// @Param X-API-Key header string true "API key with metrics scope when metrics auth is enabled"
// @Param from query string false "RFC3339 inclusive start timestamp; defaults to one hour before to"
// @Param to query string false "RFC3339 exclusive end timestamp; defaults to current time"
// @Param level query string false "Exact slog level filter"
// @Param search query string false "Case-insensitive substring search over message and attributes"
// @Param limit query int false "Maximum rows; positive values are capped at 1000" default(100) maximum(1000)
// @Success 200 {array} SystemLogLine
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 429 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /api/v1/admin/logs [get]
func (h *LogsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, r, http.StatusMethodNotAllowed, CodeInvalidRequest, "method not allowed", nil)
		return
	}

	if h.db == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
		return
	}

	values := r.URL.Query()
	limit := 100
	if rawLimit := values.Get("limit"); rawLimit != "" {
		if val, err := strconv.Atoi(rawLimit); err == nil && val > 0 {
			limit = min(val, 1000)
		}
	}

	to := time.Now().UTC()
	if rawTo := values.Get("to"); rawTo != "" {
		if parsed, err := time.Parse(time.RFC3339, rawTo); err == nil {
			to = parsed.UTC()
		}
	}

	from := to.Add(-1 * time.Hour)
	if rawFrom := values.Get("from"); rawFrom != "" {
		if parsed, err := time.Parse(time.RFC3339, rawFrom); err == nil {
			from = parsed.UTC()
		}
	}

	levelFilter := values.Get("level")
	searchFilter := values.Get("search")

	// Build dynamic query safely
	query := `SELECT timestamp, level, message, attributes FROM quiver.system_logs WHERE timestamp >= $1 AND timestamp < $2`
	args := []any{from, to}
	paramIdx := 3

	if levelFilter != "" {
		query += fmt.Sprintf(" AND level = $%d", paramIdx)
		args = append(args, levelFilter)
		paramIdx++
	}

	if searchFilter != "" {
		query += fmt.Sprintf(" AND (message ILIKE $%d OR attributes::text ILIKE $%d)", paramIdx, paramIdx)
		args = append(args, "%"+searchFilter+"%")
		paramIdx++
	}

	//nolint:gosec
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d", paramIdx)
	args = append(args, limit)

	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, CodeInternalError, "failed to query system logs", nil)
		return
	}
	defer func() { _ = rows.Close() }()

	logLines := make([]SystemLogLine, 0)
	for rows.Next() {
		var line SystemLogLine
		var attrsJSON []byte
		if err := rows.Scan(&line.Timestamp, &line.Level, &line.Message, &attrsJSON); err != nil {
			writeError(w, r, http.StatusInternalServerError, CodeInternalError, "failed to scan system log row", nil)
			return
		}
		line.Attributes = json.RawMessage(attrsJSON)
		logLines = append(logLines, line)
	}

	if err := rows.Err(); err != nil {
		writeError(w, r, http.StatusInternalServerError, CodeInternalError, "system logs rows error", nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(logLines)
}
