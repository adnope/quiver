package observability

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"
)

type DbLogHandler struct {
	slog.Handler
	db *sql.DB
}

func NewDbLogHandler(stdoutHandler slog.Handler) *DbLogHandler {
	return &DbLogHandler{
		Handler: stdoutHandler,
	}
}

func (h *DbLogHandler) SetDB(db *sql.DB) {
	h.db = db
}

func (h *DbLogHandler) Handle(ctx context.Context, r slog.Record) error {
	err := h.Handler.Handle(ctx, r)

	if h.db == nil {
		return err
	}

	attrs := make(map[string]any)
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})

	attrsJSON, jsonErr := json.Marshal(attrs)
	if jsonErr != nil {
		attrsJSON = []byte("{}")
	}

	//nolint:gosec,contextcheck // background context is required for database writes to survive request cancellation
	go func(timestamp time.Time, level, message string, attributes []byte) {
		writeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		query := `INSERT INTO quiver.system_logs (timestamp, level, message, attributes) 
				  VALUES ($1, $2, $3, $4)`
		_, _ = h.db.ExecContext(writeCtx, query, timestamp, level, message, attributes)
	}(r.Time.UTC(), r.Level.String(), r.Message, attrsJSON)

	return err
}

func (h *DbLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &DbLogHandler{
		Handler: h.Handler.WithAttrs(attrs),
		db:      h.db,
	}
}

func (h *DbLogHandler) WithGroup(name string) slog.Handler {
	return &DbLogHandler{
		Handler: h.Handler.WithGroup(name),
		db:      h.db,
	}
}
