package observability

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// Define mock slog.Handler
type mockSlogHandler struct {
	mu      sync.Mutex
	handled []slog.Record
	attrs   []slog.Attr
	group   string
}

func (m *mockSlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return true
}

func (m *mockSlogHandler) Handle(ctx context.Context, r slog.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handled = append(m.handled, r)
	return nil
}

func (m *mockSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()
	return &mockSlogHandler{
		attrs: append(m.attrs, attrs...),
		group: m.group,
	}
}

func (m *mockSlogHandler) WithGroup(name string) slog.Handler {
	m.mu.Lock()
	defer m.mu.Unlock()
	return &mockSlogHandler{
		attrs: m.attrs,
		group: name,
	}
}

// Define mock SQL driver
type mockSQLDriver struct {
	mu    sync.Mutex
	query string
	args  []driver.Value
	ch    chan struct{}
}

func (d *mockSQLDriver) Open(name string) (driver.Conn, error) {
	return &mockSQLConn{d: d}, nil
}

type mockSQLConn struct {
	d *mockSQLDriver
}

func (c *mockSQLConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.ErrUnsupported
}

func (c *mockSQLConn) Close() error {
	return nil
}

func (c *mockSQLConn) Begin() (driver.Tx, error) {
	return nil, errors.ErrUnsupported
}

func (c *mockSQLConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.d.mu.Lock()
	c.d.query = query
	c.d.args = nil
	for _, a := range args {
		c.d.args = append(c.d.args, a.Value)
	}
	c.d.mu.Unlock()
	// signal write completed if not already closed
	select {
	case <-c.d.ch:
	default:
		close(c.d.ch)
	}
	return &mockSQLResult{}, nil
}

type mockSQLResult struct{}

func (r *mockSQLResult) LastInsertId() (int64, error) { return 0, nil }
func (r *mockSQLResult) RowsAffected() (int64, error) { return 1, nil }

func TestDbLogHandler(t *testing.T) {
	driverName := "mock_slog_driver"
	mockDrv := &mockSQLDriver{ch: make(chan struct{})}
	sql.Register(driverName, mockDrv)

	db, err := sql.Open(driverName, "dsn")
	if err != nil {
		t.Fatalf("failed to open mock db: %v", err)
	}
	defer func() { _ = db.Close() }()

	parent := &mockSlogHandler{}
	handler := NewDbLogHandler(parent)

	// Test 1: db is nil, should handle without DB write
	rec := slog.Record{
		Time:    time.Now(),
		Level:   slog.LevelInfo,
		Message: "test message",
	}
	err = handler.Handle(context.Background(), rec)
	if err != nil {
		t.Fatalf("unexpected handle error: %v", err)
	}
	if len(parent.handled) != 1 {
		t.Errorf("expected 1 handled log, got %d", len(parent.handled))
	}

	// Test 2: SetDB, should write to DB
	handler.SetDB(db)
	rec2 := slog.Record{
		Time:    time.Now(),
		Level:   slog.LevelError,
		Message: "db test message",
	}
	rec2.AddAttrs(slog.String("key", "val"))

	err = handler.Handle(context.Background(), rec2)
	if err != nil {
		t.Fatalf("unexpected handle error: %v", err)
	}

	// Wait for goroutine database write
	select {
	case <-mockDrv.ch:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for DB write")
	}

	mockDrv.mu.Lock()
	q := mockDrv.query
	args := mockDrv.args
	mockDrv.mu.Unlock()

	if q == "" {
		t.Error("expected DB query to be executed")
	}
	if len(args) != 4 {
		t.Errorf("expected 4 args, got %d", len(args))
	} else {
		// Timestamp, Level, Message, Attributes JSON
		if args[1] != "ERROR" {
			t.Errorf("expected Level 'ERROR', got %v", args[1])
		}
		if args[2] != "db test message" {
			t.Errorf("expected Message 'db test message', got %v", args[2])
		}
	}

	// Test WithAttrs and WithGroup
	hWithAttrs := handler.WithAttrs([]slog.Attr{slog.String("a", "b")})
	dbHWithAttrs, ok := hWithAttrs.(*DbLogHandler)
	if !ok {
		t.Fatal("expected WithAttrs to return *DbLogHandler")
	}
	if dbHWithAttrs.db != db {
		t.Error("expected db to be propagated in WithAttrs")
	}

	hWithGroup := handler.WithGroup("g")
	dbHWithGroup, ok := hWithGroup.(*DbLogHandler)
	if !ok {
		t.Fatal("expected WithGroup to return *DbLogHandler")
	}
	if dbHWithGroup.db != db {
		t.Error("expected db to be propagated in WithGroup")
	}
}
