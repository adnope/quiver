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

type mockCollectorDriver struct {
	mu       sync.Mutex
	queries  []string
	execArgs [][]driver.Value
}

func (d *mockCollectorDriver) Open(name string) (driver.Conn, error) {
	return &mockCollectorConn{d: d}, nil
}

type mockCollectorConn struct {
	d *mockCollectorDriver
}

func (c *mockCollectorConn) Prepare(query string) (driver.Stmt, error) {
	return &mockCollectorStmt{c: c, query: query}, nil
}

func (c *mockCollectorConn) Close() error {
	return nil
}

func (c *mockCollectorConn) Begin() (driver.Tx, error) {
	return &mockCollectorTx{}, nil
}

func (c *mockCollectorConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return &mockCollectorTx{}, nil
}

type mockCollectorStmt struct {
	c     *mockCollectorConn
	query string
}

func (s *mockCollectorStmt) Close() error {
	return nil
}

func (s *mockCollectorStmt) NumInput() int {
	return -1
}

func (s *mockCollectorStmt) Exec(args []driver.Value) (driver.Result, error) {
	s.c.d.mu.Lock()
	s.c.d.queries = append(s.c.d.queries, s.query)
	s.c.d.execArgs = append(s.c.d.execArgs, args)
	s.c.d.mu.Unlock()
	return &mockCollectorResult{}, nil
}

func (s *mockCollectorStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	s.c.d.mu.Lock()
	s.c.d.queries = append(s.c.d.queries, s.query)
	var values []driver.Value
	for _, arg := range args {
		values = append(values, arg.Value)
	}
	s.c.d.execArgs = append(s.c.d.execArgs, values)
	s.c.d.mu.Unlock()
	return &mockCollectorResult{}, nil
}

func (s *mockCollectorStmt) Query(args []driver.Value) (driver.Rows, error) {
	return nil, errors.ErrUnsupported
}

func (s *mockCollectorStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return nil, errors.ErrUnsupported
}

type mockCollectorResult struct{}

func (r *mockCollectorResult) LastInsertId() (int64, error) { return 0, nil }
func (r *mockCollectorResult) RowsAffected() (int64, error) { return 1, nil }

type mockCollectorTx struct{}

func (tx *mockCollectorTx) Commit() error {
	return nil
}

func (tx *mockCollectorTx) Rollback() error {
	return nil
}

func TestMetricsSaverLifecycleAndSave(t *testing.T) {
	driverName := "mock_collector_driver"
	drv := &mockCollectorDriver{}
	sql.Register(driverName, drv)

	db, err := sql.Open(driverName, "dsn")
	if err != nil {
		t.Fatalf("failed to open mock db: %v", err)
	}
	defer func() { _ = db.Close() }()

	registry := NewRegistry()
	registry.Set("my_gauge", map[string]string{"foo": "bar"}, 42)
	registry.ObserveDuration("my_duration", map[string]string{"foo": "bar"}, time.Now().Add(-10*time.Millisecond))

	// Create and start saver
	saver := NewMetricsSaver(db, registry, slog.Default(), 15*time.Millisecond)
	saver.Start(context.Background())

	// Wait a bit to trigger at least one snapshot save
	time.Sleep(30 * time.Millisecond)
	saver.Stop()

	// Verify queries were run
	drv.mu.Lock()
	queriesRun := len(drv.queries)
	drv.mu.Unlock()

	if queriesRun == 0 {
		t.Error("expected database queries to be executed by saver")
	}
}

func TestNewMetricsSaverEdgeCases(t *testing.T) {
	saver := NewMetricsSaverWithBucketWidth(nil, nil, nil, -1, -1)
	if saver.interval != 5*time.Second {
		t.Errorf("expected default interval 5s, got %v", saver.interval)
	}
	if saver.bucketWidth != 5*time.Second {
		t.Errorf("expected default bucketWidth 5s, got %v", saver.bucketWidth)
	}
	if saver.logger == nil {
		t.Error("expected default logger to be set")
	}
}
