package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type mockRefresherDriver struct {
	mu            sync.Mutex
	queries       []string
	advisoryRetry int
	lockReturns   []bool
	execErr       error
}

func (d *mockRefresherDriver) Open(name string) (driver.Conn, error) {
	return &mockRefresherConn{d: d}, nil
}

type mockRefresherConn struct {
	d *mockRefresherDriver
}

func (c *mockRefresherConn) Prepare(query string) (driver.Stmt, error) {
	return &mockRefresherStmt{c: c, query: query}, nil
}

func (c *mockRefresherConn) Close() error {
	return nil
}

func (c *mockRefresherConn) Begin() (driver.Tx, error) {
	return &mockRefresherTx{}, nil
}

type mockRefresherStmt struct {
	c     *mockRefresherConn
	query string
}

func (s *mockRefresherStmt) Close() error {
	return nil
}

func (s *mockRefresherStmt) NumInput() int {
	return -1
}

func (s *mockRefresherStmt) Exec(args []driver.Value) (driver.Result, error) {
	return nil, errors.New("not implemented")
}

func (s *mockRefresherStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	s.c.d.mu.Lock()
	defer s.c.d.mu.Unlock()
	s.c.d.queries = append(s.c.d.queries, s.query)
	if s.c.d.execErr != nil {
		return nil, s.c.d.execErr
	}
	return &mockRefresherResult{}, nil
}

func (s *mockRefresherStmt) Query(args []driver.Value) (driver.Rows, error) {
	return nil, errors.New("not implemented")
}

func (s *mockRefresherStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	s.c.d.mu.Lock()
	defer s.c.d.mu.Unlock()
	s.c.d.queries = append(s.c.d.queries, s.query)

	val := true
	if len(s.c.d.lockReturns) > s.c.d.advisoryRetry {
		val = s.c.d.lockReturns[s.c.d.advisoryRetry]
		s.c.d.advisoryRetry++
	}

	return &mockRefresherRows{val: val}, nil
}

type mockRefresherResult struct{}

func (r *mockRefresherResult) LastInsertId() (int64, error) { return 0, nil }
func (r *mockRefresherResult) RowsAffected() (int64, error) { return 1, nil }

type mockRefresherTx struct{}

func (tx *mockRefresherTx) Commit() error   { return nil }
func (tx *mockRefresherTx) Rollback() error { return nil }

type mockRefresherRows struct {
	val  bool
	read bool
}

func (r *mockRefresherRows) Columns() []string {
	return []string{"pg_try_advisory_lock"}
}

func (r *mockRefresherRows) Close() error {
	return nil
}

func (r *mockRefresherRows) Next(dest []driver.Value) error {
	if r.read {
		return io.EOF
	}
	dest[0] = r.val
	r.read = true
	return nil
}

func TestNewFlowAggregateRefresher(t *testing.T) {
	refresher := NewFlowAggregateRefresher(nil, nil)
	if refresher.logger == nil {
		t.Error("expected default logger to be set")
	}
}

func TestFlowAggregateRefresher_Refresh(t *testing.T) {
	driverName := "mock_refresher_driver"
	drv := &mockRefresherDriver{
		lockReturns: []bool{true, false}, // first call succeeds, second lock skipped
	}
	sql.Register(driverName, drv)

	db, err := sql.Open(driverName, "dsn")
	if err != nil {
		t.Fatalf("failed to open mock db: %v", err)
	}
	defer func() { _ = db.Close() }()

	refresher := NewFlowAggregateRefresher(db, slog.Default())
	refresher.now = func() time.Time {
		return time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	}

	ctx := context.Background()

	// 1. Successful Refresh
	views := []string{"quiver.flow_5m_talkers"}
	err = refresher.refresh(ctx, views, time.Hour, "test_reason")
	if err != nil {
		t.Fatalf("unexpected refresh error: %v", err)
	}

	// 2. Lock not acquired (skipped)
	err = refresher.refresh(ctx, views, time.Hour, "test_reason_2")
	if err != nil {
		t.Fatalf("unexpected refresh error when lock skipped: %v", err)
	}

	// 3. Invalid view query failure
	err = refresher.refresh(ctx, []string{"invalid_view"}, time.Hour, "bad_view")
	if err == nil {
		t.Error("expected error for invalid view")
	}

	// 4. ExecContext query execution error
	drv.mu.Lock()
	drv.execErr = errors.New("exec error")
	drv.lockReturns = append(drv.lockReturns, true) // ensure lock succeeds
	drv.mu.Unlock()

	err = refresher.refresh(ctx, views, time.Hour, "exec_fail")
	if err == nil {
		t.Error("expected error when exec fails")
	}

	// 5. Canceled context
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	err = refresher.refresh(canceledCtx, views, time.Hour, "canceled")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestFlowAggregateRefresher_Run(t *testing.T) {
	// If db is nil, Run should return immediately
	var nilRefresher *FlowAggregateRefresher
	nilRefresher.Run(context.Background()) // should not panic

	refresherNilDB := NewFlowAggregateRefresher(nil, nil)
	refresherNilDB.Run(context.Background()) // should not panic

	driverName := "mock_refresher_driver"
	db, err := sql.Open(driverName, "dsn")
	if err != nil {
		t.Fatalf("failed to open mock db: %v", err)
	}
	defer func() { _ = db.Close() }()

	refresher := NewFlowAggregateRefresher(db, slog.Default())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	refresher.Run(ctx)
}
