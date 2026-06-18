//go:build integration

package zeek

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/storage/postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func TestZeekCollectorIntegration(t *testing.T) {
	dsn := os.Getenv("QUIVER_TEST_DATABASE_DSN")
	if dsn == "" {
		dsn = os.Getenv("QUIVER_DATABASE_DSN")
	}
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/quiver?sslmode=disable"
	}

	// 1. Run Migrations
	migrator, err := migrate.New("file://../../storage/postgres/migrations", dsn)
	if err != nil {
		t.Fatalf("Failed to create migrator: %v", err)
	}
	if err := migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("Failed to run migrations up: %v", err)
	}

	// 2. Open DB
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Clear out state store
	if _, err := db.ExecContext(ctx, "DELETE FROM quiver.collector_states"); err != nil {
		t.Fatalf("Failed to clear states: %v", err)
	}

	stateStore, err := postgres.NewStateStore(db)
	if err != nil {
		t.Fatalf("Failed to create StateStore: %v", err)
	}

	// Create a log file
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "conn.log")
	line1 := `{"ts":1718532920.125,"uid":"C1","id.orig_h":"192.0.2.10","id.orig_p":51524,"id.resp_h":"198.51.100.20","id.resp_p":443,"proto":"tcp","orig_bytes":120,"resp_bytes":340}`
	if err := os.WriteFile(logPath, []byte(line1+"\n"), 0644); err != nil {
		t.Fatalf("Failed to write log file: %v", err)
	}

	publisher := &fakeIntegrationPublisher{}
	collector, err := NewCollector(config.ZeekCollectorConfig{
		Enabled:       true,
		CollectorID:   "zeek-integration-01",
		SourceHost:    "zeek-probe-test",
		FilePath:      logPath,
		PollInterval:  config.Duration(10 * time.Millisecond),
		StartPosition: "beginning",
		MaxLineBytes:  4096,
		StateKey:      "zeek-integration-state-key",
	}, stateStore, publisher, nil, nil)
	if err != nil {
		t.Fatalf("NewCollector failed: %v", err)
	}
	collector.now = func() time.Time { return time.Date(2026, 6, 18, 2, 0, 0, 0, time.UTC) }

	// Run process once
	if err := collector.ProcessOnce(ctx); err != nil {
		t.Fatalf("ProcessOnce failed: %v", err)
	}

	publisher.mu.Lock()
	rawLen := len(publisher.raw)
	publisher.mu.Unlock()

	if rawLen != 1 {
		t.Errorf("Expected 1 event published, got %d", rawLen)
	}

	// Verify state saved to TimescaleDB
	state, found, err := stateStore.Load(ctx, "zeek-integration-state-key")
	if err != nil {
		t.Fatalf("Load state failed: %v", err)
	}
	if !found {
		t.Error("State was not found in DB")
	}
	if state.CollectorID != "zeek-integration-01" {
		t.Errorf("Unexpected collector ID in state: %s", state.CollectorID)
	}

	// Add another line and process again to verify resuming from state
	line2 := `{"ts":1718532922.125,"uid":"C2","id.orig_h":"192.0.2.10","id.orig_p":51524,"id.resp_h":"198.51.100.20","id.resp_p":443,"proto":"tcp","orig_bytes":120,"resp_bytes":340}`
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("Failed to open file for append: %v", err)
	}
	_, _ = f.WriteString(line2 + "\n")
	_ = f.Close()

	if err := collector.ProcessOnce(ctx); err != nil {
		t.Fatalf("ProcessOnce (second run) failed: %v", err)
	}

	publisher.mu.Lock()
	rawLen = len(publisher.raw)
	publisher.mu.Unlock()

	// Total should be 2 now
	if rawLen != 2 {
		t.Errorf("Expected 2 total events, got %d", rawLen)
	}
}

type fakeIntegrationPublisher struct {
	mu  sync.Mutex
	raw []*flowv1.RawFlowEventEnvelope
}

func (p *fakeIntegrationPublisher) PublishRaw(ctx context.Context, event *flowv1.RawFlowEventEnvelope) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raw = append(p.raw, event)
	return nil
}

func (p *fakeIntegrationPublisher) PublishDeadLetter(ctx context.Context, event *flowv1.DeadLetterEvent) error {
	return nil
}

func (p *fakeIntegrationPublisher) Flush(ctx context.Context) error {
	return nil
}

var _ kafka.RawEventPublisher = (*fakeIntegrationPublisher)(nil)
