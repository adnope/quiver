package observability

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"log/slog"
	"testing"
	"time"
)

func TestRegistrySetPersistsGauge(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	registry.Set("db_connections_open", nil, 12)
	registry.Set("db_connections_in_use", map[string]string{"pool": "writer"}, 3)
	registry.Set("db_connections_in_use", map[string]string{"pool": "writer"}, 4)

	if got := snapshotValue(registry.Snapshot(), "db_connections_open", nil); got != 12 {
		t.Fatalf("db_connections_open = %d, want 12", got)
	}
	if got := snapshotValue(registry.Snapshot(), "db_connections_in_use", map[string]string{"pool": "writer"}); got != 4 {
		t.Fatalf("db_connections_in_use = %d, want 4", got)
	}

	body := string(registry.WritePrometheus())
	if body == "" {
		t.Fatal("WritePrometheus() returned empty body")
	}
}

func TestRegistryDurationPercentileSnapshots(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	key := seriesKey{name: "storage_insert_duration", labels: encodeLabels(map[string]string{"status": "ok"})}
	registry.durations[key] = make([]uint64, 100)
	for i := range registry.durations[key] {
		registry.durations[key][i] = uint64(i + 1) //nolint:gosec
	}

	snapshots := registry.Snapshot()
	labels := map[string]string{"status": "ok"}
	if got := snapshotValue(snapshots, "storage_insert_duration_p95", labels); got != 95 {
		t.Fatalf("p95 = %d, want 95", got)
	}
	if got := snapshotValue(snapshots, "storage_insert_duration_p99", labels); got != 99 {
		t.Fatalf("p99 = %d, want 99", got)
	}
}

func TestRegistryObserveDurationSlidingWindow(t *testing.T) {
	registry := NewRegistry()

	for i := 0; i < durationReservoirSize+25; i++ {
		registry.ObserveDuration("storage_insert_duration", nil, time.Now().Add(-time.Millisecond))
	}

	registry.mu.RLock()
	got := len(registry.durations[seriesKey{name: "storage_insert_duration"}])
	registry.mu.RUnlock()
	if got != durationReservoirSize {
		t.Fatalf("duration reservoir length = %d, want %d", got, durationReservoirSize)
	}
}

func TestMetricsSaverRecordsDBConnectionStatsBeforePersist(t *testing.T) {
	registry := NewRegistry()
	db := sql.OpenDB(errorConnector{})
	t.Cleanup(func() { _ = db.Close() })

	saver := NewMetricsSaver(db, registry, slog.Default(), time.Second)
	saver.saveSnapshot(context.Background())

	if got := snapshotValue(registry.Snapshot(), "db_connections_open", nil); got != 0 {
		t.Fatalf("db_connections_open = %d, want 0", got)
	}
	if got := snapshotValue(registry.Snapshot(), "db_connections_in_use", nil); got != 0 {
		t.Fatalf("db_connections_in_use = %d, want 0", got)
	}
}

func snapshotValue(snapshots []MetricSnapshot, name string, labels map[string]string) uint64 {
	encodedLabels := encodeLabels(labels)
	for _, snapshot := range snapshots {
		if snapshot.Name == name && encodeLabels(snapshot.Labels) == encodedLabels {
			return snapshot.Value
		}
	}
	return 0
}

type errorConnector struct{}

func (errorConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, errors.New("expected test connector failure")
}

func (errorConnector) Driver() driver.Driver { return errorDriver{} }

type errorDriver struct{}

func (errorDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("expected test driver failure")
}
