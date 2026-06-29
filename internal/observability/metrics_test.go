package observability

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"log/slog"
	"strings"
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
		registry.durations[key][i] = uint64(i + 1)
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

	for range durationReservoirSize + 25 {
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

func TestRegistryDrainDurationAggregatesAndHistogram(t *testing.T) {
	registry := NewRegistry()
	key := seriesKey{name: "storage_insert_duration", labels: encodeLabels(map[string]string{"status": "ok"})}
	registry.mu.Lock()
	registry.accumulatorFor(key).observeDuration(1)
	registry.accumulatorFor(key).observeDuration(2)
	registry.accumulatorFor(key).observeDuration(5)
	registry.accumulatorFor(key).observeDuration(10)
	registry.histograms[key] = make([]uint64, durationHistogramBucketCount())
	registry.histograms[key][durationHistogramBucketIndex(1)]++
	registry.histograms[key][durationHistogramBucketIndex(2)]++
	registry.histograms[key][durationHistogramBucketIndex(5)]++
	registry.histograms[key][durationHistogramBucketIndex(10)]++
	registry.mu.Unlock()

	bucketStart := time.Date(2026, 6, 24, 7, 0, 0, 0, time.UTC)
	aggregates, buckets := registry.DrainBucketAggregates(bucketStart, 5*time.Second)
	if len(aggregates) != 1 {
		t.Fatalf("aggregate count = %d, want 1", len(aggregates))
	}
	agg := aggregates[0]
	if agg.MetricKind != MetricKindDuration || agg.Count != 4 || agg.SampleCount != 4 {
		t.Fatalf("aggregate = %+v", agg)
	}
	if valueOrZero(agg.Sum) != 18 || valueOrZero(agg.Avg) != 4.5 || valueOrZero(agg.Min) != 1 || valueOrZero(agg.Max) != 10 {
		t.Fatalf("unexpected aggregate values: %+v", agg)
	}
	if valueOrZero(agg.P90) != 10 || valueOrZero(agg.P95) != 10 || valueOrZero(agg.P99) != 10 {
		t.Fatalf("unexpected percentile values: %+v", agg)
	}
	if len(buckets) != 4 {
		t.Fatalf("histogram bucket rows = %d, want 4", len(buckets))
	}

	aggregates, buckets = registry.DrainBucketAggregates(bucketStart.Add(5*time.Second), 5*time.Second)
	if len(aggregates) != 0 || len(buckets) != 0 {
		t.Fatalf("drain should reset aggregates, got aggregates=%d buckets=%d", len(aggregates), len(buckets))
	}
}

func TestRegistryDrainCounterAndGaugeAggregates(t *testing.T) {
	registry := NewRegistry()
	registry.Add("flow_records_stored_total", map[string]string{"source_type": "rest_json"}, 3)
	registry.Add("flow_records_stored_total", map[string]string{"source_type": "rest_json"}, 2)
	registry.Set("db_connections_open", nil, 4)
	registry.Set("db_connections_open", nil, 6)

	aggregates, _ := registry.DrainBucketAggregates(time.Now().UTC(), 5*time.Second)
	counter := findAggregate(aggregates, "flow_records_stored_total")
	if counter == nil {
		t.Fatal("missing counter aggregate")
		return
	}
	if counter.MetricKind != MetricKindCounter || counter.Count != 2 || valueOrZero(counter.Sum) != 5 || valueOrZero(counter.Delta) != 5 {
		t.Fatalf("counter aggregate = %+v", counter)
	}
	if valueOrZero(counter.First) != 0 || valueOrZero(counter.Last) != 5 {
		t.Fatalf("counter first/last = %+v", counter)
	}

	gauge := findAggregate(aggregates, "db_connections_open")
	if gauge == nil {
		t.Fatal("missing gauge aggregate")
		return
	}
	if gauge.MetricKind != MetricKindGauge || gauge.Count != 2 || valueOrZero(gauge.Avg) != 5 || valueOrZero(gauge.Min) != 4 || valueOrZero(gauge.Max) != 6 {
		t.Fatalf("gauge aggregate = %+v", gauge)
	}
}

func valueOrZero(value *float64) float64 {
	if value == nil {
		return 0
	}
	return *value
}

func findAggregate(aggregates []MetricAggregate, name string) *MetricAggregate {
	for i := range aggregates {
		if aggregates[i].MetricName == name {
			return &aggregates[i]
		}
	}
	return nil
}

func TestRegistryPreservesNetFlowV9Labels(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	registry.Add("collector_packets_received_total", map[string]string{"collector_id": "v9-main", "source_type": "netflow_v9"}, 5)

	if got := snapshotValue(registry.Snapshot(), "collector_packets_received_total", map[string]string{"collector_id": "v9-main", "source_type": "netflow_v9"}); got != 5 {
		t.Fatalf("snapshot value = %d, want 5", got)
	}

	body := string(registry.WritePrometheus())
	if !strings.Contains(body, `collector_packets_received_total{collector_id="v9-main",source_type="netflow_v9"} 5`) {
		t.Fatalf("metrics body missing netflow_v9 source_type label:\n%s", body)
	}
}
