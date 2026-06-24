package observability

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"math"
	"sync"
	"time"
)

type MetricsSaver struct {
	db          *sql.DB
	registry    *Registry
	logger      *slog.Logger
	interval    time.Duration
	bucketWidth time.Duration
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

func NewMetricsSaver(db *sql.DB, registry *Registry, logger *slog.Logger, interval time.Duration) *MetricsSaver {
	return NewMetricsSaverWithBucketWidth(db, registry, logger, interval, interval)
}

func NewMetricsSaverWithBucketWidth(
	db *sql.DB,
	registry *Registry,
	logger *slog.Logger,
	interval time.Duration,
	bucketWidth time.Duration,
) *MetricsSaver {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if bucketWidth <= 0 {
		bucketWidth = interval
	}
	return &MetricsSaver{
		db:          db,
		registry:    registry,
		logger:      logger,
		interval:    interval,
		bucketWidth: bucketWidth,
	}
}

func (s *MetricsSaver) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.wg.Add(1)
	go s.run(ctx)
}

func (s *MetricsSaver) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

func (s *MetricsSaver) run(ctx context.Context) {
	defer s.wg.Done()
	s.logger.Info(
		"background metrics saver started",
		slog.Duration("interval", s.interval),
		slog.Duration("bucket_width", s.bucketWidth),
	)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Preserve context values while allowing a bounded final write after cancellation.
			finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			s.saveSnapshot(finalCtx)
			cancel()
			return
		case <-ticker.C:
			s.saveSnapshot(ctx)
		}
	}
}

func (s *MetricsSaver) saveSnapshot(ctx context.Context) {
	if s.db == nil || s.registry == nil {
		return
	}

	stats := s.db.Stats()
	s.registry.Set("db_connections_open", nil, uint64(stats.OpenConnections))        //nolint:gosec
	s.registry.Set("db_connections_in_use", nil, uint64(stats.InUse))                //nolint:gosec
	s.registry.Set("db_connections_max_open", nil, uint64(stats.MaxOpenConnections)) //nolint:gosec

	now := time.Now().UTC()
	bucketStart := alignBucketStart(now.Add(-s.bucketWidth), s.bucketWidth)
	snapshots := s.registry.Snapshot()
	aggregates, histogramBuckets := s.registry.DrainBucketAggregates(bucketStart, s.bucketWidth)
	if len(snapshots) == 0 && len(aggregates) == 0 && len(histogramBuckets) == 0 {
		return
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.logger.Error("failed to begin transaction for metrics saving", slog.Any("error", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	s.insertSnapshots(ctx, tx, now, snapshots)
	s.insertAggregates(ctx, tx, aggregates)
	s.insertHistogramBuckets(ctx, tx, histogramBuckets)

	if err := tx.Commit(); err != nil {
		s.logger.Error("failed to commit metrics saving transaction", slog.Any("error", err))
	}
}

func (s *MetricsSaver) insertSnapshots(
	ctx context.Context,
	tx *sql.Tx,
	now time.Time,
	snapshots []MetricSnapshot,
) {
	if len(snapshots) == 0 {
		return
	}

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO quiver.system_metrics (timestamp, metric_name, labels, value) VALUES ($1, $2, $3, $4)`)
	if err != nil {
		s.logger.Error("failed to prepare statement for metrics saving", slog.Any("error", err))
		return
	}
	defer func() { _ = stmt.Close() }()

	for _, snap := range snapshots {
		labelsJSON, err := marshalLabels(snap.Labels)
		if err != nil {
			s.logger.Error("failed to marshal metrics labels", slog.String("metric", snap.Name), slog.Any("error", err))
			continue
		}

		_, err = stmt.ExecContext(ctx, now, snap.Name, labelsJSON, float64(snap.Value))
		if err != nil {
			s.logger.Error("failed to insert metric snapshot", slog.String("metric", snap.Name), slog.Any("error", err))
			continue
		}
	}
}

func (s *MetricsSaver) insertAggregates(ctx context.Context, tx *sql.Tx, aggregates []MetricAggregate) {
	if len(aggregates) == 0 {
		return
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO quiver.system_metric_aggregates (
			bucket_start,
			bucket_width_seconds,
			metric_name,
			labels,
			metric_kind,
			sample_count,
			count,
			sum,
			avg,
			min,
			max,
			p90,
			p95,
			p99,
			first,
			last,
			delta
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		ON CONFLICT (bucket_start, bucket_width_seconds, metric_name, labels)
		DO UPDATE SET
			metric_kind = EXCLUDED.metric_kind,
			sample_count = EXCLUDED.sample_count,
			count = EXCLUDED.count,
			sum = EXCLUDED.sum,
			avg = EXCLUDED.avg,
			min = EXCLUDED.min,
			max = EXCLUDED.max,
			p90 = EXCLUDED.p90,
			p95 = EXCLUDED.p95,
			p99 = EXCLUDED.p99,
			first = EXCLUDED.first,
			last = EXCLUDED.last,
			delta = EXCLUDED.delta`)
	if err != nil {
		s.logger.Error("failed to prepare statement for metric aggregates", slog.Any("error", err))
		return
	}
	defer func() { _ = stmt.Close() }()

	for _, aggregate := range aggregates {
		labelsJSON, err := marshalLabels(aggregate.Labels)
		if err != nil {
			s.logger.Error("failed to marshal aggregate labels", slog.String("metric", aggregate.MetricName), slog.Any("error", err))
			continue
		}
		_, err = stmt.ExecContext(
			ctx,
			aggregate.BucketStart,
			aggregate.BucketWidthSeconds,
			aggregate.MetricName,
			labelsJSON,
			string(aggregate.MetricKind),
			uint64ToInt64(aggregate.SampleCount),
			uint64ToInt64(aggregate.Count),
			nullableFloat(aggregate.Sum),
			nullableFloat(aggregate.Avg),
			nullableFloat(aggregate.Min),
			nullableFloat(aggregate.Max),
			nullableFloat(aggregate.P90),
			nullableFloat(aggregate.P95),
			nullableFloat(aggregate.P99),
			nullableFloat(aggregate.First),
			nullableFloat(aggregate.Last),
			nullableFloat(aggregate.Delta),
		)
		if err != nil {
			s.logger.Error("failed to insert metric aggregate", slog.String("metric", aggregate.MetricName), slog.Any("error", err))
			continue
		}
	}
}

func (s *MetricsSaver) insertHistogramBuckets(ctx context.Context, tx *sql.Tx, buckets []MetricHistogramBucket) {
	if len(buckets) == 0 {
		return
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO quiver.system_metric_histogram_buckets (
			bucket_start,
			bucket_width_seconds,
			metric_name,
			labels,
			bucket_index,
			bucket_upper_bound,
			count
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (bucket_start, bucket_width_seconds, metric_name, labels, bucket_index)
		DO UPDATE SET
			bucket_upper_bound = EXCLUDED.bucket_upper_bound,
			count = EXCLUDED.count`)
	if err != nil {
		s.logger.Error("failed to prepare statement for metric histogram buckets", slog.Any("error", err))
		return
	}
	defer func() { _ = stmt.Close() }()

	for _, bucket := range buckets {
		labelsJSON, err := marshalLabels(bucket.Labels)
		if err != nil {
			s.logger.Error("failed to marshal histogram labels", slog.String("metric", bucket.MetricName), slog.Any("error", err))
			continue
		}
		_, err = stmt.ExecContext(
			ctx,
			bucket.BucketStart,
			bucket.BucketWidthSeconds,
			bucket.MetricName,
			labelsJSON,
			bucket.BucketIndex,
			nullableFloat(bucket.BucketUpperBound),
			uint64ToInt64(bucket.Count),
		)
		if err != nil {
			s.logger.Error("failed to insert metric histogram bucket", slog.String("metric", bucket.MetricName), slog.Any("error", err))
			continue
		}
	}
}

func marshalLabels(labels map[string]string) ([]byte, error) {
	return json.Marshal(normalizeLabels(labels))
}

func uint64ToInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value) //nolint:gosec
}

func nullableFloat(value *float64) any {
	if value == nil {
		return nil
	}
	return *value
}
