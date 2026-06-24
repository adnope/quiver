package observability

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"sync"
	"time"
)

type MetricsSaver struct {
	db       *sql.DB
	registry *Registry
	logger   *slog.Logger
	interval time.Duration
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func NewMetricsSaver(db *sql.DB, registry *Registry, logger *slog.Logger, interval time.Duration) *MetricsSaver {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &MetricsSaver{
		db:       db,
		registry: registry,
		logger:   logger,
		interval: interval,
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
	s.logger.Info("background metrics saver started", slog.Duration("interval", s.interval))

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

	snapshots := s.registry.Snapshot()
	if len(snapshots) == 0 {
		return
	}

	now := time.Now().UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.logger.Error("failed to begin transaction for metrics saving", slog.Any("error", err))
		return
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO quiver.system_metrics (timestamp, metric_name, labels, value) VALUES ($1, $2, $3, $4)`)
	if err != nil {
		s.logger.Error("failed to prepare statement for metrics saving", slog.Any("error", err))
		return
	}
	defer func() { _ = stmt.Close() }()

	for _, snap := range snapshots {
		labelsJSON, err := json.Marshal(snap.Labels)
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

	if err := tx.Commit(); err != nil {
		s.logger.Error("failed to commit metrics saving transaction", slog.Any("error", err))
	}
}
