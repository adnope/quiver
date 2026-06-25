package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

const (
	flowAggregateStartupBackfillWindow = 7 * 24 * time.Hour
	flowAggregateRecentRefreshWindow   = 24 * time.Hour
	flowAggregateRecentRefreshInterval = time.Minute
	flowAggregateWeekRefreshInterval   = 5 * time.Minute

	flowAggregateRefreshLockKey int64 = 0x7175697665720001
)

var flowContinuousAggregateViews = [...]string{
	"quiver.flow_hourly_talkers",
	"quiver.flow_hourly_ports",
}

type FlowAggregateRefresher struct {
	db     *sql.DB
	logger *slog.Logger
	now    func() time.Time
}

func NewFlowAggregateRefresher(db *sql.DB, logger *slog.Logger) *FlowAggregateRefresher {
	if logger == nil {
		logger = slog.Default()
	}
	return &FlowAggregateRefresher{
		db:     db,
		logger: logger,
		now:    time.Now,
	}
}

func (r *FlowAggregateRefresher) Run(ctx context.Context) {
	if r == nil || r.db == nil {
		return
	}

	if err := r.refresh(ctx, flowAggregateStartupBackfillWindow, "startup_backfill"); err != nil {
		r.logger.WarnContext(ctx, "flow aggregate startup backfill failed", slog.Any("error", err))
	}

	recentTicker := time.NewTicker(flowAggregateRecentRefreshInterval)
	defer recentTicker.Stop()
	weekTicker := time.NewTicker(flowAggregateWeekRefreshInterval)
	defer weekTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-recentTicker.C:
			if err := r.refresh(ctx, flowAggregateRecentRefreshWindow, "recent_refresh"); err != nil {
				r.logger.WarnContext(ctx, "flow aggregate recent refresh failed", slog.Any("error", err))
			}
		case <-weekTicker.C:
			if err := r.refresh(ctx, flowAggregateStartupBackfillWindow, "week_refresh"); err != nil {
				r.logger.WarnContext(ctx, "flow aggregate weekly-window refresh failed", slog.Any("error", err))
			}
		}
	}
}

func (r *FlowAggregateRefresher) refresh(ctx context.Context, window time.Duration, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("open aggregate refresh connection: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	var locked bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", flowAggregateRefreshLockKey).Scan(&locked); err != nil {
		return fmt.Errorf("acquire aggregate refresh lock: %w", err)
	}
	if !locked {
		r.logger.DebugContext(ctx, "flow aggregate refresh skipped; another instance holds the lock", slog.String("reason", reason))
		return nil
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(unlockCtx, "SELECT pg_advisory_unlock($1)", flowAggregateRefreshLockKey)
	}()

	end := r.now().UTC()
	start := end.Add(-window)
	for _, view := range flowContinuousAggregateViews {
		query, err := refreshContinuousAggregateQuery(view)
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, query, start, end); err != nil {
			return fmt.Errorf("refresh %s: %w", view, err)
		}
	}
	r.logger.DebugContext(
		ctx,
		"flow continuous aggregates refreshed",
		slog.String("reason", reason),
		slog.Duration("window", window),
		slog.Time("from", start),
		slog.Time("to", end),
	)
	return nil
}

func refreshContinuousAggregateQuery(view string) (string, error) {
	switch view {
	case "quiver.flow_hourly_talkers", "quiver.flow_hourly_ports":
		return fmt.Sprintf("CALL refresh_continuous_aggregate('%s', $1::timestamptz, $2::timestamptz)", view), nil
	default:
		return "", fmt.Errorf("%w: unsupported continuous aggregate %q", ErrInvalidDatabaseConfig, view)
	}
}
