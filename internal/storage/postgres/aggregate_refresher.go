package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

const (
	flowAggregateFiveMinuteRefreshWindow   = 24 * time.Hour
	flowAggregateHourlyRefreshWindow       = 7 * 24 * time.Hour
	flowAggregateFiveMinuteRefreshInterval = time.Minute
	flowAggregateHourlyRefreshInterval     = 5 * time.Minute

	flowAggregateRefreshLockKey int64 = 0x7175697665720001
)

var flowFiveMinuteContinuousAggregateViews = [...]string{
	"quiver.flow_5m_talkers",
	"quiver.flow_5m_ports",
}

var flowHourlyContinuousAggregateViews = [...]string{
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

	if err := r.refresh(ctx, flowFiveMinuteContinuousAggregateViews[:], flowAggregateFiveMinuteRefreshWindow, "startup_5m_backfill"); err != nil {
		r.logger.WarnContext(ctx, "flow aggregate 5-minute startup backfill failed", slog.Any("error", err))
	}
	if err := r.refresh(ctx, flowHourlyContinuousAggregateViews[:], flowAggregateHourlyRefreshWindow, "startup_hourly_backfill"); err != nil {
		r.logger.WarnContext(ctx, "flow aggregate hourly startup backfill failed", slog.Any("error", err))
	}

	fiveMinuteTicker := time.NewTicker(flowAggregateFiveMinuteRefreshInterval)
	defer fiveMinuteTicker.Stop()
	hourlyTicker := time.NewTicker(flowAggregateHourlyRefreshInterval)
	defer hourlyTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-fiveMinuteTicker.C:
			if err := r.refresh(ctx, flowFiveMinuteContinuousAggregateViews[:], flowAggregateFiveMinuteRefreshWindow, "5m_refresh"); err != nil {
				r.logger.WarnContext(ctx, "flow aggregate 5-minute refresh failed", slog.Any("error", err))
			}
		case <-hourlyTicker.C:
			if err := r.refresh(ctx, flowHourlyContinuousAggregateViews[:], flowAggregateHourlyRefreshWindow, "hourly_refresh"); err != nil {
				r.logger.WarnContext(ctx, "flow aggregate hourly refresh failed", slog.Any("error", err))
			}
		}
	}
}

func (r *FlowAggregateRefresher) refresh(ctx context.Context, views []string, window time.Duration, reason string) error {
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
	for _, view := range views {
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
		slog.Int("view_count", len(views)),
		slog.Time("from", start),
		slog.Time("to", end),
	)
	return nil
}

func refreshContinuousAggregateQuery(view string) (string, error) {
	switch view {
	case "quiver.flow_5m_talkers",
		"quiver.flow_5m_ports",
		"quiver.flow_hourly_talkers",
		"quiver.flow_hourly_ports":
		return fmt.Sprintf("CALL refresh_continuous_aggregate('%s', $1::timestamptz, $2::timestamptz)", view), nil
	default:
		return "", fmt.Errorf("%w: unsupported continuous aggregate %q", ErrInvalidDatabaseConfig, view)
	}
}
