package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/observability"
)

const defaultStableRuntime = time.Minute

var ErrManager = errors.New("collector manager")

type SourceTypeLabeler interface {
	SourceTypeLabel() string
}

type Manager struct {
	mu               sync.RWMutex
	collectors       map[string]*managedCollector
	packetCollectors map[string]PacketCollector
	metrics          *observability.Registry
	logger           *slog.Logger
	stableRuntime    time.Duration
	cancel           context.CancelFunc
	wg               sync.WaitGroup
}

type managedCollector struct {
	collector RuntimeCollector
	restart   resolvedRestartConfig
	status    StatusSnapshot
}

type resolvedRestartConfig struct {
	Policy         string
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	MaxRestarts    int
}

func NewManager(ctx context.Context, registry *Registry, cfg config.CollectorsConfig, buildCtx BuildContext) (*Manager, error) {
	if registry == nil {
		return nil, fmt.Errorf("%w: registry is nil", ErrManager)
	}
	if buildCtx.Logger == nil {
		buildCtx.Logger = slog.Default()
	}
	manager := &Manager{
		collectors:       map[string]*managedCollector{},
		packetCollectors: map[string]PacketCollector{},
		metrics:          buildCtx.Metrics,
		logger:           buildCtx.Logger,
		stableRuntime:    defaultStableRuntime,
	}

	failStartup := func(err error) (*Manager, error) {
		manager.closeOpened(ctx)
		return nil, err
	}

	globalRestart := resolveRestart(config.CollectorRestartConfig{}, cfg.Restart)
	seen := map[string]struct{}{}
	for _, instance := range cfg.Instances {
		if !instance.Enabled {
			continue
		}
		collectorID := strings.TrimSpace(instance.CollectorID)
		if collectorID == "" {
			return failStartup(fmt.Errorf("%w: collector_id is required", ErrManager))
		}
		if strings.TrimSpace(instance.Type) == "" {
			return failStartup(fmt.Errorf("%w: collector %q type is required", ErrManager, collectorID))
		}
		if _, exists := seen[collectorID]; exists {
			return failStartup(fmt.Errorf("%w: duplicate collector_id %q", ErrManager, collectorID))
		}
		seen[collectorID] = struct{}{}

		plugin, err := registry.MustLookup(instance.Type)
		if err != nil {
			return failStartup(err)
		}
		if err := ValidateSettingsMode(plugin.SettingsMode(), instance.Settings); err != nil {
			manager.recordStartFailure(collectorID, instance.Type, "settings")
			return failStartup(fmt.Errorf("%w: collector %q: %w", ErrManager, collectorID, err))
		}
		runtimeCollector, err := plugin.Build(buildCtx, InstanceConfig{
			Type:        strings.TrimSpace(instance.Type),
			CollectorID: collectorID,
			Settings:    instance.Settings,
		})
		if err != nil {
			manager.recordStartFailure(collectorID, instance.Type, "build")
			return failStartup(fmt.Errorf("%w: build collector %q: %w", ErrManager, collectorID, err))
		}
		if runtimeCollector == nil {
			manager.recordStartFailure(collectorID, instance.Type, "build")
			return failStartup(fmt.Errorf("%w: build collector %q returned nil", ErrManager, collectorID))
		}
		sourceType := sourceTypeLabel(runtimeCollector)
		if strings.TrimSpace(runtimeCollector.ID()) != collectorID {
			manager.recordStartFailure(collectorID, sourceType, "build")
			return failStartup(fmt.Errorf("%w: build collector %q returned runtime id %q", ErrManager, collectorID, runtimeCollector.ID()))
		}
		if strings.TrimSpace(runtimeCollector.Type()) != strings.TrimSpace(instance.Type) {
			manager.recordStartFailure(collectorID, sourceType, "build")
			return failStartup(fmt.Errorf("%w: build collector %q returned runtime type %q", ErrManager, collectorID, runtimeCollector.Type()))
		}
		if err := runtimeCollector.Open(ctx); err != nil {
			manager.recordStartFailure(collectorID, sourceType, "open")
			if closeErr := runtimeCollector.Close(ctx); closeErr != nil && manager.logger != nil {
				manager.logger.WarnContext(ctx, "collector close after startup open failure failed", slog.String("collector_id", collectorID), slog.Any("error", closeErr))
			}
			return failStartup(fmt.Errorf("%w: open collector %q: %w", ErrManager, collectorID, err))
		}

		restart := resolveRestart(globalRestart.toConfig(), instance.Restart)
		now := time.Now().UTC()
		mc := &managedCollector{
			collector: runtimeCollector,
			restart:   restart,
			status: StatusSnapshot{
				CollectorID:   runtimeCollector.ID(),
				Type:          runtimeCollector.Type(),
				SourceType:    sourceType,
				Status:        StateOpened,
				RestartPolicy: restart.Policy,
				LastStartedAt: &now,
			},
		}
		manager.collectors[runtimeCollector.ID()] = mc
		if packetCollector, ok := runtimeCollector.(PacketCollector); ok {
			manager.packetCollectors[runtimeCollector.ID()] = packetCollector
		}
		manager.setStatusLocked(mc, StateOpened, nil, now)
	}
	return manager, nil
}

func (r resolvedRestartConfig) toConfig() config.CollectorRestartConfig {
	return config.CollectorRestartConfig{
		Policy:         r.Policy,
		InitialBackoff: config.Duration(r.InitialBackoff),
		MaxBackoff:     config.Duration(r.MaxBackoff),
		MaxRestarts:    r.MaxRestarts,
		MaxRestartsSet: true,
	}
}

func resolveRestart(parent config.CollectorRestartConfig, override config.CollectorRestartConfig) resolvedRestartConfig {
	policy := strings.TrimSpace(parent.Policy)
	if policy == "" {
		policy = "always"
	}
	initialBackoff := parent.InitialBackoff.Std()
	if initialBackoff <= 0 {
		initialBackoff = time.Second
	}
	maxBackoff := parent.MaxBackoff.Std()
	if maxBackoff <= 0 {
		maxBackoff = 30 * time.Second
	}
	maxRestarts := parent.MaxRestarts

	if strings.TrimSpace(override.Policy) != "" {
		policy = strings.TrimSpace(override.Policy)
	}
	if override.InitialBackoff > 0 {
		initialBackoff = override.InitialBackoff.Std()
	}
	if override.MaxBackoff > 0 {
		maxBackoff = override.MaxBackoff.Std()
	}
	if override.MaxRestartsSet {
		maxRestarts = override.MaxRestarts
	}
	if initialBackoff > maxBackoff {
		initialBackoff = maxBackoff
	}
	return resolvedRestartConfig{Policy: policy, InitialBackoff: initialBackoff, MaxBackoff: maxBackoff, MaxRestarts: maxRestarts}
}

func (m *Manager) Start(ctx context.Context) {
	if m == nil {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.mu.Lock()
	if m.cancel != nil {
		m.mu.Unlock()
		cancel()
		return
	}
	m.cancel = cancel
	collectors := make([]*managedCollector, 0, len(m.collectors))
	for _, mc := range m.collectors {
		collectors = append(collectors, mc)
	}
	m.mu.Unlock()

	for _, mc := range collectors {
		m.wg.Add(1)
		go func(item *managedCollector) {
			defer m.wg.Done()
			m.runLoop(runCtx, item)
		}(mc)
	}
}

func (m *Manager) Stop(ctx context.Context) {
	if m == nil {
		return
	}
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	collectors := make([]RuntimeCollector, 0, len(m.collectors))
	for _, mc := range m.collectors {
		collectors = append(collectors, mc.collector)
	}
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, c := range collectors {
		if err := c.Close(ctx); err != nil && m.logger != nil {
			m.logger.WarnContext(ctx, "collector close failed", slog.String("collector_id", c.ID()), slog.Any("error", err))
		}
	}
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (m *Manager) runLoop(ctx context.Context, mc *managedCollector) {
	backoff := mc.restart.InitialBackoff
	consecutiveRestarts := 0
	for {
		if err := ctx.Err(); err != nil {
			m.markStopped(mc, nil)
			return
		}
		startedAt := time.Now().UTC()
		m.mu.Lock()
		m.setStatusLocked(mc, StateRunning, nil, startedAt)
		m.mu.Unlock()

		err := mc.collector.Run(ctx)
		stoppedAt := time.Now().UTC()
		if err == nil || errors.Is(err, context.Canceled) || ctx.Err() != nil {
			m.mu.Lock()
			m.setStatusLocked(mc, StateStopped, nil, stoppedAt)
			m.mu.Unlock()
			return
		}
		if time.Since(startedAt) >= m.stableRuntime {
			consecutiveRestarts = 0
			backoff = mc.restart.InitialBackoff
		}
		if closeErr := mc.collector.Close(ctx); closeErr != nil && m.logger != nil {
			m.logger.WarnContext(ctx, "collector close before restart failed", slog.String("collector_id", mc.collector.ID()), slog.Any("error", closeErr))
		}
		if mc.restart.Policy == "never" || restartLimitReached(mc.restart.MaxRestarts, consecutiveRestarts) {
			m.mu.Lock()
			m.setStatusLocked(mc, StateFailed, err, stoppedAt)
			m.mu.Unlock()
			return
		}

		for {
			consecutiveRestarts++
			m.incrementRestart(mc)
			m.mu.Lock()
			mc.status.RestartCount = consecutiveRestarts
			m.setStatusLocked(mc, StateRestarting, err, time.Now().UTC())
			m.mu.Unlock()

			if !sleepContext(ctx, backoff) {
				m.markStopped(mc, nil)
				return
			}
			if err := ctx.Err(); err != nil {
				m.markStopped(mc, nil)
				return
			}
			if openErr := mc.collector.Open(ctx); openErr != nil {
				m.recordStartFailure(mc.collector.ID(), sourceTypeLabel(mc.collector), "open")
				if closeErr := mc.collector.Close(ctx); closeErr != nil && m.logger != nil {
					m.logger.WarnContext(ctx, "collector close after restart open failure failed", slog.String("collector_id", mc.collector.ID()), slog.Any("error", closeErr))
				}
				err = openErr
				m.mu.Lock()
				m.setStatusLocked(mc, StateRestarting, openErr, time.Now().UTC())
				m.mu.Unlock()
				if restartLimitReached(mc.restart.MaxRestarts, consecutiveRestarts) {
					m.mu.Lock()
					m.setStatusLocked(mc, StateFailed, openErr, time.Now().UTC())
					m.mu.Unlock()
					return
				}
				backoff = nextBackoff(backoff, mc.restart.MaxBackoff)
				continue
			}
			backoff = nextBackoff(backoff, mc.restart.MaxBackoff)
			break
		}
	}
}

func restartLimitReached(maxRestarts int, consecutiveRestarts int) bool {
	return maxRestarts > 0 && consecutiveRestarts >= maxRestarts
}

func nextBackoff(current time.Duration, maxBackoff time.Duration) time.Duration {
	if current <= 0 {
		current = time.Second
	}
	next := current * 2
	if maxBackoff > 0 && next > maxBackoff {
		return maxBackoff
	}
	return next
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return true
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (m *Manager) markStopped(mc *managedCollector, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setStatusLocked(mc, StateStopped, err, time.Now().UTC())
}

func (m *Manager) setStatusLocked(mc *managedCollector, state State, err error, at time.Time) {
	mc.status.Status = state
	if state == StateRunning || state == StateOpened {
		mc.status.LastStartedAt = &at
	}
	if state == StateStopped || state == StateFailed || state == StateRestarting {
		mc.status.LastStoppedAt = &at
	}
	mc.status.LastError = SanitizeError(err)
	m.setStatusMetric(mc)
}

func (m *Manager) setStatusMetric(mc *managedCollector) {
	if m.metrics == nil {
		return
	}
	statuses := []State{StateOpened, StateRunning, StateRestarting, StateStopped, StateFailed}
	for _, state := range statuses {
		value := uint64(0)
		if mc.status.Status == state {
			value = 1
		}
		m.metrics.Set("collector_status", map[string]string{
			"collector_id": mc.status.CollectorID,
			"source_type":  mc.status.SourceType,
			"status":       string(state),
		}, value)
	}
}

func (m *Manager) incrementRestart(mc *managedCollector) {
	if m.metrics == nil {
		return
	}
	m.metrics.Inc("collector_restarts_total", map[string]string{
		"collector_id": mc.status.CollectorID,
		"source_type":  mc.status.SourceType,
	})
}

func (m *Manager) recordStartFailure(collectorID string, sourceType string, code string) {
	if m.metrics == nil {
		return
	}
	m.metrics.Inc("collector_start_failures_total", map[string]string{
		"collector_id": collectorID,
		"source_type":  sourceType,
		"error_code":   code,
	})
}

func (m *Manager) StatusSnapshots(ctx context.Context) []StatusSnapshot {
	if m == nil {
		return nil
	}

	type snapshotItem struct {
		collector RuntimeCollector
		snapshot  StatusSnapshot
	}

	m.mu.RLock()
	items := make([]snapshotItem, 0, len(m.collectors))
	for _, mc := range m.collectors {
		items = append(items, snapshotItem{collector: mc.collector, snapshot: mc.status})
	}
	m.mu.RUnlock()

	includeHealthDetails := ctx != nil && ctx.Err() == nil

	snapshots := make([]StatusSnapshot, 0, len(items))
	for _, item := range items {
		snapshot := item.snapshot
		if includeHealthDetails && item.collector != nil {
			snapshot.Details = SanitizeDetails(item.collector.Health(ctx).Details)
		}
		snapshots = append(snapshots, snapshot)
	}

	return snapshots
}

func (m *Manager) PacketCollector(id string) (PacketCollector, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	collector, ok := m.packetCollectors[strings.TrimSpace(id)]
	return collector, ok
}

func (m *Manager) CollectorExists(id string) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.collectors[strings.TrimSpace(id)]
	return ok
}

func (m *Manager) closeOpened(ctx context.Context) {
	for _, mc := range m.collectors {
		if err := mc.collector.Close(ctx); err != nil && m.logger != nil {
			m.logger.WarnContext(ctx, "collector close after startup failure failed", slog.String("collector_id", mc.collector.ID()), slog.Any("error", err))
		}
	}
}

func sourceTypeLabel(runtimeCollector RuntimeCollector) string {
	if runtimeCollector == nil {
		return "unknown"
	}
	if labeler, ok := runtimeCollector.(SourceTypeLabeler); ok {
		if label := strings.TrimSpace(labeler.SourceTypeLabel()); label != "" {
			return label
		}
	}
	if collectorType := strings.TrimSpace(runtimeCollector.Type()); collectorType != "" {
		return collectorType
	}
	return runtimeCollector.SourceType().String()
}
