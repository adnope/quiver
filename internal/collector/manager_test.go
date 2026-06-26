package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/observability"
)

func TestManagerBuildsEnabledCollectors(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	if err := registry.Register(testPlugin{pluginType: "test", mode: SettingsOptional}); err != nil {
		t.Fatalf("Register(): %v", err)
	}
	metrics := observability.NewRegistry()
	manager, err := NewManager(context.Background(), registry, config.CollectorsConfig{
		Restart: config.CollectorRestartConfig{Policy: "always", InitialBackoff: config.Duration(time.Millisecond), MaxBackoff: config.Duration(time.Millisecond)},
		Instances: []config.CollectorInstanceConfig{
			{Type: "test", CollectorID: "collector-a", Enabled: true},
			{Type: "test", CollectorID: "collector-disabled", Enabled: false},
		},
	}, BuildContext{Metrics: metrics})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	snapshots := manager.StatusSnapshots(context.Background())
	if len(snapshots) != 1 {
		t.Fatalf("snapshot count = %d, want 1", len(snapshots))
	}
	if snapshots[0].CollectorID != "collector-a" || snapshots[0].Status != StateOpened {
		t.Fatalf("snapshot = %+v", snapshots[0])
	}
	if manager.CollectorExists("collector-disabled") {
		t.Fatalf("disabled collector should not be built")
	}
	if !strings.Contains(string(metrics.WritePrometheus()), `collector_status{collector_id="collector-a",source_type="test",status="opened"} 1`) {
		t.Fatalf("collector status metric missing:\n%s", string(metrics.WritePrometheus()))
	}
}

func TestManagerRejectsUnknownPlugin(t *testing.T) {
	t.Parallel()

	_, err := NewManager(context.Background(), NewRegistry(), config.CollectorsConfig{
		Restart:   config.CollectorRestartConfig{Policy: "always"},
		Instances: []config.CollectorInstanceConfig{{Type: "missing", CollectorID: "collector-a", Enabled: true}},
	}, BuildContext{})
	if err == nil || !strings.Contains(err.Error(), "unknown collector type") {
		t.Fatalf("expected unknown plugin error, got %v", err)
	}
}

func TestManagerBuildFailureFailsStartup(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	if err := registry.Register(testPlugin{
		pluginType: "test",
		mode:       SettingsOptional,
		build: func(BuildContext, InstanceConfig) (RuntimeCollector, error) {
			return nil, errors.New("build exploded")
		},
	}); err != nil {
		t.Fatalf("Register(): %v", err)
	}
	_, err := NewManager(context.Background(), registry, config.CollectorsConfig{
		Restart:   config.CollectorRestartConfig{Policy: "always"},
		Instances: []config.CollectorInstanceConfig{{Type: "test", CollectorID: "collector-a", Enabled: true}},
	}, BuildContext{})
	if err == nil || !strings.Contains(err.Error(), "build collector") {
		t.Fatalf("expected build failure, got %v", err)
	}
}

func TestManagerOpenFailureFailsStartupAndClosesOpenedCollectors(t *testing.T) {
	t.Parallel()

	first := &testRuntimeCollector{id: "collector-a", typ: "test"}
	second := &testRuntimeCollector{id: "collector-b", typ: "test", openErr: errors.New("bind failed")}
	registry := NewRegistry()
	if err := registry.Register(testPlugin{
		pluginType: "test",
		mode:       SettingsOptional,
		build: func(_ BuildContext, cfg InstanceConfig) (RuntimeCollector, error) {
			if cfg.CollectorID == "collector-b" {
				return second, nil
			}
			return first, nil
		},
	}); err != nil {
		t.Fatalf("Register(): %v", err)
	}
	_, err := NewManager(context.Background(), registry, config.CollectorsConfig{
		Restart: config.CollectorRestartConfig{Policy: "always"},
		Instances: []config.CollectorInstanceConfig{
			{Type: "test", CollectorID: "collector-a", Enabled: true},
			{Type: "test", CollectorID: "collector-b", Enabled: true},
		},
	}, BuildContext{})
	if err == nil || !strings.Contains(err.Error(), "open collector") {
		t.Fatalf("expected open failure, got %v", err)
	}
	if first.closed == 0 {
		t.Fatalf("expected already opened collector to be closed after startup failure")
	}
	if second.closed == 0 {
		t.Fatalf("expected failed collector to receive cleanup close")
	}
}

func TestManagerStopsRunningCollectors(t *testing.T) {
	t.Parallel()

	runtime := &testRuntimeCollector{id: "collector-a", typ: "test", runCh: make(chan struct{})}
	registry := NewRegistry()
	if err := registry.Register(testPlugin{
		pluginType: "test",
		mode:       SettingsOptional,
		build: func(BuildContext, InstanceConfig) (RuntimeCollector, error) {
			return runtime, nil
		},
	}); err != nil {
		t.Fatalf("Register(): %v", err)
	}
	manager, err := NewManager(context.Background(), registry, config.CollectorsConfig{
		Restart:   config.CollectorRestartConfig{Policy: "always", InitialBackoff: config.Duration(time.Millisecond), MaxBackoff: config.Duration(time.Millisecond)},
		Instances: []config.CollectorInstanceConfig{{Type: "test", CollectorID: "collector-a", Enabled: true}},
	}, BuildContext{})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)
	cancel()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	manager.Stop(stopCtx)
	if got := manager.StatusSnapshots(context.Background())[0].Status; got != StateStopped {
		t.Fatalf("status = %s, want stopped", got)
	}
	if runtime.closed == 0 {
		t.Fatalf("expected collector Close to be called")
	}
}

func TestManagerRuntimeFailureWithNeverMarksFailed(t *testing.T) {
	t.Parallel()

	runtime := &testRuntimeCollector{id: "collector-a", typ: "test", runErr: errors.New("runtime failed")}
	manager := newTestManager(t, runtime, config.CollectorRestartConfig{
		Policy:         "never",
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
	})
	ctx := t.Context()
	manager.Start(ctx)

	snapshot := waitForStatus(t, manager, "collector-a", StateFailed)
	if snapshot.LastError == nil || !strings.Contains(*snapshot.LastError, "runtime failed") {
		t.Fatalf("expected sanitized runtime error, got %+v", snapshot)
	}
}

func TestManagerMaxRestartsExhaustionMarksFailed(t *testing.T) {
	t.Parallel()

	runtime := &testRuntimeCollector{id: "collector-a", typ: "test", runErr: errors.New("runtime failed")}
	manager := newTestManager(t, runtime, config.CollectorRestartConfig{
		Policy:         "always",
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
		MaxRestarts:    1,
		MaxRestartsSet: true,
	})
	ctx := t.Context()
	manager.Start(ctx)

	snapshot := waitForStatus(t, manager, "collector-a", StateFailed)
	if snapshot.RestartCount != 1 {
		t.Fatalf("restart count = %d, want 1", snapshot.RestartCount)
	}
	if runtime.runs < 2 {
		t.Fatalf("expected collector to run once after the restart attempt, runs = %d", runtime.runs)
	}
}

func TestManagerOpenFailureDuringRestartDoesNotRunBeforeOpenSucceeds(t *testing.T) {
	t.Parallel()

	opened := 0
	runtime := &testRuntimeCollector{
		id:     "collector-a",
		typ:    "test",
		runErr: errors.New("runtime failed"),
		open: func(context.Context) error {
			opened++
			if opened == 2 {
				return errors.New("restart bind failed")
			}
			return nil
		},
	}
	manager := newTestManager(t, runtime, config.CollectorRestartConfig{
		Policy:         "always",
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
		MaxRestarts:    2,
		MaxRestartsSet: true,
	})
	ctx := t.Context()
	manager.Start(ctx)

	snapshot := waitForStatus(t, manager, "collector-a", StateFailed)
	if snapshot.RestartCount != 2 {
		t.Fatalf("restart count = %d, want 2", snapshot.RestartCount)
	}
	if runtime.runs != 2 {
		t.Fatalf("Run calls = %d, want 2; manager should not call Run after failed Open", runtime.runs)
	}
}

func TestManagerStatusSnapshotsIncludeCollectorHealthDetails(t *testing.T) {
	t.Parallel()

	runtime := &testRuntimeCollector{
		id:  "collector-a",
		typ: "test",
		healthDetails: map[string]string{
			"listener": "  udp\nready  ",
			"empty":    " \t ",
		},
	}
	manager := newTestManager(t, runtime, config.CollectorRestartConfig{
		Policy:         "always",
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
	})

	snapshots := manager.StatusSnapshots(context.Background())
	if len(snapshots) != 1 {
		t.Fatalf("snapshot count = %d, want 1", len(snapshots))
	}
	if got := snapshots[0].Details["listener"]; got != "udp ready" {
		t.Fatalf("sanitized listener detail = %q", got)
	}
	if _, exists := snapshots[0].Details["empty"]; exists {
		t.Fatalf("empty detail should be omitted: %+v", snapshots[0].Details)
	}
}

func newTestManager(t *testing.T, runtime RuntimeCollector, restart config.CollectorRestartConfig) *Manager {
	t.Helper()

	registry := NewRegistry()
	if err := registry.Register(testPlugin{
		pluginType: "test",
		mode:       SettingsOptional,
		build: func(BuildContext, InstanceConfig) (RuntimeCollector, error) {
			return runtime, nil
		},
	}); err != nil {
		t.Fatalf("Register(): %v", err)
	}
	manager, err := NewManager(context.Background(), registry, config.CollectorsConfig{
		Restart:   restart,
		Instances: []config.CollectorInstanceConfig{{Type: "test", CollectorID: "collector-a", Enabled: true}},
	}, BuildContext{})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return manager
}

func waitForStatus(t *testing.T, manager *Manager, collectorID string, want State) StatusSnapshot {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, snapshot := range manager.StatusSnapshots(context.Background()) {
			if snapshot.CollectorID == collectorID && snapshot.Status == want {
				return snapshot
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("collector %q did not reach status %q; snapshots=%+v", collectorID, want, manager.StatusSnapshots(context.Background()))
	return StatusSnapshot{}
}
