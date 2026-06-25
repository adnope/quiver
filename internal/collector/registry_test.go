package collector

import (
	"context"
	"errors"
	"testing"

	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

type testPlugin struct {
	pluginType string
	mode       SettingsMode
	build      func(BuildContext, InstanceConfig) (RuntimeCollector, error)
}

func (p testPlugin) Type() string { return p.pluginType }

func (p testPlugin) SettingsMode() SettingsMode {
	if p.mode == "" {
		return SettingsOptional
	}
	return p.mode
}

func (p testPlugin) Build(ctx BuildContext, cfg InstanceConfig) (RuntimeCollector, error) {
	if p.build != nil {
		return p.build(ctx, cfg)
	}
	return &testRuntimeCollector{id: cfg.CollectorID, typ: cfg.Type}, nil
}

type testRuntimeCollector struct {
	id            string
	typ           string
	source        flowv1.SourceType
	openErr       error
	runErr        error
	closeErr      error
	runCh         chan struct{}
	healthDetails map[string]string
	open          func(context.Context) error
	run           func(context.Context) error
	close         func(context.Context) error
	opened        int
	closed        int
	runs          int
}

func (c *testRuntimeCollector) ID() string { return c.id }

func (c *testRuntimeCollector) Type() string {
	if c.typ == "" {
		return "test"
	}
	return c.typ
}

func (c *testRuntimeCollector) SourceType() flowv1.SourceType {
	if c.source == flowv1.SourceType_SOURCE_TYPE_UNSPECIFIED {
		return flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5
	}
	return c.source
}

func (c *testRuntimeCollector) Open(ctx context.Context) error {
	c.opened++
	if c.open != nil {
		return c.open(ctx)
	}
	return c.openErr
}

func (c *testRuntimeCollector) Run(ctx context.Context) error {
	c.runs++
	if c.run != nil {
		return c.run(ctx)
	}
	if c.runCh != nil {
		select {
		case <-c.runCh:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return c.runErr
}

func (c *testRuntimeCollector) Close(ctx context.Context) error {
	c.closed++
	if c.close != nil {
		return c.close(ctx)
	}
	return c.closeErr
}

func (c *testRuntimeCollector) Health(context.Context) CollectorHealth {
	return CollectorHealth{Details: c.healthDetails}
}

func TestRegistryRegisterLookup(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	plugin := testPlugin{pluginType: "test"}
	if err := registry.Register(plugin); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	got, ok := registry.Lookup(" test ")
	if !ok || got.Type() != "test" {
		t.Fatalf("Lookup() = %v, %v", got, ok)
	}
	if err := registry.Register(plugin); err == nil || !errors.Is(err, ErrRegistry) {
		t.Fatalf("expected duplicate ErrRegistry, got %v", err)
	}
	if _, err := registry.MustLookup("missing"); err == nil || !errors.Is(err, ErrRegistry) {
		t.Fatalf("expected missing ErrRegistry, got %v", err)
	}
}
