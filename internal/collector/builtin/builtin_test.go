package builtin

import (
	"testing"
)

func TestNewRegistry(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if registry == nil {
		t.Fatal("expected registry to not be nil")
	}

	// Verify expected plugins are registered
	expectedPlugins := []string{"netflow_v5", "netflow_v9", "zeek_conn_tcp"}
	for _, p := range expectedPlugins {
		_, ok := registry.Lookup(p)
		if !ok {
			t.Errorf("expected plugin %q to be registered", p)
		}
	}
}
