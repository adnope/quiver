package collector

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/adnope/quiver/internal/config"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

type packetTestCollector struct {
	*testRuntimeCollector
	inputs []PacketInput
}

func (c *packetTestCollector) HandlePacket(_ context.Context, input PacketInput) (PacketResult, error) {
	c.inputs = append(c.inputs, input)
	return PacketResult{Status: PacketAccepted}, nil
}

func TestPacketRouterRoutesLegacyAndMixedVersions(t *testing.T) {
	t.Parallel()

	v5 := &packetTestCollector{testRuntimeCollector: &testRuntimeCollector{
		id:  "netflow-v5",
		typ: "netflow_v5",
	}}
	v9 := &packetTestCollector{testRuntimeCollector: &testRuntimeCollector{
		id:     "netflow-v9",
		typ:    "netflow_v9",
		source: flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9,
	}}
	manager := packetRouterTestManager(t, v5, v9)

	legacy, err := NewPacketRouter(manager, config.ProxyNetFlowConfig{CollectorID: "netflow-v5"})
	if err != nil {
		t.Fatalf("NewPacketRouter(legacy) error = %v", err)
	}
	result, err := legacy.HandlePacket(
		context.Background(),
		map[string]struct{}{"netflow-v5": {}},
		packetInputForVersion(5),
	)
	if err != nil || result.Status != PacketAccepted || len(v5.inputs) != 1 {
		t.Fatalf("legacy dispatch result=%+v err=%v inputs=%d", result, err, len(v5.inputs))
	}

	mixed, err := NewPacketRouter(manager, config.ProxyNetFlowConfig{Routes: []config.ProxyNetFlowRouteConfig{
		{Version: 5, CollectorID: "netflow-v5"},
		{Version: 9, CollectorID: "netflow-v9"},
	}})
	if err != nil {
		t.Fatalf("NewPacketRouter(mixed) error = %v", err)
	}
	allowed := map[string]struct{}{"netflow-v5": {}, "netflow-v9": {}}
	for _, version := range []uint16{9, 5} {
		result, err = mixed.HandlePacket(context.Background(), allowed, packetInputForVersion(version))
		if err != nil || result.Status != PacketAccepted {
			t.Fatalf("version %d result=%+v err=%v", version, result, err)
		}
	}
	if len(v5.inputs) != 2 || len(v9.inputs) != 1 {
		t.Fatalf("routed v5=%d v9=%d", len(v5.inputs), len(v9.inputs))
	}
}

func TestPacketRouterRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	v5 := &packetTestCollector{testRuntimeCollector: &testRuntimeCollector{id: "v5", typ: "netflow_v5"}}
	v9Mismatch := &packetTestCollector{testRuntimeCollector: &testRuntimeCollector{id: "v9-mismatch", typ: "netflow_v9"}}
	nonPacket := &testRuntimeCollector{id: "non-packet", typ: "test"}
	manager := packetRouterTestManager(t, v5, v9Mismatch, nonPacket)

	tests := []struct {
		name     string
		cfg      config.ProxyNetFlowConfig
		expected string
	}{
		{name: "no routes", cfg: config.ProxyNetFlowConfig{}, expected: "no routes"},
		{name: "duplicate version", cfg: config.ProxyNetFlowConfig{Routes: []config.ProxyNetFlowRouteConfig{{Version: 5, CollectorID: "v5"}, {Version: 5, CollectorID: "v5"}}}, expected: "duplicate"},
		{name: "unsupported version", cfg: config.ProxyNetFlowConfig{Routes: []config.ProxyNetFlowRouteConfig{{Version: 10, CollectorID: "v5"}}}, expected: "unsupported"},
		{name: "missing collector", cfg: config.ProxyNetFlowConfig{Routes: []config.ProxyNetFlowRouteConfig{{Version: 5, CollectorID: "missing"}}}, expected: "does not exist"},
		{name: "non packet collector", cfg: config.ProxyNetFlowConfig{Routes: []config.ProxyNetFlowRouteConfig{{Version: 5, CollectorID: "non-packet"}}}, expected: "not packet-capable"},
		{name: "source mismatch", cfg: config.ProxyNetFlowConfig{Routes: []config.ProxyNetFlowRouteConfig{{Version: 9, CollectorID: "v9-mismatch"}}}, expected: "does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewPacketRouter(manager, tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.expected) {
				t.Fatalf("NewPacketRouter() error = %v, want %q", err, tt.expected)
			}
		})
	}
}

func TestPacketRouterRejectsShortUnsupportedAndUnauthorizedPackets(t *testing.T) {
	t.Parallel()

	v5 := &packetTestCollector{testRuntimeCollector: &testRuntimeCollector{id: "v5", typ: "netflow_v5"}}
	manager := packetRouterTestManager(t, v5)
	router, err := NewPacketRouter(manager, config.ProxyNetFlowConfig{CollectorID: "v5"})
	if err != nil {
		t.Fatalf("NewPacketRouter() error = %v", err)
	}

	tests := []struct {
		name    string
		allowed map[string]struct{}
		input   PacketInput
		code    string
	}{
		{name: "short", allowed: map[string]struct{}{"v5": {}}, input: PacketInput{Data: []byte{5}}, code: "malformed_packet"},
		{name: "oversized", allowed: map[string]struct{}{"v5": {}}, input: PacketInput{Data: make([]byte, 65536)}, code: "packet_too_large"},
		{name: "unsupported", allowed: map[string]struct{}{"v5": {}}, input: packetInputForVersion(9), code: "unsupported_version"},
		{name: "unauthorized", allowed: map[string]struct{}{}, input: packetInputForVersion(5), code: "unauthorized_collector"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := router.HandlePacket(context.Background(), tt.allowed, tt.input)
			if err != nil || result.Status != PacketRejected || result.ErrorCode != tt.code {
				t.Fatalf("HandlePacket() result=%+v err=%v", result, err)
			}
		})
	}
}

func packetRouterTestManager(t *testing.T, runtimes ...RuntimeCollector) *Manager {
	t.Helper()

	registry := NewRegistry()
	instances := make([]config.CollectorInstanceConfig, 0, len(runtimes))
	for _, runtime := range runtimes {
		collectorRuntime := runtime
		pluginType := runtime.Type()
		if _, exists := registry.Lookup(pluginType); !exists {
			if err := registry.Register(testPlugin{
				pluginType: pluginType,
				build: func(_ BuildContext, cfg InstanceConfig) (RuntimeCollector, error) {
					for _, candidate := range runtimes {
						if candidate.ID() == cfg.CollectorID {
							return candidate, nil
						}
					}
					return collectorRuntime, nil
				},
			}); err != nil {
				t.Fatalf("Register() error = %v", err)
			}
		}
		instances = append(instances, config.CollectorInstanceConfig{
			Type:        pluginType,
			CollectorID: runtime.ID(),
			Enabled:     true,
		})
	}
	manager, err := NewManager(context.Background(), registry, config.CollectorsConfig{Instances: instances}, BuildContext{})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return manager
}

func packetInputForVersion(version uint16) PacketInput {
	data := make([]byte, 20)
	binary.BigEndian.PutUint16(data, version)
	return PacketInput{
		SourceIP:   netip.MustParseAddr("192.0.2.10"),
		SourceHost: "gateway-1",
		Data:       data,
	}
}
