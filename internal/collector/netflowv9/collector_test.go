package netflowv9

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/adnope/quiver/internal/collector"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/observability"
)

type fakePublisher struct {
	mu          sync.Mutex
	raw         []*flowv1.RawFlowEventEnvelope
	deadLetters []*flowv1.DeadLetterEvent
	publishErr  error
}

func (p *fakePublisher) PublishRaw(_ context.Context, event *flowv1.RawFlowEventEnvelope) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.publishErr != nil {
		return p.publishErr
	}
	p.raw = append(p.raw, event)
	return nil
}

func (p *fakePublisher) PublishDeadLetter(_ context.Context, event *flowv1.DeadLetterEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deadLetters = append(p.deadLetters, event)
	return nil
}

func (p *fakePublisher) Flush(context.Context) error {
	return nil
}

var _ kafka.RawEventPublisher = (*fakePublisher)(nil)

func netflowV9SettingsNode(t *testing.T, content string) *yaml.Node {
	t.Helper()
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(content), &node); err != nil {
		t.Fatalf("yaml.Unmarshal(): %v", err)
	}
	if len(node.Content) == 0 {
		t.Fatalf("expected content node")
	}
	return node.Content[0]
}

const validSettingsYAML = `
template_ttl: "1h"
cleanup_interval: "1m"
exporter_idle_timeout: "24h"
sampling_rate: 1
max_packet_bytes: 65535
max_exporters: 4096
max_templates_per_exporter: 1024
max_templates_total: 65536
max_fields_per_template: 128
max_record_bytes: 65535
max_unknown_field_bytes: 4096
max_attributes_bytes: 65536
worker_count: 2
queue_capacity: 4096
max_queue_bytes: 33554432
pending:
  max_wait: "30s"
  max_bytes_per_exporter: 1048576
  max_bytes_total: 33554432
`

func TestPluginBuildsCollectorFromStrictSettings(t *testing.T) {
	t.Parallel()

	runtime, err := NewPlugin().Build(collector.BuildContext{Publisher: &fakePublisher{}}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "netflow-v9-main",
		Settings:    netflowV9SettingsNode(t, validSettingsYAML),
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if runtime.ID() != "netflow-v9-main" || runtime.Type() != PluginType || runtime.SourceType() != flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9 {
		t.Fatalf("runtime = id:%q type:%q source:%s", runtime.ID(), runtime.Type(), runtime.SourceType())
	}
}

func TestPluginRejectsMissingAndUnknownSettings(t *testing.T) {
	t.Parallel()

	_, err := NewPlugin().Build(collector.BuildContext{Publisher: &fakePublisher{}}, collector.InstanceConfig{Type: PluginType, CollectorID: "netflow-v9-main"})
	if err == nil || !strings.Contains(err.Error(), "settings are required") {
		t.Fatalf("expected missing settings error, got %v", err)
	}
	_, err = NewPlugin().Build(collector.BuildContext{Publisher: &fakePublisher{}}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "netflow-v9-main",
		Settings:    netflowV9SettingsNode(t, "template_ttl: 1h\nunknown: true\n"),
	})
	if err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("expected unknown settings error, got %v", err)
	}
}

func TestCollectorRejectsUnauthenticated(t *testing.T) {
	t.Parallel()

	publisher := &fakePublisher{}
	metrics := observability.NewRegistry()
	c, err := NewPlugin().Build(collector.BuildContext{Publisher: publisher, Metrics: metrics, Logger: slog.Default()}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "netflow-v9-test",
		Settings:    netflowV9SettingsNode(t, validSettingsYAML),
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	pktCollector := c.(collector.PacketCollector)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() { _ = pktCollector.Run(ctx) }()

	res, err := pktCollector.HandlePacket(ctx, collector.PacketInput{
		SourceIP:   netip.MustParseAddr("10.10.0.1"),
		SourceHost: "", // Unauthenticated
		Data:       make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("HandlePacket() error = %v", err)
	}
	if res.Status != collector.PacketRejected || res.ErrorCode != "auth_required" {
		t.Fatalf("HandlePacket() result = %+v", res)
	}
}

func TestCollectorRejectsMalformedAndTooLarge(t *testing.T) {
	t.Parallel()

	publisher := &fakePublisher{}
	metrics := observability.NewRegistry()
	c, err := NewPlugin().Build(collector.BuildContext{Publisher: publisher, Metrics: metrics, Logger: slog.Default()}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "netflow-v9-test",
		Settings:    netflowV9SettingsNode(t, validSettingsYAML),
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	pktCollector := c.(collector.PacketCollector)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() { _ = pktCollector.Run(ctx) }()

	res, err := pktCollector.HandlePacket(ctx, collector.PacketInput{
		SourceIP:   netip.MustParseAddr("10.10.0.1"),
		SourceHost: "auth-gateway",
		Data:       make([]byte, 10), // Too small for header
	})
	if err != nil || res.Status != collector.PacketRejected || res.ErrorCode != "malformed_packet" {
		t.Fatalf("HandlePacket(small) result = %+v, err = %v", res, err)
	}

	res, err = pktCollector.HandlePacket(ctx, collector.PacketInput{
		SourceIP:   netip.MustParseAddr("10.10.0.1"),
		SourceHost: "auth-gateway",
		Data:       make([]byte, 70000), // Too large
	})
	if err != nil || res.Status != collector.PacketRejected || res.ErrorCode != "packet_too_large" {
		t.Fatalf("HandlePacket(large) result = %+v, err = %v", res, err)
	}
}

func TestPluginMethods(t *testing.T) {
	t.Parallel()
	p := NewPlugin()
	if p.Type() != PluginType {
		t.Errorf("Type() = %q, want %q", p.Type(), PluginType)
	}
	if p.SettingsMode() != collector.SettingsRequired {
		t.Errorf("SettingsMode() = %v, want SettingsRequired", p.SettingsMode())
	}
	if p.SourceType() != flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9 {
		t.Errorf("SourceType() = %v, want NetFlow V9", p.SourceType())
	}
}

func TestCollectorDecodesAndPublishes(t *testing.T) {
	t.Parallel()

	publisher := &fakePublisher{}
	metrics := observability.NewRegistry()
	c, err := NewPlugin().Build(collector.BuildContext{Publisher: publisher, Metrics: metrics, Logger: slog.Default()}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "netflow-v9-test",
		Settings:    netflowV9SettingsNode(t, validSettingsYAML),
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	pktCollector := c.(collector.PacketCollector)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() { _ = pktCollector.Run(ctx) }()

	fields := []testField{
		{id: 8, length: 4},  // IPv4 source address
		{id: 12, length: 4}, // IPv4 dest address
		{id: 7, length: 2},  // source port
		{id: 11, length: 2}, // dest port
		{id: 4, length: 1},  // IP protocol
		{id: 1, length: 8},  // bytes
		{id: 2, length: 8},  // packets
	}
	record := bytes.Join([][]byte{
		{192, 0, 2, 10},
		{192, 0, 2, 20},
		uintBytes(12345, 2),
		uintBytes(80, 2),
		{6}, // TCP
		uintBytes(1000, 8),
		uintBytes(10, 8),
	}, nil)
	packet := packetBytes(
		2,
		1000,
		100,
		10,
		7,
		templateFlowSet(256, fields),
		dataFlowSet(256, record, 0, false),
	)

	res, err := pktCollector.HandlePacket(ctx, collector.PacketInput{
		SourceIP:   netip.MustParseAddr("10.10.0.1"),
		SourceHost: "auth-gateway",
		Data:       packet,
	})
	if err != nil || res.Status != collector.PacketAccepted {
		t.Fatalf("HandlePacket(valid) result = %+v, err = %v", res, err)
	}

	// Verify that the publisher received the raw event
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if len(publisher.raw) != 1 {
		t.Fatalf("expected 1 raw flow event published, got %d", len(publisher.raw))
	}
}
