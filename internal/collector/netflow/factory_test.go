package netflow

import (
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/adnope/quiver/internal/collector"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

func TestPluginBuildsCollectorFromStrictSettings(t *testing.T) {
	t.Parallel()

	runtime, err := NewPlugin().Build(collector.BuildContext{Publisher: &fakePublisher{}}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "netflow-main",
		Settings:    netflowSettingsNode(t, "listen_addr: 127.0.0.1:0\nread_buffer_bytes: 4096\npacket_buffer_bytes: 1500\nauth_required: false\n"),
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if runtime.ID() != "netflow-main" || runtime.Type() != PluginType || runtime.SourceType() != flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5 {
		t.Fatalf("runtime = id:%q type:%q source:%s", runtime.ID(), runtime.Type(), runtime.SourceType())
	}
}

func TestPluginRejectsMissingAndUnknownSettings(t *testing.T) {
	t.Parallel()

	_, err := NewPlugin().Build(collector.BuildContext{Publisher: &fakePublisher{}}, collector.InstanceConfig{Type: PluginType, CollectorID: "netflow-main"})
	if err == nil || !strings.Contains(err.Error(), "settings are required") {
		t.Fatalf("expected missing settings error, got %v", err)
	}
	_, err = NewPlugin().Build(collector.BuildContext{Publisher: &fakePublisher{}}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "netflow-main",
		Settings:    netflowSettingsNode(t, "listen_addr: 127.0.0.1:0\nunknown: true\n"),
	})
	if err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("expected unknown settings error, got %v", err)
	}
}

func TestPluginRejectsInvalidListenAddr(t *testing.T) {
	t.Parallel()

	_, err := NewPlugin().Build(collector.BuildContext{Publisher: &fakePublisher{}}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "netflow-main",
		Settings:    netflowSettingsNode(t, "listen_addr: localhost\n"),
	})
	if err == nil || !strings.Contains(err.Error(), "listen_addr must be host:port") {
		t.Fatalf("expected listen_addr error, got %v", err)
	}
}

func netflowSettingsNode(t *testing.T, content string) *yaml.Node {
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

func TestCollectorOpenHonorsContext(t *testing.T) {
	t.Parallel()

	runtime, err := NewPlugin().Build(collector.BuildContext{Publisher: &fakePublisher{}}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "netflow-main",
		Settings:    netflowSettingsNode(t, "listen_addr: 127.0.0.1:0\n"),
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Open(ctx); err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}
