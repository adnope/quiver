package zeekconntcp

import (
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	quiverauth "github.com/adnope/quiver/internal/auth"
	"github.com/adnope/quiver/internal/collector"
	"github.com/adnope/quiver/internal/config"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

func TestPluginBuildsCollectorFromStrictSettings(t *testing.T) {
	t.Parallel()

	runtime, err := NewPlugin().Build(collector.BuildContext{
		Publisher: newTCPTestPublisher(),
		Services: collector.Services{
			APIKeyAuthenticator: testAuthenticator(t),
		},
	}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "zeek-conn-tcp-main",
		Settings:    settingsNode(t, "listen_addr: 127.0.0.1:0\nmax_connections: 2\nbatch_size: 1\n"),
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if runtime.ID() != "zeek-conn-tcp-main" || runtime.Type() != PluginType {
		t.Fatalf("runtime = id:%q type:%q", runtime.ID(), runtime.Type())
	}
}

func TestPluginRejectsMissingAuthenticatorAndUnknownSettings(t *testing.T) {
	t.Parallel()

	_, err := NewPlugin().Build(collector.BuildContext{Publisher: newTCPTestPublisher()}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "zeek-conn-tcp-main",
		Settings:    settingsNode(t, "listen_addr: 127.0.0.1:0\n"),
	})
	if err == nil || !strings.Contains(err.Error(), "authenticator is nil") {
		t.Fatalf("expected authenticator error, got %v", err)
	}

	_, err = NewPlugin().Build(collector.BuildContext{
		Publisher: newTCPTestPublisher(),
		Services: collector.Services{
			APIKeyAuthenticator: testAuthenticator(t),
		},
	}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "zeek-conn-tcp-main",
		Settings:    settingsNode(t, "listen_addr: 127.0.0.1:0\nunknown: true\n"),
	})
	if err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("expected unknown settings error, got %v", err)
	}
}

func settingsNode(t *testing.T, content string) *yaml.Node {
	t.Helper()

	var node yaml.Node
	if err := yaml.Unmarshal([]byte(content), &node); err != nil {
		t.Fatalf("yaml.Unmarshal(): %v", err)
	}
	if len(node.Content) == 0 {
		t.Fatal("expected content node")
	}
	return node.Content[0]
}

func testAuthenticator(t *testing.T) *quiverauth.Authenticator {
	t.Helper()

	cfg := config.Default()
	cfg.API.Keys = []config.APIKeyConfig{{
		Name:   "query",
		KeyEnv: "QUERY_KEY",
		Scopes: []string{"query"},
	}}
	cfg.QuiverClientGateways = []config.QuiverClientGatewayConfig{{
		Name:       "zeek-shipper",
		SourceHost: "zeek-probe-01",
		KeyEnv:     "ZEEK_KEY",
	}}
	authenticator, err := quiverauth.NewAuthenticator(cfg, func(key string) string {
		switch key {
		case "QUERY_KEY":
			return "query-key"
		case "ZEEK_KEY":
			return "zeek-key"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("NewAuthenticator() error = %v", err)
	}
	return authenticator
}

func TestPluginOpenHonorsContext(t *testing.T) {
	t.Parallel()

	runtime, err := NewPlugin().Build(collector.BuildContext{
		Publisher: newTCPTestPublisher(),
		Services: collector.Services{
			APIKeyAuthenticator: testAuthenticator(t),
		},
	}, collector.InstanceConfig{
		Type:        PluginType,
		CollectorID: "zeek-conn-tcp-main",
		Settings:    settingsNode(t, "listen_addr: 127.0.0.1:0\n"),
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

func TestPluginMethods(t *testing.T) {
	t.Parallel()
	p := NewPlugin()
	if p.Type() != PluginType {
		t.Errorf("Type() = %q, want %q", p.Type(), PluginType)
	}
	if p.SettingsMode() != collector.SettingsRequired {
		t.Errorf("SettingsMode() = %v, want SettingsRequired", p.SettingsMode())
	}
	if p.SourceType() != flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON {
		t.Errorf("SourceType() = %v, want ZEEK_CONN_JSON", p.SourceType())
	}
}
