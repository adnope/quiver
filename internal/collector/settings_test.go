package collector

import (
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type sampleSettings struct {
	ListenAddr string `yaml:"listen_addr"`
}

func TestValidateSettingsMode(t *testing.T) {
	t.Parallel()

	settings := yamlNode(t, "listen_addr: ':2055'\n")
	if err := ValidateSettingsMode(NoSettings, settings); err == nil || !errors.Is(err, ErrSettings) {
		t.Fatalf("expected NoSettings error, got %v", err)
	}
	if err := ValidateSettingsMode(SettingsRequired, nil); err == nil || !errors.Is(err, ErrSettings) {
		t.Fatalf("expected required settings error, got %v", err)
	}
	if err := ValidateSettingsMode(SettingsOptional, nil); err != nil {
		t.Fatalf("optional nil settings error = %v", err)
	}
}

func TestDecodeSettingsStrict(t *testing.T) {
	t.Parallel()

	var cfg sampleSettings
	if err := DecodeSettingsStrict(SettingsRequired, yamlNode(t, "listen_addr: ':2055'\n"), &cfg); err != nil {
		t.Fatalf("DecodeSettingsStrict() error = %v", err)
	}
	if cfg.ListenAddr != ":2055" {
		t.Fatalf("listen_addr = %q", cfg.ListenAddr)
	}
	if err := DecodeSettingsStrict(SettingsRequired, yamlNode(t, "unknown: true\n"), &cfg); err == nil || !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func yamlNode(t *testing.T, content string) *yaml.Node {
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
