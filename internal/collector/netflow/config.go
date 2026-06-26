package netflow

import (
	"fmt"
	"net"
	"strings"

	"github.com/adnope/quiver/internal/collector"
)

type Config struct {
	ListenAddr        string `yaml:"listen_addr"`
	ReadBufferBytes   int    `yaml:"read_buffer_bytes"`
	PacketBufferBytes int    `yaml:"packet_buffer_bytes"`
	AuthRequired      bool   `yaml:"auth_required"`
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.ListenAddr) == "" {
		return fmt.Errorf("%w: listen_addr is required", ErrCollector)
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("%w: listen_addr must be host:port: %w", ErrCollector, err)
	}
	if c.ReadBufferBytes < 0 {
		return fmt.Errorf("%w: read_buffer_bytes must be non-negative", ErrCollector)
	}
	if c.PacketBufferBytes < 0 || c.PacketBufferBytes > 65535 {
		return fmt.Errorf("%w: packet_buffer_bytes must be within 0..65535", ErrCollector)
	}
	return nil
}

func decodeConfig(settings collector.InstanceConfig) (Config, error) {
	cfg := Config{AuthRequired: true}
	if err := collector.DecodeSettingsStrict(collector.SettingsRequired, settings.Settings, &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
