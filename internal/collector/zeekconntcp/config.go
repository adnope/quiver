package zeekconntcp

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/adnope/quiver/internal/collector"
	"github.com/adnope/quiver/internal/config"
)

const (
	defaultAuthTimeout   = 5 * time.Second
	defaultIdleTimeout   = 60 * time.Second
	defaultMaxLineBytes  = 1 << 20
	defaultBatchSize     = 100
	defaultFlushInterval = time.Second
	defaultMaxConns      = 32
)

type settings struct {
	ListenAddr       string            `yaml:"listen_addr"`
	TLS              tlsSettings       `yaml:"tls"`
	MaxConnections   int               `yaml:"max_connections"`
	AuthTimeout      config.Duration   `yaml:"auth_timeout"`
	IdleTimeout      config.Duration   `yaml:"idle_timeout"`
	MaxLineBytes     int               `yaml:"max_line_bytes"`
	BatchSize        int               `yaml:"batch_size"`
	FlushInterval    config.Duration   `yaml:"flush_interval"`
	TrustPeerIP      bool              `yaml:"trust_peer_ip"`
	AllowedPeerCIDRs []string          `yaml:"allowed_peer_cidrs"`
	RateLimit        rateLimitSettings `yaml:"rate_limit"`
}

type tlsSettings struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type rateLimitSettings struct {
	Enabled       bool   `yaml:"enabled"`
	RecordsPerSec int    `yaml:"records_per_second"`
	Burst         int    `yaml:"burst"`
	Mode          string `yaml:"mode"`
}

func decodeSettings(node collector.InstanceConfig) (settings, []netip.Prefix, error) {
	cfg := settings{
		MaxConnections: defaultMaxConns,
		AuthTimeout:    config.Duration(defaultAuthTimeout),
		IdleTimeout:    config.Duration(defaultIdleTimeout),
		MaxLineBytes:   defaultMaxLineBytes,
		BatchSize:      defaultBatchSize,
		FlushInterval:  config.Duration(defaultFlushInterval),
	}
	if err := collector.DecodeSettingsStrict(collector.SettingsRequired, node.Settings, &cfg); err != nil {
		return settings{}, nil, err
	}
	if strings.TrimSpace(cfg.ListenAddr) == "" {
		return settings{}, nil, fmt.Errorf("zeek_conn_tcp: listen_addr is required")
	}
	if _, _, err := net.SplitHostPort(cfg.ListenAddr); err != nil {
		return settings{}, nil, fmt.Errorf("zeek_conn_tcp: listen_addr must be host:port: %w", err)
	}
	if cfg.TLS.Enabled && (strings.TrimSpace(cfg.TLS.CertFile) == "" || strings.TrimSpace(cfg.TLS.KeyFile) == "") {
		return settings{}, nil, fmt.Errorf("zeek_conn_tcp: tls cert_file and key_file are required when tls is enabled")
	}
	if cfg.MaxConnections <= 0 {
		return settings{}, nil, fmt.Errorf("zeek_conn_tcp: max_connections must be positive")
	}
	if cfg.AuthTimeout <= 0 || cfg.IdleTimeout <= 0 || cfg.FlushInterval <= 0 {
		return settings{}, nil, fmt.Errorf("zeek_conn_tcp: timeouts and flush_interval must be positive")
	}
	if cfg.MaxLineBytes <= 0 || cfg.MaxLineBytes > 16<<20 {
		return settings{}, nil, fmt.Errorf("zeek_conn_tcp: max_line_bytes must be within 1..16777216")
	}
	if cfg.BatchSize <= 0 || cfg.BatchSize > 10000 {
		return settings{}, nil, fmt.Errorf("zeek_conn_tcp: batch_size must be within 1..10000")
	}
	if cfg.RateLimit.Enabled {
		if cfg.RateLimit.RecordsPerSec <= 0 || cfg.RateLimit.Burst <= 0 {
			return settings{}, nil, fmt.Errorf("zeek_conn_tcp: rate_limit records_per_second and burst must be positive")
		}
		mode := strings.TrimSpace(cfg.RateLimit.Mode)
		if mode == "" {
			cfg.RateLimit.Mode = "backpressure"
		} else if mode != "backpressure" && mode != "drop" {
			return settings{}, nil, fmt.Errorf("zeek_conn_tcp: rate_limit.mode must be backpressure or drop")
		}
	}
	prefixes := make([]netip.Prefix, 0, len(cfg.AllowedPeerCIDRs))
	for _, raw := range cfg.AllowedPeerCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return settings{}, nil, fmt.Errorf("zeek_conn_tcp: parse allowed_peer_cidrs %q: %w", raw, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return cfg, prefixes, nil
}
