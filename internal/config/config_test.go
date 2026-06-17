package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const cursorEnv = "QUIVER_CURSOR_HMAC"

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	if err := cfg.Validate(envLookup(map[string]string{
		cursorEnv:                     "cursor-key",
		"QUIVER_DEMO_ADMIN_API_KEY":   "admin-key",
		"REST_INGEST_DEMO_CLIENT_KEY": "ingest-key",
	})); err != nil {
		t.Fatalf("valid config failed validation: %v", err)
	}
}

func TestConfigValidateFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*Config)
		expected string
	}{
		{
			name: "missing cursor secret env",
			mutate: func(c *Config) {
				c.API.Cursor.HMACSecretEnv = "MISSING_SECRET"
			},
			expected: "cursor secret env",
		},
		{
			name: "duplicate collector id",
			mutate: func(c *Config) {
				c.Collectors.ZeekConnJSON[0].CollectorID = c.Collectors.NetFlowV5[0].CollectorID
			},
			expected: "duplicate collector_id",
		},
		{
			name: "invalid server address",
			mutate: func(c *Config) {
				c.Server.HTTPAddr = "localhost"
			},
			expected: "server.http_addr",
		},
		{
			name: "invalid body size",
			mutate: func(c *Config) {
				c.API.MaxRequestBodyBytes = 0
			},
			expected: "max_request_body_bytes",
		},
		{
			name: "invalid query window",
			mutate: func(c *Config) {
				c.API.Query.MaxQueryWindow = 0
			},
			expected: "max_query_window",
		},
		{
			name: "invalid netflow source ip",
			mutate: func(c *Config) {
				c.Collectors.NetFlowV5[0].AllowedSources[0].SourceIP = "not-an-ip"
			},
			expected: "source_ip",
		},
		{
			name: "missing zeek state key",
			mutate: func(c *Config) {
				c.Collectors.ZeekConnJSON[0].StateKey = ""
			},
			expected: "state_key",
		},
		{
			name: "invalid rate limit",
			mutate: func(c *Config) {
				c.API.RateLimits.Query.RequestsPerMinute = 0
			},
			expected: "rate_limits.query",
		},
		{
			name: "invalid storage writer backoff",
			mutate: func(c *Config) {
				c.StorageWriter.InitialBackoff = Duration(10 * time.Second)
				c.StorageWriter.MaxBackoff = Duration(time.Second)
			},
			expected: "initial_backoff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validConfig()
			tt.mutate(&cfg)
			err := cfg.Validate(envLookup(map[string]string{
				cursorEnv:                     "cursor-key",
				"QUIVER_DEMO_ADMIN_API_KEY":   "admin-key",
				"REST_INGEST_DEMO_CLIENT_KEY": "ingest-key",
			}))
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.expected) {
				t.Fatalf("error %q does not contain %q", err, tt.expected)
			}
		})
	}
}

func TestLoadBytes(t *testing.T) {
	t.Parallel()

	cfg, err := LoadBytes([]byte(validYAML()), envLookup(map[string]string{
		"QUIVER_DATABASE_DSN":         "postgres://timescaledb:5432/quiver?sslmode=disable",
		cursorEnv:                     "cursor-key",
		"QUIVER_DEMO_ADMIN_API_KEY":   "admin-key",
		"REST_INGEST_DEMO_CLIENT_KEY": "ingest-key",
	}))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	if cfg.Database.DSN != "postgres://timescaledb:5432/quiver?sslmode=disable" {
		t.Fatalf("database dsn = %q", cfg.Database.DSN)
	}
	if cfg.Storage.Columnstore.After != Duration(24*time.Hour) {
		t.Fatalf("columnstore after = %s", cfg.Storage.Columnstore.After.Std())
	}
	if cfg.API.Query.MaxQueryWindow != Duration(24*time.Hour) {
		t.Fatalf("query window = %s", cfg.API.Query.MaxQueryWindow.Std())
	}
	if !cfg.Storage.Columnstore.Enabled {
		t.Fatal("columnstore should default to enabled")
	}
}

func TestLoadBytesRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	_, err := LoadBytes([]byte("unknown: true\n"), envLookup(map[string]string{}))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
	if !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("error %q does not describe unknown field", err)
	}
}

func TestLoadBytesMissingExpandedEnv(t *testing.T) {
	t.Parallel()

	_, err := LoadBytes([]byte(validYAML()), envLookup(map[string]string{
		cursorEnv:                     "cursor-key",
		"QUIVER_DEMO_ADMIN_API_KEY":   "admin-key",
		"REST_INGEST_DEMO_CLIENT_KEY": "ingest-key",
	}))
	if err == nil {
		t.Fatal("expected missing database dsn env error")
	}
	if !strings.Contains(err.Error(), "QUIVER_DATABASE_DSN") {
		t.Fatalf("error %q does not mention missing env var", err)
	}
}

func TestLoadFileHonorsContext(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(validYAML()), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := LoadFile(ctx, path, envLookup(map[string]string{}))
	if err == nil {
		t.Fatal("expected canceled context error")
	}
	if !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("error %q does not mention context cancellation", err)
	}
}

func TestExampleConfigLoads(t *testing.T) {
	t.Parallel()

	cursorSecretEnv := "QUIVER_API_CURSOR_" + "SECRET"
	cfg, err := LoadFile(context.Background(), "../../configs/quiver.example.yaml", envLookup(map[string]string{
		"QUIVER_DATABASE_DSN":         "postgres://timescaledb:5432/quiver?sslmode=disable",
		cursorSecretEnv:               fixtureValue("cursor"),
		"QUIVER_DEMO_ADMIN_API_KEY":   fixtureValue("admin"),
		"REST_INGEST_DEMO_CLIENT_KEY": fixtureValue("ingest"),
	}))
	if err != nil {
		t.Fatalf("example config failed to load: %v", err)
	}
	if cfg.RestIngest.CollectorID != "rest-ingest-main" {
		t.Fatalf("rest collector id = %q", cfg.RestIngest.CollectorID)
	}
}

func validConfig() Config {
	cfg := Default()
	cfg.Kafka.Brokers = []string{"kafka:9092"}
	cfg.Database.DSN = "postgres://timescaledb:5432/quiver?sslmode=disable"
	cfg.API.Cursor.HMACSecretEnv = cursorEnv
	cfg.API.Keys = []APIKeyConfig{
		{
			Name:   "demo-admin",
			KeyEnv: "QUIVER_DEMO_ADMIN_API_KEY",
			Scopes: []string{"ingest", "query", "metrics"},
		},
	}
	cfg.RestIngest.Enabled = true
	cfg.RestIngest.CollectorID = "rest-ingest-main"
	cfg.RestIngest.APIKeys = []RESTAPIKeyConfig{
		{
			Name:       "demo-client",
			SourceHost: "rest-demo-client",
			KeyEnv:     "REST_INGEST_DEMO_CLIENT_KEY",
		},
	}
	cfg.Collectors.NetFlowV5 = []NetFlowV5CollectorConfig{
		{
			Enabled:     true,
			CollectorID: "netflow-main",
			ListenAddr:  "0.0.0.0:2055",
			AllowedSources: []NetFlowAllowedSource{
				{
					SourceIP:     "10.10.0.1",
					SourceHost:   "router-core-01",
					SamplingRate: 1,
				},
			},
		},
	}
	cfg.Collectors.ZeekConnJSON = []ZeekCollectorConfig{
		{
			Enabled:       true,
			CollectorID:   "zeek-conn-01",
			SourceHost:    "zeek-probe-01",
			FilePath:      "/var/log/zeek/current/conn.log",
			PollInterval:  Duration(time.Second),
			StartPosition: "end",
			MaxLineBytes:  1048576,
			StateKey:      "zeek-conn-01",
		},
	}
	return cfg
}

func envLookup(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func fixtureValue(name string) string {
	return "fixture-" + name
}

func validYAML() string {
	return `
kafka:
  brokers:
    - kafka:9092
database:
  dsn: "${QUIVER_DATABASE_DSN}"
api:
  cursor:
    hmac_secret_env: QUIVER_CURSOR_HMAC
  keys:
    - name: demo-admin
      key_env: QUIVER_DEMO_ADMIN_API_KEY
      scopes: ["ingest", "query", "metrics"]
rest_ingest:
  enabled: true
  collector_id: rest-ingest-main
  api_keys:
    - name: demo-client
      source_host: rest-demo-client
      key_env: REST_INGEST_DEMO_CLIENT_KEY
collectors:
  netflow_v5:
    - enabled: true
      collector_id: netflow-main
      listen_addr: "0.0.0.0:2055"
      allowed_sources:
        - source_ip: "10.10.0.1"
          source_host: router-core-01
          sampling_rate: 1
  zeek_conn_json:
    - enabled: true
      collector_id: zeek-conn-01
      source_host: zeek-probe-01
      file_path: /var/log/zeek/current/conn.log
      poll_interval: "1s"
      start_position: end
      max_line_bytes: 1048576
      state_key: zeek-conn-01
`
}
