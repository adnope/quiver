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
		"NETFLOW_GATEWAY_DEMO_KEY":    "netflow-key",
		"ZEEK_SHIPPER_DEMO_KEY":       "zeek-key",
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
				c.ZeekIngest.CollectorID = c.Collectors.Instances[0].CollectorID
			},
			expected: "duplicate collector_id",
		},
		{
			name: "duplicate rest ingest collector id",
			mutate: func(c *Config) {
				c.RestIngest.CollectorID = c.Collectors.Instances[0].CollectorID
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
			name: "invalid metrics save interval",
			mutate: func(c *Config) {
				c.Observability.MetricsSaveInterval = 0
			},
			expected: "observability.metrics_save_interval",
		},
		{
			name: "invalid metrics aggregate bucket width",
			mutate: func(c *Config) {
				c.Observability.MetricsAggregateBucketWidth = 0
			},
			expected: "observability.metrics_aggregate_bucket_width",
		},

		{
			name: "subsecond metrics aggregate bucket width",
			mutate: func(c *Config) {
				c.Observability.MetricsAggregateBucketWidth = Duration(500 * time.Millisecond)
			},
			expected: "observability.metrics_aggregate_bucket_width",
		},
		{
			name: "invalid metrics aggregate max points",
			mutate: func(c *Config) {
				c.Observability.MetricsAggregateMaxPoints = 0
			},
			expected: "observability.metrics_aggregate_max_points",
		},

		{
			name: "invalid zeek ingest batch size",
			mutate: func(c *Config) {
				c.ZeekIngest.MaxBatchSize = 0
			},
			expected: "zeek_ingest.max_batch_size",
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
				"NETFLOW_GATEWAY_DEMO_KEY":    "netflow-key",
				"ZEEK_SHIPPER_DEMO_KEY":       "zeek-key",
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
		"NETFLOW_GATEWAY_DEMO_KEY":    "netflow-key",
		"ZEEK_SHIPPER_DEMO_KEY":       "zeek-key",
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
	if cfg.API.Query.MaxQueryWindow != Duration(7*dayDuration) {
		t.Fatalf("query window = %s", cfg.API.Query.MaxQueryWindow.Std())
	}
	if !cfg.Storage.Columnstore.Enabled {
		t.Fatal("columnstore should default to enabled")
	}
	if cfg.Observability.MetricsSaveInterval != Duration(5*time.Second) {
		t.Fatalf("metrics save interval = %s", cfg.Observability.MetricsSaveInterval.Std())
	}
	if cfg.Observability.MetricsAggregateBucketWidth != Duration(5*time.Second) {
		t.Fatalf("metrics aggregate bucket width = %s", cfg.Observability.MetricsAggregateBucketWidth.Std())
	}
	if cfg.Observability.MetricsAggregateMaxPoints != 1000 {
		t.Fatalf("metrics aggregate max points = %d", cfg.Observability.MetricsAggregateMaxPoints)
	}
}

func TestCollectorInstanceDefaultEnabled(t *testing.T) {
	t.Parallel()

	yamlContent := strings.ReplaceAll(validYAML(), "      enabled: true\n", "")
	cfg, err := LoadBytes([]byte(yamlContent), envLookup(map[string]string{
		"QUIVER_DATABASE_DSN":         "postgres://timescaledb:5432/quiver?sslmode=disable",
		cursorEnv:                     "cursor-key",
		"QUIVER_DEMO_ADMIN_API_KEY":   "admin-key",
		"REST_INGEST_DEMO_CLIENT_KEY": "ingest-key",
		"NETFLOW_GATEWAY_DEMO_KEY":    "netflow-key",
		"ZEEK_SHIPPER_DEMO_KEY":       "zeek-key",
	}))
	if err != nil {
		t.Fatalf("LoadBytes() error = %v", err)
	}

	if len(cfg.Collectors.Instances) != 1 {
		t.Fatalf("expected 1 collector instance, got %d", len(cfg.Collectors.Instances))
	}

	instance := cfg.Collectors.Instances[0]
	if !instance.Enabled {
		t.Fatal("expected collector instance enabled to default to true")
	}
	if instance.Settings == nil {
		t.Fatal("expected collector instance settings to be preserved")
	}
	var settings struct {
		ListenAddr   string `yaml:"listen_addr"`
		AuthRequired bool   `yaml:"auth_required"`
	}
	if err := instance.Settings.Decode(&settings); err != nil {
		t.Fatalf("decode collector settings: %v", err)
	}
	if settings.ListenAddr != "0.0.0.0:2055" {
		t.Fatalf("listen_addr setting = %q", settings.ListenAddr)
	}
	if settings.AuthRequired {
		t.Fatal("expected auth_required setting to be false")
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

func TestLoadBytesRejectsUnknownRestartFields(t *testing.T) {
	t.Parallel()

	yamlContent := strings.Replace(validYAML(), "    max_restarts: 0\n", "    max_restarts: 0\n    typo_field: true\n", 1)
	_, err := LoadBytes([]byte(yamlContent), envLookup(map[string]string{
		"QUIVER_DATABASE_DSN":         "postgres://timescaledb:5432/quiver?sslmode=disable",
		cursorEnv:                     "cursor-key",
		"QUIVER_DEMO_ADMIN_API_KEY":   "admin-key",
		"REST_INGEST_DEMO_CLIENT_KEY": "ingest-key",
		"NETFLOW_GATEWAY_DEMO_KEY":    "netflow-key",
		"ZEEK_SHIPPER_DEMO_KEY":       "zeek-key",
	}))
	if err == nil {
		t.Fatal("expected unknown restart field error")
	}
	if !strings.Contains(err.Error(), "field typo_field not found") {
		t.Fatalf("error %q does not describe unknown restart field", err)
	}
}

func TestLoadBytesRejectsUnknownInstanceRestartFields(t *testing.T) {
	t.Parallel()

	yamlContent := strings.Replace(validYAML(), "      settings:\n", "      restart:\n        policy: always\n        typo_field: true\n      settings:\n", 1)
	_, err := LoadBytes([]byte(yamlContent), envLookup(map[string]string{
		"QUIVER_DATABASE_DSN":         "postgres://timescaledb:5432/quiver?sslmode=disable",
		cursorEnv:                     "cursor-key",
		"QUIVER_DEMO_ADMIN_API_KEY":   "admin-key",
		"REST_INGEST_DEMO_CLIENT_KEY": "ingest-key",
		"NETFLOW_GATEWAY_DEMO_KEY":    "netflow-key",
		"ZEEK_SHIPPER_DEMO_KEY":       "zeek-key",
	}))
	if err == nil {
		t.Fatal("expected unknown instance restart field error")
	}
	if !strings.Contains(err.Error(), "field typo_field not found") {
		t.Fatalf("error %q does not describe unknown instance restart field", err)
	}
}

func TestLoadBytesRejectsLegacyNetFlowCollectorShape(t *testing.T) {
	t.Parallel()

	yamlContent := strings.Replace(validYAML(), `collectors:
  restart:
    policy: always
    initial_backoff: "1s"
    max_backoff: "30s"
    max_restarts: 0
  instances:
    - type: netflow_v5
      collector_id: netflow-main
      enabled: true
      settings:
        listen_addr: "0.0.0.0:2055"
        auth_required: false`, `collectors:
  netflow_v5:
    - enabled: true
      collector_id: netflow-main
      listen_addr: "0.0.0.0:2055"
      auth_required: false`, 1)
	_, err := LoadBytes([]byte(yamlContent), envLookup(map[string]string{
		"QUIVER_DATABASE_DSN":         "postgres://timescaledb:5432/quiver?sslmode=disable",
		cursorEnv:                     "cursor-key",
		"QUIVER_DEMO_ADMIN_API_KEY":   "admin-key",
		"REST_INGEST_DEMO_CLIENT_KEY": "ingest-key",
		"NETFLOW_GATEWAY_DEMO_KEY":    "netflow-key",
		"ZEEK_SHIPPER_DEMO_KEY":       "zeek-key",
	}))
	if err == nil {
		t.Fatal("expected legacy collectors.netflow_v5 shape to fail")
	}
	if !strings.Contains(err.Error(), "field netflow_v5 not found") {
		t.Fatalf("error %q does not describe legacy field", err)
	}
}

func TestValidateSkipsDisabledCollectorInstances(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Collectors.Instances = append(cfg.Collectors.Instances, CollectorInstanceConfig{Enabled: false})
	if err := cfg.Validate(envLookup(map[string]string{
		cursorEnv:                     "cursor-key",
		"QUIVER_DEMO_ADMIN_API_KEY":   "admin-key",
		"REST_INGEST_DEMO_CLIENT_KEY": "ingest-key",
		"NETFLOW_GATEWAY_DEMO_KEY":    "netflow-key",
		"ZEEK_SHIPPER_DEMO_KEY":       "zeek-key",
	})); err != nil {
		t.Fatalf("Validate() error = %v", err)
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
		"NETFLOW_GATEWAY_DEMO_KEY":    fixtureValue("netflow"),
		"ZEEK_SHIPPER_DEMO_KEY":       fixtureValue("zeek"),
	}))
	if err != nil {
		t.Fatalf("example config failed to load: %v", err)
	}
	if cfg.RestIngest.CollectorID != "rest-ingest-main" {
		t.Fatalf("rest collector id = %q", cfg.RestIngest.CollectorID)
	}
}

func TestDemoConfigLoads(t *testing.T) {
	t.Parallel()

	cursorSecretEnv := "QUIVER_API_CURSOR_" + "SECRET"
	cfg, err := LoadFile(context.Background(), "../../configs/quiver.demo.yaml", envLookup(map[string]string{
		"QUIVER_HTTP_ADDR":            "0.0.0.0:8080",
		"KAFKA_BROKER_INTERNAL":       "kafka:9092",
		"KAFKA_TOPIC_RAW":             "flow.raw",
		"KAFKA_TOPIC_DLQ":             "flow.dead_letter",
		"QUIVER_DATABASE_DSN":         "postgres://timescaledb:5432/quiver?sslmode=disable",
		cursorSecretEnv:               fixtureValue("cursor"),
		"QUIVER_DEMO_ADMIN_API_KEY":   fixtureValue("admin"),
		"REST_INGEST_DEMO_CLIENT_KEY": fixtureValue("ingest"),
		"NETFLOW_GATEWAY_DEMO_KEY":    fixtureValue("netflow"),
		"ZEEK_SHIPPER_DEMO_KEY":       fixtureValue("zeek"),
		"NETFLOW_PORT":                "2055",
		"ZEEK_CONN_TCP_PORT":          "4770",
		"POSTGRES_POOL_SIZE":          "20",
		"POSTGRES_MAX_IDLE_CONNS":     "10",
	}))
	if err != nil {
		t.Fatalf("demo config failed to load: %v", err)
	}
	if cfg.Database.MaxOpenConns != 20 {
		t.Fatalf("max_open_conns = %d", cfg.Database.MaxOpenConns)
	}
}

func TestDevConfigLoads(t *testing.T) {
	t.Parallel()

	cursorSecretEnv := "QUIVER_API_CURSOR_" + "SECRET"
	cfg, err := LoadFile(context.Background(), "../../configs/quiver.dev.yaml", envLookup(map[string]string{
		"QUIVER_HTTP_ADDR":            "0.0.0.0:8080",
		"KAFKA_BROKER_EXTERNAL":       "localhost:9094",
		"KAFKA_TOPIC_RAW":             "flow.raw",
		"KAFKA_TOPIC_DLQ":             "flow.dead_letter",
		"QUIVER_DATABASE_DSN_HOST":    fixturePostgresDSN("localhost"),
		cursorSecretEnv:               fixtureValue("cursor"),
		"QUIVER_DEMO_ADMIN_API_KEY":   fixtureValue("admin"),
		"REST_INGEST_DEMO_CLIENT_KEY": fixtureValue("ingest"),
		"NETFLOW_GATEWAY_DEMO_KEY":    fixtureValue("netflow"),
		"ZEEK_SHIPPER_DEMO_KEY":       fixtureValue("zeek"),
		"NETFLOW_PORT":                "2055",
		"ZEEK_CONN_TCP_PORT":          "4770",
		"POSTGRES_POOL_SIZE":          "20",
		"POSTGRES_MAX_IDLE_CONNS":     "10",
	}))
	if err != nil {
		t.Fatalf("dev config failed to load: %v", err)
	}
	if cfg.Database.MaxOpenConns != 20 {
		t.Fatalf("max_open_conns = %d", cfg.Database.MaxOpenConns)
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
	cfg.ZeekIngest.Enabled = true
	cfg.ZeekIngest.CollectorID = "zeek-conn-http"
	cfg.ZeekIngest.MaxBatchSize = 1000
	cfg.ProxyNetFlow.CollectorID = "netflow-main"
	cfg.Collectors.Instances = []CollectorInstanceConfig{
		{
			Type:        "netflow_v5",
			CollectorID: "netflow-main",
			Enabled:     true,
		},
	}
	cfg.QuiverClientGateways = []QuiverClientGatewayConfig{
		{
			Name:       "netflow-demo-gateway",
			SourceHost: "netflow-gateway-01",
			KeyEnv:     "NETFLOW_GATEWAY_DEMO_KEY",
		},
		{
			Name:       "zeek-demo-shipper",
			SourceHost: "zeek-probe-01",
			KeyEnv:     "ZEEK_SHIPPER_DEMO_KEY",
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

func fixturePostgresDSN(host string) string {
	return "postgres://postgres:" + fixtureValue("postgres-password") + "@" + host + ":5432/quiver?sslmode=disable"
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
  query:
    max_query_window: "7d"
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
zeek_ingest:
  enabled: true
  collector_id: zeek-conn-http
  max_batch_size: 1000
proxy_netflow:
  collector_id: netflow-main
collectors:
  restart:
    policy: always
    initial_backoff: "1s"
    max_backoff: "30s"
    max_restarts: 0
  instances:
    - type: netflow_v5
      collector_id: netflow-main
      enabled: true
      settings:
        listen_addr: "0.0.0.0:2055"
        auth_required: false
quiver_client_gateways:
  - name: netflow-demo-gateway
    source_host: netflow-gateway-01
    key_env: NETFLOW_GATEWAY_DEMO_KEY
  - name: zeek-demo-shipper
    source_host: zeek-probe-01
    key_env: ZEEK_SHIPPER_DEMO_KEY
`
}
