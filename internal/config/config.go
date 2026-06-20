package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultMaxRequestBodyBytes       = 5 * 1024 * 1024
	DefaultMaxBatchSize              = 1000
	DefaultMaxStorageWriterBatchSize = 5000
	DefaultMaxQueryWindow            = Duration(7 * dayDuration)
	DefaultQueryLimit                = 100
	DefaultMaxQueryLimit             = 1000
	DefaultAggregationLimit          = 20
	DefaultShutdownTimeout           = Duration(10 * time.Second)
)

const dayDuration = 24 * time.Hour

type Config struct {
	Server               ServerConfig                `yaml:"server"`
	Kafka                KafkaConfig                 `yaml:"kafka"`
	Database             DatabaseConfig              `yaml:"database"`
	Ingestion            IngestionConfig             `yaml:"ingestion"`
	Storage              StorageConfig               `yaml:"storage"`
	StorageWriter        StorageWriterConfig         `yaml:"storage_writer"`
	API                  APIConfig                   `yaml:"api"`
	RestIngest           RESTIngestConfig            `yaml:"rest_ingest"`
	ZeekIngest           ZeekIngestConfig            `yaml:"zeek_ingest"`
	QuiverClientGateways []QuiverClientGatewayConfig `yaml:"quiver_client_gateways"`
	Collectors           CollectorsConfig            `yaml:"collectors"`
	DeadLetter           DeadLetterConfig            `yaml:"dead_letter"`
	Shutdown             ShutdownConfig              `yaml:"shutdown"`
}

type ServerConfig struct {
	HTTPAddr string `yaml:"http_addr"`
}

type KafkaConfig struct {
	Brokers []string    `yaml:"brokers"`
	Topics  KafkaTopics `yaml:"topics"`
}

type KafkaTopics struct {
	Raw        string `yaml:"raw"`
	DeadLetter string `yaml:"dead_letter"`
}

type DatabaseConfig struct {
	DSN             string   `yaml:"dsn"`
	Schema          string   `yaml:"schema"`
	MaxOpenConns    int      `yaml:"max_open_conns"`
	MaxIdleConns    int      `yaml:"max_idle_conns"`
	ConnMaxLifetime Duration `yaml:"conn_max_lifetime"`
	ConnMaxIdleTime Duration `yaml:"conn_max_idle_time"`
}

type IngestionConfig struct {
	PublishQueueSize int `yaml:"publish_queue_size"`
	PublisherWorkers int `yaml:"publisher_workers"`
}

type StorageConfig struct {
	Retention   RetentionConfig   `yaml:"retention"`
	Columnstore ColumnstoreConfig `yaml:"columnstore"`
}

type RetentionConfig struct {
	FlowRecordsDays int `yaml:"flow_records_days"`
}

type ColumnstoreConfig struct {
	Enabled bool     `yaml:"enabled"`
	After   Duration `yaml:"after"`
}

type StorageWriterConfig struct {
	BatchSize      int      `yaml:"batch_size"`
	FlushInterval  Duration `yaml:"flush_interval"`
	MaxRetries     int      `yaml:"max_retries"`
	InitialBackoff Duration `yaml:"initial_backoff"`
	MaxBackoff     Duration `yaml:"max_backoff"`
}

type APIConfig struct {
	MaxRequestBodyBytes int64              `yaml:"max_request_body_bytes"`
	Cursor              CursorConfig       `yaml:"cursor"`
	Query               QueryConfig        `yaml:"query"`
	RateLimits          RateLimitsConfig   `yaml:"rate_limits"`
	Health              EndpointAuthConfig `yaml:"health"`
	Metrics             EndpointAuthConfig `yaml:"metrics"`
	Keys                []APIKeyConfig     `yaml:"keys"`
}

type CursorConfig struct {
	HMACSecretEnv string `yaml:"hmac_secret_env"`
}

type QueryConfig struct {
	MaxQueryWindow          Duration `yaml:"max_query_window"`
	DefaultLimit            int      `yaml:"default_limit"`
	MaxLimit                int      `yaml:"max_limit"`
	AggregationDefaultLimit int      `yaml:"aggregation_default_limit"`
}

type RateLimitsConfig struct {
	Ingest  RateLimitConfig `yaml:"ingest"`
	Query   RateLimitConfig `yaml:"query"`
	Metrics RateLimitConfig `yaml:"metrics"`
}

type RateLimitConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
}

type EndpointAuthConfig struct {
	AuthRequired bool `yaml:"auth_required"`
}

type APIKeyConfig struct {
	Name   string   `yaml:"name"`
	KeyEnv string   `yaml:"key_env"`
	Scopes []string `yaml:"scopes"`
}

type RESTIngestConfig struct {
	Enabled      bool               `yaml:"enabled"`
	CollectorID  string             `yaml:"collector_id"`
	MaxBatchSize int                `yaml:"max_batch_size"`
	APIKeys      []RESTAPIKeyConfig `yaml:"api_keys"`
}

type RESTAPIKeyConfig struct {
	Name       string `yaml:"name"`
	SourceHost string `yaml:"source_host"`
	KeyEnv     string `yaml:"key_env"`
}

type ZeekIngestConfig struct {
	Enabled      bool   `yaml:"enabled"`
	CollectorID  string `yaml:"collector_id"`
	MaxBatchSize int    `yaml:"max_batch_size"`
}

type QuiverClientGatewayConfig struct {
	Name       string `yaml:"name"`
	SourceHost string `yaml:"source_host"`
	KeyEnv     string `yaml:"key_env"`
}

type CollectorsConfig struct {
	NetFlowV5 []NetFlowV5CollectorConfig `yaml:"netflow_v5"`
}

type NetFlowV5CollectorConfig struct {
	Enabled           bool   `yaml:"enabled"`
	CollectorID       string `yaml:"collector_id"`
	ListenAddr        string `yaml:"listen_addr"`
	ReadBufferBytes   int    `yaml:"read_buffer_bytes"`
	PacketBufferBytes int    `yaml:"packet_buffer_bytes"`
	AuthRequired      bool   `yaml:"auth_required"`
}

func (n *NetFlowV5CollectorConfig) UnmarshalYAML(value *yaml.Node) error {
	type alias NetFlowV5CollectorConfig
	aux := alias{
		AuthRequired: true, // Default to true
	}
	if err := value.Decode(&aux); err != nil {
		return err
	}
	*n = NetFlowV5CollectorConfig(aux)
	return nil
}

type DeadLetterConfig struct {
	MaxRawPacketBytes int `yaml:"max_raw_packet_bytes"`
}

type ShutdownConfig struct {
	Timeout Duration `yaml:"timeout"`
}

var ErrInvalidConfig = errors.New("config: invalid")

type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar")
	}
	parsed, err := parseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", value.Value, err)
	}
	*d = Duration(parsed)
	return nil
}

func parseDuration(raw string) (time.Duration, error) {
	value := strings.TrimSpace(raw)
	if dayCount, ok := strings.CutSuffix(value, "d"); ok {
		days, err := strconv.ParseInt(strings.TrimSpace(dayCount), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("day suffix requires an integer count: %w", err)
		}
		const maxDuration = time.Duration(1<<63 - 1)
		maxDays := int64(maxDuration / dayDuration)
		if days > maxDays || days < -maxDays {
			return 0, fmt.Errorf("day duration %d exceeds maximum supported duration", days)
		}
		return time.Duration(days) * dayDuration, nil
	}
	return time.ParseDuration(value)
}

func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

func LoadFile(ctx context.Context, path string, lookupEnv func(string) string) (Config, error) {
	if err := ctx.Err(); err != nil {
		return Config{}, fmt.Errorf("load config: %w", err)
	}
	// Operator-controlled startup config path; not derived from HTTP/user request input.
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Config{}, fmt.Errorf("load config: %w", err)
	}
	return LoadBytes(data, lookupEnv)
}

func LoadReader(reader io.Reader, lookupEnv func(string) string) (Config, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return Config{}, fmt.Errorf("read config data: %w", err)
	}
	content := string(data)
	var missingVar string
	if lookupEnv != nil {
		content = os.Expand(content, func(name string) string {
			resolved := lookupEnv(name)
			if strings.TrimSpace(resolved) == "" {
				missingVar = name
				return ""
			}
			return resolved
		})
	}
	if missingVar != "" {
		return Config{}, fmt.Errorf("%w: required env var %q is missing", ErrInvalidConfig, missingVar)
	}
	cfg := Default()
	decoder := yaml.NewDecoder(strings.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode yaml config: %w", err)
	}
	return finalize(cfg, lookupEnv)
}

func LoadBytes(data []byte, lookupEnv func(string) string) (Config, error) {
	return LoadReader(strings.NewReader(string(data)), lookupEnv)
}

func Default() Config {
	return Config{
		Server: ServerConfig{HTTPAddr: "0.0.0.0:8080"},
		Kafka: KafkaConfig{
			Topics: KafkaTopics{
				Raw:        "flow.raw",
				DeadLetter: "flow.dead_letter",
			},
		},
		Database: DatabaseConfig{
			Schema:          "quiver",
			MaxOpenConns:    20,
			MaxIdleConns:    10,
			ConnMaxLifetime: Duration(30 * time.Minute),
			ConnMaxIdleTime: Duration(5 * time.Minute),
		},
		Ingestion: IngestionConfig{
			PublishQueueSize: 10000,
			PublisherWorkers: 4,
		},
		Storage: StorageConfig{
			Retention: RetentionConfig{FlowRecordsDays: 30},
			Columnstore: ColumnstoreConfig{
				Enabled: true,
				After:   Duration(24 * time.Hour),
			},
		},
		StorageWriter: StorageWriterConfig{
			BatchSize:      3000,
			FlushInterval:  Duration(time.Second),
			MaxRetries:     10,
			InitialBackoff: Duration(100 * time.Millisecond),
			MaxBackoff:     Duration(5 * time.Second),
		},
		API: APIConfig{
			MaxRequestBodyBytes: DefaultMaxRequestBodyBytes,
			Query: QueryConfig{
				MaxQueryWindow:          DefaultMaxQueryWindow,
				DefaultLimit:            DefaultQueryLimit,
				MaxLimit:                DefaultMaxQueryLimit,
				AggregationDefaultLimit: DefaultAggregationLimit,
			},
			RateLimits: RateLimitsConfig{
				Ingest:  RateLimitConfig{RequestsPerMinute: 60},
				Query:   RateLimitConfig{RequestsPerMinute: 120},
				Metrics: RateLimitConfig{RequestsPerMinute: 60},
			},
			Metrics: EndpointAuthConfig{AuthRequired: true},
		},
		RestIngest: RESTIngestConfig{MaxBatchSize: DefaultMaxBatchSize},
		ZeekIngest: ZeekIngestConfig{MaxBatchSize: DefaultMaxBatchSize},
		DeadLetter: DeadLetterConfig{MaxRawPacketBytes: 1500},
		Shutdown:   ShutdownConfig{Timeout: DefaultShutdownTimeout},
	}
}

func (c Config) Validate(lookupEnv func(string) string) error {
	if lookupEnv == nil {
		return fmt.Errorf("%w: env lookup is required", ErrInvalidConfig)
	}
	if err := c.validateServer(); err != nil {
		return err
	}
	if err := c.validateKafka(); err != nil {
		return err
	}
	if err := c.validateDatabase(); err != nil {
		return err
	}
	if err := c.validateIngestion(); err != nil {
		return err
	}
	if err := c.validateAPI(lookupEnv); err != nil {
		return err
	}
	if err := c.validateRESTIngest(lookupEnv); err != nil {
		return err
	}
	if err := c.validateZeekIngest(); err != nil {
		return err
	}
	if err := c.validateQuiverClientGateways(lookupEnv); err != nil {
		return err
	}
	if err := c.validateCollectors(); err != nil {
		return err
	}
	if err := c.validateStorage(); err != nil {
		return err
	}
	if err := c.validateStorageWriter(); err != nil {
		return err
	}
	if c.Shutdown.Timeout <= 0 {
		return fmt.Errorf("%w: shutdown.timeout must be positive", ErrInvalidConfig)
	}
	return nil
}

func (c Config) validateQuiverClientGateways(lookupEnv func(string) string) error {
	for _, gateway := range c.QuiverClientGateways {
		if strings.TrimSpace(gateway.Name) == "" || strings.TrimSpace(gateway.SourceHost) == "" ||
			strings.TrimSpace(gateway.KeyEnv) == "" {
			return fmt.Errorf("%w: quiver client gateway name, source_host, and key_env are required", ErrInvalidConfig)
		}
		if strings.TrimSpace(lookupEnv(gateway.KeyEnv)) == "" {
			return fmt.Errorf("%w: quiver client gateway key env %q is missing", ErrInvalidConfig, gateway.KeyEnv)
		}
	}
	return nil
}

func (c Config) validateServer() error {
	if strings.TrimSpace(c.Server.HTTPAddr) == "" {
		return fmt.Errorf("%w: server.http_addr is required", ErrInvalidConfig)
	}
	if _, _, err := net.SplitHostPort(c.Server.HTTPAddr); err != nil {
		return fmt.Errorf("%w: server.http_addr must be host:port: %w", ErrInvalidConfig, err)
	}
	return nil
}

func (c Config) validateKafka() error {
	if len(c.Kafka.Brokers) == 0 {
		return fmt.Errorf("%w: kafka.brokers is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.Kafka.Topics.Raw) == "" {
		return fmt.Errorf("%w: kafka.topics.raw is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.Kafka.Topics.DeadLetter) == "" {
		return fmt.Errorf("%w: kafka.topics.dead_letter is required", ErrInvalidConfig)
	}
	return nil
}

func (c Config) validateDatabase() error {
	if strings.TrimSpace(c.Database.DSN) == "" {
		return fmt.Errorf("%w: database.dsn is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.Database.Schema) == "" {
		return fmt.Errorf("%w: database.schema is required", ErrInvalidConfig)
	}
	if c.Database.MaxOpenConns <= 0 {
		return fmt.Errorf("%w: database.max_open_conns must be positive", ErrInvalidConfig)
	}
	if c.Database.MaxIdleConns <= 0 {
		return fmt.Errorf("%w: database.max_idle_conns must be positive", ErrInvalidConfig)
	}
	if c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		return fmt.Errorf("%w: database.max_idle_conns cannot exceed max_open_conns", ErrInvalidConfig)
	}
	return nil
}

func (c Config) validateIngestion() error {
	if c.Ingestion.PublishQueueSize <= 0 {
		return fmt.Errorf("%w: ingestion.publish_queue_size must be positive", ErrInvalidConfig)
	}
	if c.Ingestion.PublisherWorkers <= 0 {
		return fmt.Errorf("%w: ingestion.publisher_workers must be positive", ErrInvalidConfig)
	}
	return nil
}

func (c Config) validateAPI(lookupEnv func(string) string) error {
	if c.API.MaxRequestBodyBytes <= 0 {
		return fmt.Errorf("%w: api.max_request_body_bytes must be positive", ErrInvalidConfig)
	}
	if strings.TrimSpace(c.API.Cursor.HMACSecretEnv) == "" {
		return fmt.Errorf("%w: api.cursor.hmac_secret_env is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(lookupEnv(c.API.Cursor.HMACSecretEnv)) == "" {
		return fmt.Errorf("%w: cursor secret env %q is missing", ErrInvalidConfig, c.API.Cursor.HMACSecretEnv)
	}
	if c.API.Query.MaxQueryWindow <= 0 {
		return fmt.Errorf("%w: api.query.max_query_window must be positive", ErrInvalidConfig)
	}
	if c.API.Query.DefaultLimit <= 0 || c.API.Query.MaxLimit <= 0 {
		return fmt.Errorf("%w: api query limits must be positive", ErrInvalidConfig)
	}
	if c.API.Query.DefaultLimit > c.API.Query.MaxLimit {
		return fmt.Errorf("%w: api.query.default_limit cannot exceed max_limit", ErrInvalidConfig)
	}
	if c.API.Query.AggregationDefaultLimit <= 0 {
		return fmt.Errorf("%w: api.query.aggregation_default_limit must be positive", ErrInvalidConfig)
	}
	if err := c.validateRateLimits(); err != nil {
		return err
	}
	for _, key := range c.API.Keys {
		if strings.TrimSpace(key.Name) == "" || strings.TrimSpace(key.KeyEnv) == "" {
			return fmt.Errorf("%w: api key name and key_env are required", ErrInvalidConfig)
		}
		if strings.TrimSpace(lookupEnv(key.KeyEnv)) == "" {
			return fmt.Errorf("%w: api key env %q is missing", ErrInvalidConfig, key.KeyEnv)
		}
		if len(key.Scopes) == 0 {
			return fmt.Errorf("%w: api key %q must have at least one scope", ErrInvalidConfig, key.Name)
		}
		for _, scope := range key.Scopes {
			if !validScope(scope) {
				return fmt.Errorf("%w: api key %q has invalid scope %q", ErrInvalidConfig, key.Name, scope)
			}
		}
	}
	return nil
}

func (c Config) validateRESTIngest(lookupEnv func(string) string) error {
	if !c.RestIngest.Enabled {
		return nil
	}
	if strings.TrimSpace(c.RestIngest.CollectorID) == "" {
		return fmt.Errorf("%w: rest_ingest.collector_id is required", ErrInvalidConfig)
	}
	if c.RestIngest.MaxBatchSize <= 0 || c.RestIngest.MaxBatchSize > DefaultMaxBatchSize {
		return fmt.Errorf("%w: rest_ingest.max_batch_size must be within 1..1000", ErrInvalidConfig)
	}
	if len(c.RestIngest.APIKeys) == 0 {
		return fmt.Errorf("%w: rest_ingest.api_keys is required", ErrInvalidConfig)
	}
	for _, key := range c.RestIngest.APIKeys {
		if strings.TrimSpace(key.Name) == "" || strings.TrimSpace(key.SourceHost) == "" ||
			strings.TrimSpace(key.KeyEnv) == "" {
			return fmt.Errorf("%w: rest api key name, source_host, and key_env are required", ErrInvalidConfig)
		}
		if strings.TrimSpace(lookupEnv(key.KeyEnv)) == "" {
			return fmt.Errorf("%w: rest api key env %q is missing", ErrInvalidConfig, key.KeyEnv)
		}
	}
	return nil
}

func (c Config) validateZeekIngest() error {
	if !c.ZeekIngest.Enabled {
		return nil
	}
	if strings.TrimSpace(c.ZeekIngest.CollectorID) == "" {
		return fmt.Errorf("%w: zeek_ingest.collector_id is required", ErrInvalidConfig)
	}
	if c.ZeekIngest.MaxBatchSize <= 0 || c.ZeekIngest.MaxBatchSize > DefaultMaxBatchSize {
		return fmt.Errorf("%w: zeek_ingest.max_batch_size must be within 1..1000", ErrInvalidConfig)
	}
	return nil
}

func (c Config) validateCollectors() error {
	collectorIDs := map[string]struct{}{}
	if c.ZeekIngest.Enabled {
		if err := reserveCollectorID(collectorIDs, c.ZeekIngest.CollectorID); err != nil {
			return err
		}
	}
	for _, collector := range c.Collectors.NetFlowV5 {
		if !collector.Enabled {
			continue
		}
		if err := reserveCollectorID(collectorIDs, collector.CollectorID); err != nil {
			return err
		}
		if _, _, err := net.SplitHostPort(collector.ListenAddr); err != nil {
			return fmt.Errorf("%w: netflow_v5.listen_addr must be host:port: %w", ErrInvalidConfig, err)
		}
	}
	return nil
}

func reserveCollectorID(ids map[string]struct{}, collectorID string) error {
	collectorID = strings.TrimSpace(collectorID)
	if collectorID == "" {
		return fmt.Errorf("%w: collector_id is required", ErrInvalidConfig)
	}
	if _, exists := ids[collectorID]; exists {
		return fmt.Errorf("%w: duplicate collector_id %q", ErrInvalidConfig, collectorID)
	}
	ids[collectorID] = struct{}{}
	return nil
}

func finalize(cfg Config, lookupEnv func(string) string) (Config, error) {
	if lookupEnv == nil {
		return Config{}, fmt.Errorf("%w: env lookup is required", ErrInvalidConfig)
	}
	dsn, err := expandEnv(cfg.Database.DSN, lookupEnv)
	if err != nil {
		return Config{}, err
	}
	cfg.Database.DSN = dsn
	if err := cfg.Validate(lookupEnv); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func expandEnv(value string, lookupEnv func(string) string) (string, error) {
	var missing []string
	expanded := os.Expand(value, func(name string) string {
		resolved := lookupEnv(name)
		if strings.TrimSpace(resolved) == "" {
			missing = append(missing, name)
			return ""
		}
		return resolved
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("%w: required env var %q is missing", ErrInvalidConfig, missing[0])
	}
	return expanded, nil
}

func (c Config) validateRateLimits() error {
	limits := []struct {
		name  string
		limit RateLimitConfig
	}{
		{name: "ingest", limit: c.API.RateLimits.Ingest},
		{name: "query", limit: c.API.RateLimits.Query},
		{name: "metrics", limit: c.API.RateLimits.Metrics},
	}
	for _, item := range limits {
		if item.limit.RequestsPerMinute <= 0 {
			return fmt.Errorf("%w: api.rate_limits.%s.requests_per_minute must be positive", ErrInvalidConfig, item.name)
		}
	}
	return nil
}

func (c Config) validateStorage() error {
	if c.Storage.Retention.FlowRecordsDays <= 0 {
		return fmt.Errorf("%w: storage.retention.flow_records_days must be positive", ErrInvalidConfig)
	}
	if c.Storage.Columnstore.Enabled && c.Storage.Columnstore.After <= 0 {
		return fmt.Errorf("%w: storage.columnstore.after must be positive when enabled", ErrInvalidConfig)
	}
	return nil
}

func (c Config) validateStorageWriter() error {
	if c.StorageWriter.BatchSize <= 0 || c.StorageWriter.BatchSize > DefaultMaxStorageWriterBatchSize {
		return fmt.Errorf("%w: storage_writer.batch_size must be within 1..5000", ErrInvalidConfig)
	}
	if c.StorageWriter.FlushInterval <= 0 {
		return fmt.Errorf("%w: storage_writer.flush_interval must be positive", ErrInvalidConfig)
	}
	if c.StorageWriter.MaxRetries < 0 {
		return fmt.Errorf("%w: storage_writer.max_retries cannot be negative", ErrInvalidConfig)
	}
	if c.StorageWriter.InitialBackoff <= 0 || c.StorageWriter.MaxBackoff <= 0 {
		return fmt.Errorf("%w: storage_writer backoffs must be positive", ErrInvalidConfig)
	}
	if c.StorageWriter.InitialBackoff > c.StorageWriter.MaxBackoff {
		return fmt.Errorf("%w: storage_writer.initial_backoff cannot exceed max_backoff", ErrInvalidConfig)
	}
	return nil
}

func validScope(scope string) bool {
	switch scope {
	case "ingest", "query", "metrics":
		return true
	default:
		return false
	}
}
