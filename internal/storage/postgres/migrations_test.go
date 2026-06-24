package postgres

import (
	"embed"
	"strings"
	"testing"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func TestMigrationFilesExist(t *testing.T) {
	t.Parallel()

	expected := []string{
		"000001_create_schema.up.sql",
		"000001_create_schema.down.sql",
		"000002_enable_extensions.up.sql",
		"000002_enable_extensions.down.sql",
		"000003_create_flow_records.up.sql",
		"000003_create_flow_records.down.sql",
		"000004_create_flow_record_indexes.up.sql",
		"000004_create_flow_record_indexes.down.sql",
		"000005_create_collector_states.up.sql",
		"000005_create_collector_states.down.sql",
		"000006_add_retention_policy.up.sql",
		"000006_add_retention_policy.down.sql",
		"000007_add_columnstore_policy.up.sql",
		"000007_add_columnstore_policy.down.sql",
		"000010_create_system_metric_aggregates.up.sql",
		"000010_create_system_metric_aggregates.down.sql",
	}
	for _, name := range expected {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := migrationFiles.ReadFile("migrations/" + name); err != nil {
				t.Fatalf("missing migration %s: %v", name, err)
			}
		})
	}
}

func TestMigrationsMatchPhaseFiveStorageDecisions(t *testing.T) {
	t.Parallel()

	createSchema := readMigration(t, "000001_create_schema.up.sql")
	requireMigrationContains(t, createSchema, "CREATE SCHEMA IF NOT EXISTS quiver")

	extensions := readMigration(t, "000002_enable_extensions.up.sql")
	requireMigrationContains(t, extensions, "CREATE EXTENSION IF NOT EXISTS timescaledb")
	requireMigrationContains(t, extensions, "CREATE EXTENSION IF NOT EXISTS pgcrypto")

	flowRecords := readMigration(t, "000003_create_flow_records.up.sql")
	requireMigrationContains(t, flowRecords, "CREATE TABLE IF NOT EXISTS quiver.flow_records")
	requireMigrationContains(t, flowRecords, "PRIMARY KEY (event_start_time, id)")
	requireMigrationContains(t, flowRecords, "UNIQUE (event_start_time, idempotency_key)")
	requireMigrationContains(t, flowRecords, "SELECT create_hypertable(")
	requireMigrationContains(t, flowRecords, "'quiver.flow_records'")
	requireMigrationContains(t, flowRecords, "'event_start_time'")
	requireMigrationContains(t, flowRecords, "chunk_time_interval => INTERVAL '1 day'")
	requireMigrationContains(t, flowRecords, "if_not_exists => TRUE")

	indexes := readMigration(t, "000004_create_flow_record_indexes.up.sql")
	for _, indexName := range []string{
		"idx_flow_records_time_id_desc",
		"idx_flow_records_id",
		"idx_flow_records_raw_event_id",
		"idx_flow_records_src_ip_time",
		"idx_flow_records_dst_ip_time",
		"idx_flow_records_src_dst_proto_time",
		"idx_flow_records_dst_port_time",
		"idx_flow_records_src_port_time",
		"idx_flow_records_protocol_time",
		"idx_flow_records_transport_protocol_time",
		"idx_flow_records_source_type_time",
		"idx_flow_records_source_time",
		"idx_flow_records_app_proto_time",
		"idx_flow_records_direction_time",
	} {
		requireMigrationContains(t, indexes, indexName)
	}

	collectorStates := readMigration(t, "000005_create_collector_states.up.sql")
	requireMigrationContains(t, collectorStates, "CREATE TABLE IF NOT EXISTS quiver.collector_states")
	requireMigrationContains(t, collectorStates, "state JSONB NOT NULL")
	requireMigrationContains(t, collectorStates, "idx_collector_states_collector")

	retention := readMigration(t, "000006_add_retention_policy.up.sql")
	requireMigrationContains(t, retention, "SELECT add_retention_policy")
	requireMigrationContains(t, retention, "'quiver.flow_records'")
	requireMigrationContains(t, retention, "INTERVAL '30 days'")
	requireMigrationContains(t, retention, "if_not_exists => TRUE")

	columnstore := readMigration(t, "000007_add_columnstore_policy.up.sql")
	requireMigrationContains(t, columnstore, "timescaledb.enable_columnstore = true")
	requireMigrationContains(t, columnstore, "CALL add_columnstore_policy")
	requireMigrationContains(t, columnstore, "'quiver.flow_records'")
	requireMigrationContains(t, columnstore, "after => INTERVAL '1 day'")
	requireMigrationContains(t, columnstore, "if_not_exists => TRUE")

	metricAggregates := readMigration(t, "000010_create_system_metric_aggregates.up.sql")
	requireMigrationContains(t, metricAggregates, "CREATE TABLE IF NOT EXISTS quiver.system_metric_aggregates")
	requireMigrationContains(t, metricAggregates, "CREATE TABLE IF NOT EXISTS quiver.system_metric_histogram_buckets")
	requireMigrationContains(t, metricAggregates, "SELECT create_hypertable(")
	requireMigrationContains(t, metricAggregates, "'quiver.system_metric_aggregates'")
	requireMigrationContains(t, metricAggregates, "'quiver.system_metric_histogram_buckets'")
	requireMigrationContains(t, metricAggregates, "uq_system_metric_aggregates_identity")
	requireMigrationContains(t, metricAggregates, "uq_system_metric_histogram_buckets_identity")
	requireMigrationContains(t, metricAggregates, "idx_system_metric_aggregates_metric_time")
	requireMigrationContains(t, metricAggregates, "idx_system_metric_histogram_buckets_metric_time")
}

func readMigration(t *testing.T, name string) string {
	t.Helper()

	data, err := migrationFiles.ReadFile("migrations/" + name)
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	return string(data)
}

func requireMigrationContains(t *testing.T, migration string, expected string) {
	t.Helper()

	if !strings.Contains(migration, expected) {
		t.Fatalf("migration does not contain %q:\n%s", expected, migration)
	}
}
