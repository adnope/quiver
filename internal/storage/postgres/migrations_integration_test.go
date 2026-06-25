//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func TestMigrationsApplyOnTimescaleDB(t *testing.T) {
	dsn := os.Getenv("QUIVER_TEST_DATABASE_DSN")
	if dsn == "" {
		dsn = os.Getenv("QUIVER_DATABASE_DSN")
	}
	if dsn == "" {
		t.Skip("set QUIVER_TEST_DATABASE_DSN to a disposable TimescaleDB database to run migration integration tests")
	}

	migrator, err := migrate.New("file://migrations", dsn)
	if err != nil {
		t.Fatalf("create migrator: %v", err)
	}
	if err := migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("apply migrations: %v", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close postgres: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	requireExists(ctx, t, db, "schema quiver", `
SELECT EXISTS (
    SELECT 1
    FROM information_schema.schemata
    WHERE schema_name = 'quiver'
)`)
	requireExists(ctx, t, db, "TimescaleDB extension", `
SELECT EXISTS (
    SELECT 1
    FROM pg_extension
    WHERE extname = 'timescaledb'
)`)
	requireExists(ctx, t, db, "flow_records table", `SELECT to_regclass('quiver.flow_records') IS NOT NULL`)
	requireExists(ctx, t, db, "collector_states table", `SELECT to_regclass('quiver.collector_states') IS NOT NULL`)
	requireExists(ctx, t, db, "system_metric_aggregates table", `SELECT to_regclass('quiver.system_metric_aggregates') IS NOT NULL`)
	requireExists(ctx, t, db, "system_metric_histogram_buckets table", `SELECT to_regclass('quiver.system_metric_histogram_buckets') IS NOT NULL`)
	for _, viewName := range []string{
		"flow_5m_talkers",
		"flow_5m_ports",
		"flow_hourly_talkers",
		"flow_hourly_ports",
	} {
		requireExists(ctx, t, db, viewName+" continuous aggregate", `SELECT to_regclass('quiver.' || $1) IS NOT NULL`, viewName)
		requireBoolQuery(ctx, t, db, viewName+" materialized-only", `
SELECT materialized_only
FROM timescaledb_information.continuous_aggregates
WHERE view_schema = 'quiver'
  AND view_name = $1`, true, viewName)
	}
	requireExists(ctx, t, db, "flow_records hypertable", `
SELECT EXISTS (
    SELECT 1
    FROM timescaledb_information.hypertables
    WHERE hypertable_schema = 'quiver'
      AND hypertable_name = 'flow_records'
)`)
	for _, hypertableName := range []string{"system_metric_aggregates", "system_metric_histogram_buckets"} {
		requireExists(ctx, t, db, hypertableName+" hypertable", `
SELECT EXISTS (
    SELECT 1
    FROM timescaledb_information.hypertables
    WHERE hypertable_schema = 'quiver'
      AND hypertable_name = $1
)`, hypertableName)
	}
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
		"idx_collector_states_collector",
		"idx_system_metric_aggregates_metric_time",
		"idx_system_metric_aggregates_time",
		"idx_system_metric_histogram_buckets_metric_time",
		"idx_system_metric_histogram_buckets_time",
	} {
		requireExists(ctx, t, db, indexName, `
SELECT EXISTS (
    SELECT 1
    FROM pg_indexes
    WHERE schemaname = 'quiver'
      AND indexname = $1
)`, indexName)
	}
	requireExists(ctx, t, db, "retention policy", `
SELECT EXISTS (
    SELECT 1
    FROM timescaledb_information.jobs
    WHERE hypertable_schema = 'quiver'
      AND hypertable_name = 'flow_records'
      AND proc_name = 'policy_retention'
)`)
	requireExists(ctx, t, db, "columnstore policy", `
SELECT EXISTS (
    SELECT 1
    FROM timescaledb_information.jobs
    WHERE hypertable_schema = 'quiver'
      AND hypertable_name = 'flow_records'
      AND proc_name = 'policy_compression'
)`)
}

func requireBoolQuery(ctx context.Context, t *testing.T, db *sql.DB, name string, query string, want bool, args ...any) {
	t.Helper()

	var got bool
	if err := db.QueryRowContext(ctx, query, args...).Scan(&got); err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	if got != want {
		t.Fatalf("%s = %t, want %t", name, got, want)
	}
}

func requireExists(ctx context.Context, t *testing.T, db *sql.DB, name string, query string, args ...any) {
	t.Helper()

	var exists bool
	if err := db.QueryRowContext(ctx, query, args...).Scan(&exists); err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	if !exists {
		t.Fatalf("%s does not exist", name)
	}
}
