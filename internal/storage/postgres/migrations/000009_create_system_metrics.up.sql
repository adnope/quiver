CREATE TABLE IF NOT EXISTS quiver.system_metrics (
    timestamp TIMESTAMPTZ NOT NULL,
    metric_name TEXT NOT NULL,
    labels JSONB,
    value DOUBLE PRECISION NOT NULL
);

SELECT create_hypertable('quiver.system_metrics', 'timestamp', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_system_metrics_query 
ON quiver.system_metrics (metric_name, timestamp DESC);

SELECT add_retention_policy('quiver.system_metrics', INTERVAL '30 days', if_not_exists => TRUE);
