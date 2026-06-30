CREATE TABLE IF NOT EXISTS quiver.system_logs (
    timestamp TIMESTAMPTZ NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb
);

SELECT create_hypertable(
    'quiver.system_logs',
    'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

CREATE INDEX IF NOT EXISTS idx_system_logs_level_time
    ON quiver.system_logs (level, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_system_logs_time
    ON quiver.system_logs (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_system_logs_attributes
    ON quiver.system_logs USING GIN (attributes);
