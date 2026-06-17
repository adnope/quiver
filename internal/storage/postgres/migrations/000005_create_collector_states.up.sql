CREATE TABLE IF NOT EXISTS quiver.collector_states (
    state_key TEXT PRIMARY KEY,
    collector_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_host TEXT NOT NULL,
    state JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_collector_states_collector
    ON quiver.collector_states (collector_id, source_type, source_host);
