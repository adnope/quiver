CREATE TABLE IF NOT EXISTS quiver.system_metric_aggregates (
    bucket_start TIMESTAMPTZ NOT NULL,
    bucket_width_seconds INTEGER NOT NULL,
    metric_name TEXT NOT NULL,
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    metric_kind TEXT NOT NULL,
    sample_count BIGINT NOT NULL DEFAULT 0,
    count BIGINT NOT NULL DEFAULT 0,
    sum DOUBLE PRECISION NULL,
    avg DOUBLE PRECISION NULL,
    min DOUBLE PRECISION NULL,
    max DOUBLE PRECISION NULL,
    p90 DOUBLE PRECISION NULL,
    p95 DOUBLE PRECISION NULL,
    p99 DOUBLE PRECISION NULL,
    first DOUBLE PRECISION NULL,
    last DOUBLE PRECISION NULL,
    delta DOUBLE PRECISION NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_system_metric_aggregates_width_positive CHECK (bucket_width_seconds > 0),
    CONSTRAINT chk_system_metric_aggregates_kind CHECK (metric_kind IN ('counter', 'gauge', 'duration'))
);

SELECT create_hypertable(
    'quiver.system_metric_aggregates',
    'bucket_start',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_system_metric_aggregates_identity
    ON quiver.system_metric_aggregates (bucket_start, bucket_width_seconds, metric_name, labels);

CREATE INDEX IF NOT EXISTS idx_system_metric_aggregates_metric_time
    ON quiver.system_metric_aggregates (metric_name, bucket_start DESC);

CREATE INDEX IF NOT EXISTS idx_system_metric_aggregates_time
    ON quiver.system_metric_aggregates (bucket_start DESC);

CREATE INDEX IF NOT EXISTS idx_system_metric_aggregates_labels_gin
    ON quiver.system_metric_aggregates USING GIN (labels);

CREATE TABLE IF NOT EXISTS quiver.system_metric_histogram_buckets (
    bucket_start TIMESTAMPTZ NOT NULL,
    bucket_width_seconds INTEGER NOT NULL,
    metric_name TEXT NOT NULL,
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    bucket_index INTEGER NOT NULL,
    bucket_upper_bound DOUBLE PRECISION NULL,
    count BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_system_metric_histogram_width_positive CHECK (bucket_width_seconds > 0),
    CONSTRAINT chk_system_metric_histogram_bucket_index CHECK (bucket_index >= 0),
    CONSTRAINT chk_system_metric_histogram_count CHECK (count >= 0)
);

SELECT create_hypertable(
    'quiver.system_metric_histogram_buckets',
    'bucket_start',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_system_metric_histogram_buckets_identity
    ON quiver.system_metric_histogram_buckets (bucket_start, bucket_width_seconds, metric_name, labels, bucket_index);

CREATE INDEX IF NOT EXISTS idx_system_metric_histogram_buckets_metric_time
    ON quiver.system_metric_histogram_buckets (metric_name, bucket_start DESC);

CREATE INDEX IF NOT EXISTS idx_system_metric_histogram_buckets_time
    ON quiver.system_metric_histogram_buckets (bucket_start DESC);
