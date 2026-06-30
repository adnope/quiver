CREATE MATERIALIZED VIEW IF NOT EXISTS quiver.system_metric_5m_aggregates
WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT
  time_bucket('5 minutes', bucket_start) AS bucket_start,
  300::integer AS bucket_width_seconds,
  metric_name,
  labels,
  metric_kind,
  SUM(sample_count)::bigint AS sample_count,
  SUM(count)::bigint AS count,
  SUM(sum)::double precision AS sum,
  (SUM(sum) / NULLIF(SUM(count), 0))::double precision AS avg,
  MIN(min)::double precision AS min,
  MAX(max)::double precision AS max,
  NULL::double precision AS p90,
  NULL::double precision AS p95,
  NULL::double precision AS p99,
  first(first, bucket_start)::double precision AS first,
  last(last, bucket_start)::double precision AS last,
  SUM(delta)::double precision AS delta
FROM quiver.system_metric_aggregates
GROUP BY time_bucket('5 minutes', bucket_start), metric_name, labels, metric_kind WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS quiver.system_metric_5m_histogram_buckets
WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT
  time_bucket('5 minutes', bucket_start) AS bucket_start,
  300::integer AS bucket_width_seconds,
  metric_name,
  labels,
  bucket_index,
  bucket_upper_bound,
  SUM(count)::bigint AS count
FROM quiver.system_metric_histogram_buckets
GROUP BY time_bucket('5 minutes', bucket_start), metric_name, labels, bucket_index, bucket_upper_bound WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS quiver.system_metric_1h_aggregates
WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT
  time_bucket('1 hour', bucket_start) AS bucket_start,
  3600::integer AS bucket_width_seconds,
  metric_name,
  labels,
  metric_kind,
  SUM(sample_count)::bigint AS sample_count,
  SUM(count)::bigint AS count,
  SUM(sum)::double precision AS sum,
  (SUM(sum) / NULLIF(SUM(count), 0))::double precision AS avg,
  MIN(min)::double precision AS min,
  MAX(max)::double precision AS max,
  NULL::double precision AS p90,
  NULL::double precision AS p95,
  NULL::double precision AS p99,
  first(first, bucket_start)::double precision AS first,
  last(last, bucket_start)::double precision AS last,
  SUM(delta)::double precision AS delta
FROM quiver.system_metric_aggregates
GROUP BY time_bucket('1 hour', bucket_start), metric_name, labels, metric_kind WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS quiver.system_metric_1h_histogram_buckets
WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT
  time_bucket('1 hour', bucket_start) AS bucket_start,
  3600::integer AS bucket_width_seconds,
  metric_name,
  labels,
  bucket_index,
  bucket_upper_bound,
  SUM(count)::bigint AS count
FROM quiver.system_metric_histogram_buckets
GROUP BY time_bucket('1 hour', bucket_start), metric_name, labels, bucket_index, bucket_upper_bound WITH NO DATA;
