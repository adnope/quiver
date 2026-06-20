CREATE MATERIALIZED VIEW IF NOT EXISTS quiver.flow_hourly_talkers
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT
  time_bucket('1 hour', event_start_time) AS bucket,
  src_ip,
  dst_ip,
  protocol_number,
  transport_protocol,
  source_type,
  SUM(bytes) AS bytes,
  SUM(packets) AS packets,
  COUNT(*) AS flow_count
FROM quiver.flow_records
GROUP BY bucket, src_ip, dst_ip, protocol_number, transport_protocol, source_type WITH NO DATA;

CREATE MATERIALIZED VIEW IF NOT EXISTS quiver.flow_hourly_ports
WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
SELECT
  time_bucket('1 hour', event_start_time) AS bucket,
  src_port,
  dst_port,
  protocol_number,
  transport_protocol,
  source_type,
  SUM(bytes) AS bytes,
  SUM(packets) AS packets,
  COUNT(*) AS flow_count
FROM quiver.flow_records
GROUP BY bucket, src_port, dst_port, protocol_number, transport_protocol, source_type WITH NO DATA;

SELECT add_continuous_aggregate_policy('quiver.flow_hourly_talkers',
  start_offset => INTERVAL '3 hours',
  end_offset => INTERVAL '0 minutes',
  schedule_interval => INTERVAL '30 minutes',
  if_not_exists => true);

SELECT add_continuous_aggregate_policy('quiver.flow_hourly_ports',
  start_offset => INTERVAL '3 hours',
  end_offset => INTERVAL '0 minutes',
  schedule_interval => INTERVAL '30 minutes',
  if_not_exists => true);
