SELECT remove_continuous_aggregate_policy('quiver.flow_hourly_talkers', if_exists => true);
SELECT remove_continuous_aggregate_policy('quiver.flow_hourly_ports', if_exists => true);

ALTER MATERIALIZED VIEW quiver.flow_hourly_talkers SET (timescaledb.materialized_only = true);
ALTER MATERIALIZED VIEW quiver.flow_hourly_ports SET (timescaledb.materialized_only = true);

CREATE MATERIALIZED VIEW IF NOT EXISTS quiver.flow_5m_talkers
WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT
  time_bucket('5 minutes', event_start_time) AS bucket,
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

CREATE MATERIALIZED VIEW IF NOT EXISTS quiver.flow_5m_ports
WITH (timescaledb.continuous, timescaledb.materialized_only = true) AS
SELECT
  time_bucket('5 minutes', event_start_time) AS bucket,
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
