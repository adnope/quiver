DROP MATERIALIZED VIEW IF EXISTS quiver.flow_5m_ports;
DROP MATERIALIZED VIEW IF EXISTS quiver.flow_5m_talkers;

ALTER MATERIALIZED VIEW quiver.flow_hourly_ports SET (timescaledb.materialized_only = false);
ALTER MATERIALIZED VIEW quiver.flow_hourly_talkers SET (timescaledb.materialized_only = false);

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
