SELECT remove_continuous_aggregate_policy('quiver.flow_hourly_talkers', if_exists => true);
DROP MATERIALIZED VIEW IF EXISTS quiver.flow_hourly_talkers;

SELECT remove_continuous_aggregate_policy('quiver.flow_hourly_ports', if_exists => true);
DROP MATERIALIZED VIEW IF EXISTS quiver.flow_hourly_ports;
