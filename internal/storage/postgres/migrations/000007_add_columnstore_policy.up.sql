ALTER TABLE quiver.flow_records SET (
    timescaledb.enable_columnstore = true,
    timescaledb.segmentby = 'source_type,collector_id,source_host',
    timescaledb.orderby = 'event_start_time DESC'
);

CALL add_columnstore_policy(
    'quiver.flow_records',
    after => INTERVAL '1 day',
    if_not_exists => TRUE
);
