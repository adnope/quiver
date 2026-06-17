CALL remove_columnstore_policy('quiver.flow_records', if_exists => TRUE);

ALTER TABLE quiver.flow_records SET (
    timescaledb.enable_columnstore = false
);
