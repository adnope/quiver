CREATE INDEX IF NOT EXISTS idx_flow_records_time_id_desc
    ON quiver.flow_records (event_start_time DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_flow_records_id
    ON quiver.flow_records (id);

CREATE INDEX IF NOT EXISTS idx_flow_records_raw_event_id
    ON quiver.flow_records (raw_event_id);

CREATE INDEX IF NOT EXISTS idx_flow_records_src_ip_time
    ON quiver.flow_records (src_ip, event_start_time DESC);

CREATE INDEX IF NOT EXISTS idx_flow_records_dst_ip_time
    ON quiver.flow_records (dst_ip, event_start_time DESC);

CREATE INDEX IF NOT EXISTS idx_flow_records_src_dst_proto_time
    ON quiver.flow_records (src_ip, dst_ip, protocol_number, event_start_time DESC);

CREATE INDEX IF NOT EXISTS idx_flow_records_dst_port_time
    ON quiver.flow_records (dst_port, event_start_time DESC);

CREATE INDEX IF NOT EXISTS idx_flow_records_src_port_time
    ON quiver.flow_records (src_port, event_start_time DESC);

CREATE INDEX IF NOT EXISTS idx_flow_records_protocol_time
    ON quiver.flow_records (protocol_number, event_start_time DESC);

CREATE INDEX IF NOT EXISTS idx_flow_records_transport_protocol_time
    ON quiver.flow_records (transport_protocol, event_start_time DESC);

CREATE INDEX IF NOT EXISTS idx_flow_records_source_type_time
    ON quiver.flow_records (source_type, event_start_time DESC);

CREATE INDEX IF NOT EXISTS idx_flow_records_source_time
    ON quiver.flow_records (collector_id, source_host, event_start_time DESC);

CREATE INDEX IF NOT EXISTS idx_flow_records_app_proto_time
    ON quiver.flow_records (application_protocol, event_start_time DESC)
    WHERE application_protocol IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_flow_records_direction_time
    ON quiver.flow_records (direction, event_start_time DESC);
