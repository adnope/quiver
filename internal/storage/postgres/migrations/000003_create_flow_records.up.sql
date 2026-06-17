CREATE TABLE IF NOT EXISTS quiver.flow_records (
    id UUID NOT NULL,
    schema_version TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    raw_event_id UUID NOT NULL,

    source_type TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    source_host TEXT NOT NULL,
    source_ip INET NULL,
    ingested_at TIMESTAMPTZ NOT NULL,
    normalized_at TIMESTAMPTZ NOT NULL,

    event_start_time TIMESTAMPTZ NOT NULL,
    event_end_time TIMESTAMPTZ NULL,
    duration_ms BIGINT NULL CHECK (duration_ms IS NULL OR duration_ms >= 0),

    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INTEGER NULL CHECK (src_port IS NULL OR (src_port >= 0 AND src_port <= 65535)),
    dst_port INTEGER NULL CHECK (dst_port IS NULL OR (dst_port >= 0 AND dst_port <= 65535)),
    ip_version SMALLINT NOT NULL CHECK (ip_version IN (4, 6)),
    transport_protocol TEXT NOT NULL,
    protocol_number SMALLINT NOT NULL CHECK (protocol_number >= 0 AND protocol_number <= 255),

    bytes BIGINT NULL CHECK (bytes IS NULL OR bytes >= 0),
    packets BIGINT NULL CHECK (packets IS NULL OR packets >= 0),
    tcp_flags INTEGER NULL,
    flow_state TEXT NULL,

    direction TEXT NOT NULL DEFAULT 'unknown',
    input_interface INTEGER NULL,
    output_interface INTEGER NULL,
    next_hop_ip INET NULL,

    application_protocol TEXT NULL,
    sampling_rate INTEGER NULL CHECK (sampling_rate IS NULL OR sampling_rate > 0),

    normalization_status TEXT NOT NULL DEFAULT 'ok',
    normalization_error TEXT NULL,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,

    PRIMARY KEY (event_start_time, id),
    UNIQUE (event_start_time, idempotency_key),

    CONSTRAINT chk_schema_version
        CHECK (schema_version = 'flow.v1'),
    CONSTRAINT chk_event_time_order
        CHECK (event_end_time IS NULL OR event_end_time >= event_start_time),
    CONSTRAINT chk_transport_protocol
        CHECK (transport_protocol IN ('tcp', 'udp', 'icmp', 'gre', 'esp', 'other', 'unknown')),
    CONSTRAINT chk_direction
        CHECK (direction IN ('inbound', 'outbound', 'internal', 'external', 'unknown')),
    CONSTRAINT chk_normalization_status
        CHECK (normalization_status IN ('ok', 'partial'))
);

SELECT create_hypertable(
    'quiver.flow_records',
    'event_start_time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);
