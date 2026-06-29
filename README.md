# Quiver

Quiver is a high-performance, multi-protocol flow ingestion and normalization platform designed for modern network observability. It provides robust ingestion pipelines for NetFlow v5, NetFlow v9, REST, and Zeek logs.

## Features

- **NetFlow v5 Ingestion**: High-throughput UDP collector with zero-copy packet framing and full normalization.
- **NetFlow v9 Ingestion**: Advanced template-based NetFlow v9 collector with stateful decoding, zero-allocation caching, and strict memory limits.
- **REST Ingest**: JSON batch ingestion API with rich custom field mapping.
- **Zeek Ingest**: Multi-protocol streaming ingest for Zeek connection logs (`zeek_conn_tcp`, `zeek_conn_http`).
- **Storage & Search**: TimescaleDB columnar storage engine with flexible query capabilities and real-time aggregations.
- **Redpanda / Kafka Ingestion Buffer**: Durable raw and dead-letter queues (DLQ) for operational safety.

## Configuration

Quiver uses a structured YAML configuration file. See `configs/quiver.example.yaml` for a complete reference.

### NetFlow v9 Proxy & Collector Configuration

```yaml
quiver_client_gateways:
  - name: "netflow-demo-gateway"
    source_host: "netflow-gateway-01"
    key_env: "NETFLOW_GATEWAY_DEMO_KEY"
    allowed_collector_ids: ["netflow-main", "netflow-v9-main"]

proxy_netflow:
  routes:
    - version: 5
      collector_id: "netflow-main"
    - version: 9
      collector_id: "netflow-v9-main"

collectors:
  instances:
    - type: "netflow_v9"
      collector_id: "netflow-v9-main"
      enabled: true
      settings:
        template_ttl: "30m"
        cleanup_interval: "1m"
        exporter_idle_timeout: "5m"
        sampling_rate: 1
        max_packet_bytes: 65535
        max_exporters: 100
        max_templates_per_exporter: 100
        max_templates_total: 1000
        max_fields_per_template: 100
        max_record_bytes: 4096
        max_unknown_field_bytes: 1024
        max_attributes_bytes: 4096
        worker_count: 4
        queue_capacity: 1000
        max_queue_bytes: 10485760
        pending:
          max_wait: "1m"
          max_bytes_per_exporter: 1048576
          max_bytes_total: 10485760
```

## Running Verification & Tests

To run the full suite of unit tests:
```bash
make test-unit
```

To run end-to-end NetFlow v9 verification using Docker Compose:
```bash
make verify-netflow-v9
```
