# Quiver

Quiver is a network-flow ingestion and query service written in Go. It receives NetFlow v5, NetFlow v9, Zeek `conn.log`, and REST network flow records, publishes Protobuf events to Kafka topics, normalizes them, stores them in TimescaleDB, and exposes query, aggregation, metrics, logs API endpoints.

## Ingestion paths

| Source          | Runtime path                                                         |
| --------------- | -------------------------------------------------------------------- |
| NetFlow v5      | `netflow_v5` via direct UDP collector, or with `quiver-client` proxy |
| NetFlow v9      | `quiver-client` proxy routed to the `netflow_v9` collector           |
| Zeek `conn.log` | HTTP batch ingest or the `zeek_conn_tcp` collector                   |
| REST            | `POST /api/v1/ingest/flows` authenticated batches                    |

All accepted raw events use `flow.v1.RawFlowEventEnvelope` Protobuf values on `flow.raw` Kafka topic.

Failed events use `flow.v1.DeadLetterEvent` on `flow.dead_letter` topic.

Both topics are published with LZ4 compression and the key `collector_id + ":" + source_host`.

## Runtime

The main Docker Compose stack includes TimescaleDB, Redpanda (Kafka-compatible alternative), a migration job, one or more Quiver instances behind Nginx, and `quiver-client`.

In production environment, it is recommended to run `quiver-client` on exporter hosts instead of running it in the compose stack.

The frontend is embedded into the backend.

```bash
cp .env.example .env
make dev-up
```

The default dev UI and API are exposed through `quiver-lb` at
`http://localhost:8118`.

By default, the compose stack uses the configuration at `configs/quiver.dev.yaml`. Feel free to use your own YAML configuration file. See `configs/quiver.example.yaml` for the complete strict YAML configuration shape.

## Deployment

For deploying Quiver in a production environment:

### Backend Services

- Deploy the core backend services (TimescaleDB, Redpanda, Nginx, and Quiver instances) using Docker Compose.
- It is recommended to not deploy `quiver-client` in the central backend compose stack in production.

### On Exporter host - NetFlow Ingestion

- For secure NetFlow v5/v9 ingestion with API keys, use `quiver-client`.
- Deploy the client directly on the host that produces the network flows.
- Refer to [client.yaml](configs/client.yaml) for client configuration.

### On Exporter host - Zeek Log Ingestion

- For Zeek `conn.log` ingestion, run Vector on the host producing the logs.
- Refer to [vector.yaml](vector.yaml) for the pipeline configuration.
- Refer to [compose.vector.yml](compose.vector.yml) for deployment reference.

## Verification

```bash
make test-unit            # unit tests for all Go packages
make lint                 # Go and frontend lint/format checks
make proto-check          # generated Protobuf freshness
make swagger-check        # annotation freshness
make test                 # isolated services + unit + integration tests
make verify-demo          # full REST, Zeek HTTP, NetFlow v5/v9, DB, API, metrics, DLQ demo test
make verify-vector-shipper
make verify-zeek-conn-tcp
make verify-netflow-v9
```

`make coverage` writes `coverage.out`; the repository documents an 80% core
package target, but the Makefile and CI currently generate coverage without
enforcing that threshold.
