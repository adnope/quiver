#!/usr/bin/env bash

set -euo pipefail

# Ensure script is run from the project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Load environment variables from .env without overwriting existing environment variables
if [ -f .env ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    # Skip comments and empty lines
    [[ "$line" =~ ^#.*$ ]] && continue
    [[ -z "$line" ]] && continue
    # Extract key and value
    key="${line%%=*}"
    val="${line#*=}"
    # Only export if key is not already defined in environment
    if [ -z "${!key+x}" ]; then
      export "$key=$val"
    fi
  done < .env
fi

# Set isolated defaults, overriding the standard dev stack values if present
if [ -z "${QUIVER_HOST_PORT:-}" ] || [ "${QUIVER_HOST_PORT}" = "8236" ]; then
  export QUIVER_HOST_PORT=8237
fi
if [ -z "${POSTGRES_HOST_PORT:-}" ] || [ "${POSTGRES_HOST_PORT}" = "5432" ]; then
  export POSTGRES_HOST_PORT=5433
fi
if [ -z "${NETFLOW_PORT:-}" ] || [ "${NETFLOW_PORT}" = "2055" ]; then
  export NETFLOW_PORT=2056
fi
if [ -z "${KAFKA_HOST_PORT:-}" ] || [ "${KAFKA_HOST_PORT}" = "9094" ]; then
  export KAFKA_HOST_PORT=9095
fi
if [ -z "${QUIVER_CONFIG:-}" ] || [ "${QUIVER_CONFIG}" = "/configs/quiver.dev.yaml" ]; then
  export QUIVER_CONFIG=/configs/quiver.demo.yaml
fi
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-quiver-verify}

export QUIVER_DEMO_ADMIN_API_KEY=${QUIVER_DEMO_ADMIN_API_KEY:-demoadminkey123}
export REST_INGEST_DEMO_CLIENT_KEY=${REST_INGEST_DEMO_CLIENT_KEY:-democlientkey456}
export NETFLOW_GATEWAY_DEMO_KEY=${NETFLOW_GATEWAY_DEMO_KEY:-netflowgatewaykey456}
export ZEEK_SHIPPER_DEMO_KEY=${ZEEK_SHIPPER_DEMO_KEY:-zeekshipperkey456}
export KAFKA_TOPIC_DLQ=${KAFKA_TOPIC_DLQ:-flow.dead_letter}

echo "=================================================="
# 1. Start Docker Compose
echo "Starting Docker Compose services for project: ${COMPOSE_PROJECT_NAME}..."
docker compose down -v || true

docker compose up -d --build

# Wait for healthy Quiver API server
echo "Waiting for Quiver API to be healthy..."
HEALTH_URL="http://localhost:${QUIVER_HOST_PORT}/health"
MAX_ATTEMPTS=20
ATTEMPT=1
HEALTHY=false

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
  if curl -s --fail "$HEALTH_URL" | grep -q '"status":"ok"'; then
    echo "Quiver API is healthy!"
    HEALTHY=true
    break
  fi
  echo "Attempt $ATTEMPT/$MAX_ATTEMPTS: Quiver not ready yet, sleeping 2s..."
  sleep 2
  ATTEMPT=$((ATTEMPT + 1))
done

if [ "$HEALTHY" = "false" ]; then
  echo "ERROR: Quiver API failed to start or become healthy in time."
  docker compose logs
  exit 1
fi

echo "=================================================="
# 2. Ingest REST batch flow records
echo "Ingesting REST Batch JSON flows..."
# Run restgen valid batch
go run tools/restgen/main.go -target http://localhost:${QUIVER_HOST_PORT} -key "${REST_INGEST_DEMO_CLIENT_KEY}" -count 5

# Run restgen malformed batch (triggers partial batch return)
go run tools/restgen/main.go -target http://localhost:${QUIVER_HOST_PORT} -key "${REST_INGEST_DEMO_CLIENT_KEY}" -count 1 -malformed || true

echo "=================================================="
# 3. Ingest Zeek conn.log records through the authenticated shipper HTTP path
echo "Posting Zeek conn.log records through HTTP ingest..."
go run tools/zeekloggen/main.go -target "http://localhost:${QUIVER_HOST_PORT}" -key "${ZEEK_SHIPPER_DEMO_KEY}" -count 5
go run tools/zeekloggen/main.go -target "http://localhost:${QUIVER_HOST_PORT}" -key "${ZEEK_SHIPPER_DEMO_KEY}" -count 1 -malformed || true

echo "=================================================="
# 4. Ingest NetFlow UDP
echo "Sending NetFlow v5 packets..."
# Send 1 packet with 3 valid records
go run tools/netflowgen/main.go -target "localhost:${NETFLOW_PORT}" -count 3 -seq 1

# Send 1 malformed NetFlow packet (destined for DLQ)
go run tools/netflowgen/main.go -target "localhost:${NETFLOW_PORT}" -count 1 -seq 4 -malformed version

# Give pipelines time to process Kafka and write to TimescaleDB
echo "Waiting 12 seconds for processing pipelines to complete..."
sleep 12

echo "=================================================="
# 5. Query /api/v1/flows
echo "Querying API GET /api/v1/flows..."
FROM_TIME=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
TO_TIME=$(date -u -d '1 hour hence' +%Y-%m-%dT%H:%M:%SZ)
URL="http://localhost:${QUIVER_HOST_PORT}/api/v1/flows?from=${FROM_TIME}&to=${TO_TIME}"

echo "URL: $URL"
RESPONSE=$(curl -s -H "X-API-Key: ${QUIVER_DEMO_ADMIN_API_KEY}" "$URL")
echo "Response: $RESPONSE"

# Assert records are present for all three ingestion types
echo "Validating ingestion types exist in query results..."
if ! echo "$RESPONSE" | grep -q '"source_type":"rest_json"'; then
  echo "ERROR: Missing source_type 'rest_json' in flows query."
  exit 1
fi
if ! echo "$RESPONSE" | grep -q '"source_type":"zeek_conn_json"'; then
  echo "ERROR: Missing source_type 'zeek_conn_json' in flows query."
  exit 1
fi
if ! echo "$RESPONSE" | grep -q '"source_type":"netflow_v5"'; then
  echo "ERROR: Missing source_type 'netflow_v5' in flows query."
  exit 1
fi
echo "Ingest verification PASS!"

echo "=================================================="
# 6. Verify Aggregations
echo "Verifying GET /api/v1/aggregations/top-talkers..."
AGG_URL="http://localhost:${QUIVER_HOST_PORT}/api/v1/aggregations/top-talkers?from=${FROM_TIME}&to=${TO_TIME}&direction=src"
AGG_RESP=$(curl -s -H "X-API-Key: ${QUIVER_DEMO_ADMIN_API_KEY}" "$AGG_URL")
echo "Aggregations Response: $AGG_RESP"
if ! echo "$AGG_RESP" | grep -q '"ip"'; then
  echo "ERROR: Missing top talkers aggregation fields."
  exit 1
fi
echo "Aggregations verification PASS!"

echo "=================================================="
# 7. Verify Prometheus metrics
echo "Querying GET /metrics..."
METRICS_RESP=$(curl -s -H "X-API-Key: ${QUIVER_DEMO_ADMIN_API_KEY}" "http://localhost:${QUIVER_HOST_PORT}/metrics")
echo "Metrics contains http_requests_total? ..."
if ! echo "$METRICS_RESP" | grep -q 'api_http_requests_total'; then
  echo "ERROR: Missing expected Prometheus metrics."
  exit 1
fi
echo "Metrics verification PASS!"

echo "=================================================="
# 8. Verify DLQ (Redpanda Kafka-compatible dead_letter topic)
echo "Verifying ${KAFKA_TOPIC_DLQ} topic has messages..."
# Consume two messages from the beginning using Redpanda's rpk CLI.
# docker-compose.yml keeps the service name as "kafka" for compatibility,
# but the actual container name is ${COMPOSE_PROJECT_NAME}-redpanda.
DLQ_MESSAGES=$(timeout 10s docker exec "${COMPOSE_PROJECT_NAME}-redpanda" \
  rpk topic consume "${KAFKA_TOPIC_DLQ}" \
  --brokers=localhost:9092 \
  --offset=start \
  --num=2 2>/dev/null || true)
DLQ_COUNT=$(printf '%s\n' "$DLQ_MESSAGES" | awk '/"topic"[[:space:]]*:/ {count++} END {print count+0}')
echo "DLQ message count: $DLQ_COUNT"
if [ -z "$DLQ_COUNT" ] || [ "$DLQ_COUNT" -lt 2 ]; then
  echo "ERROR: Expected at least 2 messages in ${KAFKA_TOPIC_DLQ}, got: ${DLQ_COUNT:-0}"
  echo "Redpanda topic list:"
  docker exec "${COMPOSE_PROJECT_NAME}-redpanda" rpk topic list --brokers=localhost:9092 || true
  exit 1
fi
echo "DLQ verification PASS!"

echo "=================================================="
echo "DEMO VERIFICATION SUCCESSFUL!"
echo "=================================================="
