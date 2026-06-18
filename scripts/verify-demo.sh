#!/usr/bin/env bash

set -euo pipefail

# Ensure script is run from the project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Load environment variables from .env
if [ -f .env ]; then
  # Export variables from .env, excluding comments and empty lines
  export $(grep -v '^#' .env | xargs)
fi

# Fallback values
QUIVER_HOST_PORT=${QUIVER_HOST_PORT:-8236}
QUIVER_DEMO_ADMIN_API_KEY=${QUIVER_DEMO_ADMIN_API_KEY:-demoadminkey123}
REST_INGEST_DEMO_CLIENT_KEY=${REST_INGEST_DEMO_CLIENT_KEY:-democlientkey456}
NETFLOW_PORT=${NETFLOW_PORT:-2055}
KAFKA_TOPIC_DLQ=${KAFKA_TOPIC_DLQ:-flow.dead_letter}

echo "=================================================="
# 1. Start Docker Compose
echo "Starting Docker Compose services..."
docker compose down -v || true
# Ensure clean /tmp/zeek directory
docker run --rm -v /tmp:/tmp alpine rm -rf /tmp/zeek || rm -rf /tmp/zeek || true
mkdir -p /tmp/zeek
chmod 777 /tmp/zeek

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
# 3. Ingest Zeek conn.log
echo "Seeding Zeek conn.log..."
# Append 5 valid records
go run tools/zeekloggen/main.go -file /tmp/zeek/conn.log -mode append -count 5

# Append 1 malformed JSON record (destined for DLQ)
go run tools/zeekloggen/main.go -file /tmp/zeek/conn.log -mode append -malformed

# Sync to docker container in case volume mount is not sharing the same filesystem (e.g. in containerized CI)
if docker ps --format '{{.Names}}' | grep -q 'quiver-app'; then
  docker exec quiver-app mkdir -p /var/log/zeek/current || true
  docker cp /tmp/zeek/conn.log quiver-app:/var/log/zeek/current/conn.log || true
fi

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
# 8. Verify DLQ (Kafka dead_letter topic)
echo "Verifying ${KAFKA_TOPIC_DLQ} topic has messages..."
# Consume from dead_letter topic using docker cp-kafka tools
DLQ_COUNT=$(docker exec quiver-kafka kafka-get-offsets --bootstrap-server localhost:9092 --topic "${KAFKA_TOPIC_DLQ}" | cut -d':' -f3 | awk '{s+=$1} END {print s}')
echo "DLQ message count: $DLQ_COUNT"
if [ -z "$DLQ_COUNT" ] || [ "$DLQ_COUNT" -lt 2 ]; then
  echo "ERROR: Expected at least 2 messages in ${KAFKA_TOPIC_DLQ}, got: ${DLQ_COUNT:-0}"
  exit 1
fi
echo "DLQ verification PASS!"

echo "=================================================="
echo "DEMO VERIFICATION SUCCESSFUL!"
echo "=================================================="
