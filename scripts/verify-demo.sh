#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

PROJECT="${COMPOSE_PROJECT_NAME:-quiver-verify}"
COMPOSE_FILE="${VERIFY_COMPOSE_FILE:-docker-compose.verify.yml}"

QUIVER_HOST_PORT="${VERIFY_HOST_PORT:-8237}"
NETFLOW_PORT="${VERIFY_NETFLOW_PORT:-2056}"

QUIVER_DEMO_ADMIN_API_KEY="demoadminkey123"
REST_INGEST_DEMO_CLIENT_KEY="democlientkey456"
ZEEK_SHIPPER_DEMO_KEY="zeekshipperkey456"
KAFKA_TOPIC_DLQ="flow.dead_letter"

VERIFY_CLEANUP="${VERIFY_CLEANUP:-true}"

compose() {
  COMPOSE_PROJECT_NAME="$PROJECT" docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  if [ "$VERIFY_CLEANUP" = "true" ]; then
    compose down -v >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

echo "=================================================="
echo "Starting Docker Compose services for project: ${PROJECT}..."
compose down -v || true
compose up -d --build

echo "Waiting for Quiver API to be healthy..."
HEALTH_URL="http://localhost:${QUIVER_HOST_PORT}/health"
MAX_ATTEMPTS=20
ATTEMPT=1
HEALTHY=false

while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
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
  compose logs
  exit 1
fi

echo "=================================================="
echo "Ingesting REST Batch JSON flows..."
go run tools/restgen/main.go -target "http://localhost:${QUIVER_HOST_PORT}" -key "${REST_INGEST_DEMO_CLIENT_KEY}" -count 5
go run tools/restgen/main.go -target "http://localhost:${QUIVER_HOST_PORT}" -key "${REST_INGEST_DEMO_CLIENT_KEY}" -count 1 -malformed || true

echo "=================================================="
echo "Posting Zeek conn.log records through HTTP ingest..."
go run tools/zeekloggen/main.go -target "http://localhost:${QUIVER_HOST_PORT}" -key "${ZEEK_SHIPPER_DEMO_KEY}" -count 5
go run tools/zeekloggen/main.go -target "http://localhost:${QUIVER_HOST_PORT}" -key "${ZEEK_SHIPPER_DEMO_KEY}" -count 1 -malformed || true

echo "=================================================="
echo "Sending NetFlow v5 packets..."
go run tools/netflowgen/main.go -target "localhost:${NETFLOW_PORT}" -count 3 -seq 1

# Send two malformed NetFlow packets. These are expected to reach Kafka DLQ.
go run tools/netflowgen/main.go -target "localhost:${NETFLOW_PORT}" -count 1 -seq 4 -malformed version
go run tools/netflowgen/main.go -target "localhost:${NETFLOW_PORT}" -count 1 -seq 5 -malformed version

echo "Waiting 12 seconds for processing pipelines to complete..."
sleep 12

echo "=================================================="
echo "Querying API GET /api/v1/flows..."
FROM_TIME=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
TO_TIME=$(date -u -d '1 hour hence' +%Y-%m-%dT%H:%M:%SZ)
URL="http://localhost:${QUIVER_HOST_PORT}/api/v1/flows?from=${FROM_TIME}&to=${TO_TIME}"

echo "URL: $URL"
RESPONSE=$(curl -s -H "X-API-Key: ${QUIVER_DEMO_ADMIN_API_KEY}" "$URL")
echo "Response: $RESPONSE"

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
echo "Querying GET /metrics..."
METRICS_RESP=$(curl -s -H "X-API-Key: ${QUIVER_DEMO_ADMIN_API_KEY}" "http://localhost:${QUIVER_HOST_PORT}/metrics")
echo "Metrics contains http_requests_total? ..."
if ! echo "$METRICS_RESP" | grep -q 'api_http_requests_total'; then
  echo "ERROR: Missing expected Prometheus metrics."
  exit 1
fi
echo "Metrics verification PASS!"

echo "=================================================="
echo "Verifying ${KAFKA_TOPIC_DLQ} topic has messages..."

EXPECTED_DLQ_COUNT=2

get_dlq_count() {
  local topic="$1"
  local desc

  desc=$(compose exec -T kafka \
    rpk topic describe "$topic" \
    --brokers=localhost:9092 \
    --print-partitions 2>/dev/null || true)

  printf '%s\n' "$desc" | awk '
    BEGIN {
      start_col = 0
      high_col = 0
      total = 0
    }

    /^PARTITION[[:space:]]/ {
      for (i = 1; i <= NF; i++) {
        if ($i == "LOG-START-OFFSET") {
          start_col = i
        }
        if ($i == "HIGH-WATERMARK") {
          high_col = i
        }
      }
      next
    }

    start_col > 0 && high_col > 0 && $1 ~ /^[0-9]+$/ {
      total += ($high_col - $start_col)
    }

    END {
      print total + 0
    }
  '
}

DLQ_COUNT=0
for i in $(seq 1 30); do
  DLQ_COUNT="$(get_dlq_count "${KAFKA_TOPIC_DLQ}")"
  echo "DLQ message count attempt $i/30: $DLQ_COUNT"

  if [ "$DLQ_COUNT" -ge "$EXPECTED_DLQ_COUNT" ]; then
    break
  fi

  sleep 1
done

if [ "$DLQ_COUNT" -lt "$EXPECTED_DLQ_COUNT" ]; then
  echo "ERROR: Expected at least ${EXPECTED_DLQ_COUNT} messages in ${KAFKA_TOPIC_DLQ}, got: ${DLQ_COUNT:-0}"
  echo "Redpanda topic list:"
  compose exec -T kafka rpk topic list --brokers=localhost:9092 || true
  echo "DLQ topic description:"
  compose exec -T kafka rpk topic describe "${KAFKA_TOPIC_DLQ}" --brokers=localhost:9092 --print-partitions || true
  echo "Quiver logs:"
  compose logs quiver || true
  exit 1
fi

echo "DLQ verification PASS!"

echo "=================================================="
echo "DEMO VERIFICATION SUCCESSFUL!"
echo "=================================================="