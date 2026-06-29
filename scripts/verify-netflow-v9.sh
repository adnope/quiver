#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

PROJECT="${COMPOSE_PROJECT_NAME:-quiver-verify-v9}"
COMPOSE_FILE="${VERIFY_COMPOSE_FILE:-docker-compose.verify.yml}"
QUIVER_HOST_PORT="${VERIFY_HOST_PORT:-8237}"
NETFLOW_PORT="${VERIFY_NETFLOW_PORT:-2056}"
COLLECTOR_ID="${VERIFY_NETFLOW_V9_COLLECTOR_ID:-netflow-v9-main}"
SOURCE_HOST="${VERIFY_NETFLOW_GATEWAY_SOURCE_HOST:-netflow-gateway-01}"

QUIVER_DEMO_ADMIN_API_KEY="demoadminkey123"

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

echo "Starting Docker Compose services for NetFlow v9 verification: ${PROJECT}"
compose down -v || true
compose up -d --build

HEALTH_URL="http://localhost:${QUIVER_HOST_PORT}/health"
for attempt in $(seq 1 30); do
  if curl -s --fail "$HEALTH_URL" | grep -q '"status":"ok"'; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    echo "ERROR: Quiver API did not become healthy."
    compose logs
    exit 1
  fi
  sleep 2
done

DETAILS="$(curl -s --fail -H "X-API-Key: ${QUIVER_DEMO_ADMIN_API_KEY}" "$HEALTH_URL")"
if ! echo "$DETAILS" | grep -Fq "\"collector_id\":\"${COLLECTOR_ID}\""; then
  echo "ERROR: detailed health missing collector ${COLLECTOR_ID}"
  echo "$DETAILS"
  exit 1
fi
if ! echo "$DETAILS" | grep -Fq '"type":"netflow_v9"'; then
  echo "ERROR: detailed health missing netflow_v9 type"
  echo "$DETAILS"
  exit 1
fi

echo "Sending NetFlow v9 packets..."
go run tools/netflowv9gen/main.go -target "localhost:${NETFLOW_PORT}" -count 3 -seq 1
go run tools/netflowv9gen/main.go -target "localhost:${NETFLOW_PORT}" -malformed short || true

echo "Waiting for processing..."
sleep 8

FROM_TIME=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
TO_TIME=$(date -u -d '1 hour hence' +%Y-%m-%dT%H:%M:%SZ)
URL="http://localhost:${QUIVER_HOST_PORT}/api/v1/flows?from=${FROM_TIME}&to=${TO_TIME}&source_type=netflow_v9&collector_id=${COLLECTOR_ID}&source_host=${SOURCE_HOST}"
RESPONSE="$(curl -s --fail -H "X-API-Key: ${QUIVER_DEMO_ADMIN_API_KEY}" "$URL")"
echo "Response: $RESPONSE"
if ! echo "$RESPONSE" | grep -Fq "\"collector_id\":\"${COLLECTOR_ID}\""; then
  echo "ERROR: missing NetFlow v9 collector records in query response."
  exit 1
fi
if ! echo "$RESPONSE" | grep -Fq "\"source_host\":\"${SOURCE_HOST}\""; then
  echo "ERROR: missing NetFlow v9 source_host in query response."
  exit 1
fi

METRICS="$(curl -s --fail -H "X-API-Key: ${QUIVER_DEMO_ADMIN_API_KEY}" "http://localhost:${QUIVER_HOST_PORT}/metrics")"
if ! echo "$METRICS" | grep -Fq "collector_events_published_total{collector_id=\"${COLLECTOR_ID}\",source_host=\"${SOURCE_HOST}\",source_type=\"netflow_v9\"}"; then
  echo "ERROR: missing NetFlow v9 publish metric."
  exit 1
fi
if ! echo "$METRICS" | grep -Fq "collector_parse_errors_total{collector_id=\"${COLLECTOR_ID}\",error_code=\"malformed_packet\",source_host=\"${SOURCE_HOST}\",source_type=\"netflow_v9\"}"; then
  echo "ERROR: missing NetFlow v9 parse error metric."
  exit 1
fi

echo "NetFlow v9 verification PASS!"
