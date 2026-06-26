#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

PROJECT="${COMPOSE_PROJECT_NAME:-quiver-verify-zeek-tcp}"
COMPOSE_FILE="${VERIFY_COMPOSE_FILE:-docker-compose.verify.yml}"
QUIVER_HOST_PORT="${VERIFY_HOST_PORT:-8237}"
ZEEK_TCP_PORT="${VERIFY_ZEEK_TCP_PORT:-4771}"
COLLECTOR_ID="${VERIFY_ZEEK_TCP_COLLECTOR_ID:-zeek-conn-tcp-main}"
SOURCE_HOST="${VERIFY_ZEEK_TCP_SOURCE_HOST:-zeek-probe-01}"

QUIVER_DEMO_ADMIN_API_KEY="demoadminkey123"
ZEEK_SHIPPER_DEMO_KEY="zeekshipperkey456"

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

echo "Starting Docker Compose services for Zeek TCP verification: ${PROJECT}"
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
if ! echo "$DETAILS" | grep -Fq '"type":"zeek_conn_tcp"'; then
  echo "ERROR: detailed health missing zeek_conn_tcp type"
  echo "$DETAILS"
  exit 1
fi

echo "Sending Zeek TCP records..."
go run tools/zeektcpsend/main.go -target "localhost:${ZEEK_TCP_PORT}" -key "${ZEEK_SHIPPER_DEMO_KEY}" -count 5
go run tools/zeektcpsend/main.go -target "localhost:${ZEEK_TCP_PORT}" -key "${ZEEK_SHIPPER_DEMO_KEY}" -malformed || true

echo "Waiting for processing..."
sleep 8

FROM_TIME=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
TO_TIME=$(date -u -d '1 hour hence' +%Y-%m-%dT%H:%M:%SZ)
URL="http://localhost:${QUIVER_HOST_PORT}/api/v1/flows?from=${FROM_TIME}&to=${TO_TIME}&source_type=zeek_conn_json&collector_id=${COLLECTOR_ID}&source_host=${SOURCE_HOST}"
RESPONSE="$(curl -s --fail -H "X-API-Key: ${QUIVER_DEMO_ADMIN_API_KEY}" "$URL")"
echo "Response: $RESPONSE"
if ! echo "$RESPONSE" | grep -Fq "\"collector_id\":\"${COLLECTOR_ID}\""; then
  echo "ERROR: missing TCP Zeek collector records in query response."
  exit 1
fi
if ! echo "$RESPONSE" | grep -Fq "\"source_host\":\"${SOURCE_HOST}\""; then
  echo "ERROR: missing TCP Zeek source_host in query response."
  exit 1
fi

METRICS="$(curl -s --fail -H "X-API-Key: ${QUIVER_DEMO_ADMIN_API_KEY}" "http://localhost:${QUIVER_HOST_PORT}/metrics")"
if ! echo "$METRICS" | grep -Fq "collector_events_published_total{collector_id=\"${COLLECTOR_ID}\",source_host=\"${SOURCE_HOST}\",source_type=\"zeek_conn_json\"}"; then
  echo "ERROR: missing Zeek TCP publish metric."
  exit 1
fi
if ! echo "$METRICS" | grep -Fq "collector_parse_errors_total{collector_id=\"${COLLECTOR_ID}\",error_code=\"invalid_zeek_conn\",source_host=\"${SOURCE_HOST}\",source_type=\"zeek_conn_json\"}"; then
  echo "ERROR: missing Zeek TCP parse error metric."
  exit 1
fi

echo "Zeek TCP verification PASS!"
