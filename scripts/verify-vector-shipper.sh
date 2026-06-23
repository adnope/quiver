#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vector_image="${VECTOR_IMAGE:-timberio/vector:0.56.0-alpine}"
timeout_secs="${VECTOR_VERIFY_TIMEOUT_SECS:-30}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
server_pid=""
vector_pid=""

cleanup() {
  if [[ -n "${vector_pid}" ]]; then
    kill "${vector_pid}" >/dev/null 2>&1 || true
    wait "${vector_pid}" >/dev/null 2>&1 || true
  fi

  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
  fi

  rm -rf "${tmpdir}"
}
trap cleanup EXIT

vector_config="${tmpdir}/vector.yaml"
body_file="${tmpdir}/body.json"
headers_file="${tmpdir}/headers.txt"
port_file="${tmpdir}/server.port"
server_log="${tmpdir}/server.log"
vector_log="${tmpdir}/vector.log"

python3 - "${body_file}" "${headers_file}" "${port_file}" >"${server_log}" 2>&1 <<'PY' &
import http.server
import sys

body_file, headers_file, port_file = sys.argv[1:4]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)

        with open(headers_file, "w", encoding="utf-8") as f:
            for key, value in self.headers.items():
                f.write(f"{key}: {value}\n")

        with open(body_file, "wb") as f:
            f.write(body)

        self.send_response(202)
        self.end_headers()

    def log_message(self, *_):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "w", encoding="utf-8") as f:
    f.write(str(server.server_port))
server.serve_forever()
PY
server_pid="$!"

for _ in $(seq 1 50); do
  if [[ -s "${port_file}" ]]; then
    break
  fi
  sleep 0.1
done

if [[ ! -s "${port_file}" ]]; then
  echo "capture server did not start" >&2
  sed -n '1,120p' "${server_log}" >&2 || true
  exit 1
fi

port="$(cat "${port_file}")"
endpoint="http://127.0.0.1:${port}/api/v1/ingest/zeek/conn"

cat >"${vector_config}" <<'YAML'
data_dir: /var/lib/vector

sources:
  zeek_conn_log:
    type: exec
    mode: scheduled
    command:
      - /bin/sh
      - -c
      - "printf '%s\n' '{\"ts\":1700000000.0,\"uid\":\"C1\",\"id.orig_h\":\"10.0.0.1\",\"id.orig_p\":12345,\"id.resp_h\":\"10.0.0.2\",\"id.resp_p\":443,\"proto\":\"tcp\"}'"
    scheduled:
      exec_interval_secs: 60
    decoding:
      codec: bytes
    include_stderr: false

transforms:
  quiver_zeek_record:
    type: remap
    inputs:
      - zeek_conn_log
    drop_on_error: false
    source: |-
      line = string!(.message)
      parsed, err = parse_json(line)
      if err == null {
        . = parsed
      } else {
        . = { "raw": line }
      }

sinks:
  quiver_zeek_ingest:
    type: http
    inputs:
      - quiver_zeek_record
    uri: "${QUIVER_ZEEK_INGEST_URL}"
    method: post

    request:
      timeout_secs: 30
      retry_initial_backoff_secs: 1
      retry_max_duration_secs: 30
      headers:
        Content-Type: application/json
        X-API-Key: "${ZEEK_SHIPPER_API_KEY}"

    batch:
      max_events: 500
      max_bytes: 4194304
      timeout_secs: 1

    buffer:
      type: memory
      max_events: 500
      when_full: block

    encoding:
      codec: json

    payload_prefix: '{"records":'
    payload_suffix: '}'
YAML

echo "Starting Vector capture test"
echo "  image: ${vector_image}"
echo "  endpoint: ${endpoint}"
echo "  production config: ${repo_root}/vector.yaml"
echo "  verification config: ${vector_config}"

docker run --rm \
  -e ZEEK_SHIPPER_API_KEY=test-vector-key \
  -e QUIVER_ZEEK_INGEST_URL="${endpoint}" \
  -e VECTOR_ZEEK_LOG_PATH=/tmp/conn.log \
  -v "${repo_root}/vector.yaml:/etc/vector/vector.yaml:ro" \
  "${vector_image}" \
  --config /etc/vector/vector.yaml validate >/dev/null

docker run --rm --network host \
  -e ZEEK_SHIPPER_API_KEY=test-vector-key \
  -e QUIVER_ZEEK_INGEST_URL="${endpoint}" \
  -v "${vector_config}:/etc/vector/vector.yaml:ro" \
  "${vector_image}" \
  --graceful-shutdown-limit-secs 1 \
  --config /etc/vector/vector.yaml >"${vector_log}" 2>&1 &
vector_pid="$!"

deadline=$((SECONDS + timeout_secs))
while [[ ! -s "${body_file}" && "${SECONDS}" -lt "${deadline}" ]]; do
  sleep 1
done

if [[ ! -s "${body_file}" ]]; then
  echo "Vector did not POST a body within ${timeout_secs}s" >&2
  echo
  echo "Vector log:" >&2
  sed -n '1,220p' "${vector_log}" >&2 || true
  echo
  echo "Server log:" >&2
  sed -n '1,120p' "${server_log}" >&2 || true
  exit 1
fi

echo
echo "Captured request headers:"
sed -n '1,120p' "${headers_file}"

echo
echo "Captured raw body:"
cat "${body_file}"
echo

echo
echo "Parsed/validated body:"
python3 - "${body_file}" <<'PY'
import json
import sys

with open(sys.argv[1], "rb") as f:
    payload = json.load(f)

if not isinstance(payload, dict):
    raise SystemExit(f"expected top-level object, got {type(payload).__name__}")

records = payload.get("records")
if not isinstance(records, list):
    raise SystemExit("expected records array")

if len(records) != 1:
    raise SystemExit(f"expected exactly 1 record, got {len(records)}")

record = records[0]
if not isinstance(record, dict):
    raise SystemExit(f"expected record object, got {type(record).__name__}")

required = {
    "ts": 1700000000.0,
    "uid": "C1",
    "id.orig_h": "10.0.0.1",
    "id.orig_p": 12345,
    "id.resp_h": "10.0.0.2",
    "id.resp_p": 443,
    "proto": "tcp",
}
for key, expected in required.items():
    actual = record.get(key)
    if actual != expected:
        raise SystemExit(f"record[{key!r}] expected {expected!r}, got {actual!r}")

print(json.dumps(payload, indent=2, sort_keys=True))
print("shape_ok")
PY

echo
echo "Vector shipper batch format is valid."
