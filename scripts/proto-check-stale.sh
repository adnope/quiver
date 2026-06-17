#!/usr/bin/env bash
set -euo pipefail

before="$(mktemp)"
after="$(mktemp)"
trap 'rm -f "$before" "$after"' EXIT

find internal/gen -type f -name '*.pb.go' -print0 2>/dev/null | sort -z | xargs -0 sha256sum >"$before" || true
make proto >/dev/null
find internal/gen -type f -name '*.pb.go' -print0 2>/dev/null | sort -z | xargs -0 sha256sum >"$after" || true

if ! cmp -s "$before" "$after"; then
  printf '%s\n' "generated protobuf files are stale; run make proto"
  exit 1
fi
