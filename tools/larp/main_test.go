package main

import (
	"strings"
	"testing"
	"time"
)

func TestBuildIdempotencyKeyLocal(t *testing.T) {
	t.Parallel()

	srcPort := uint16(12345)
	dstPort := uint16(443)
	bytesVal := uint64(1000)
	packetsVal := uint64(10)
	start := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	key1 := buildIdempotencyKeyLocal(start, "192.168.1.10", "8.8.8.8", &srcPort, &dstPort, &bytesVal, &packetsVal)
	key2 := buildIdempotencyKeyLocal(start, "192.168.1.10", "8.8.8.8", &srcPort, &dstPort, &bytesVal, &packetsVal)
	if key1 != key2 {
		t.Fatalf("idempotency key is not deterministic")
	}
	if !strings.HasPrefix(key1, "sha256:") || len(key1) != len("sha256:")+64 {
		t.Fatalf("key format = %q", key1)
	}
}

func TestFormatOptionalValues(t *testing.T) {
	t.Parallel()

	port := uint16(443)
	bytesVal := uint64(2048)
	if got := formatOptionalUint16(nil); got != "" {
		t.Fatalf("nil uint16 = %q", got)
	}
	if got := formatOptionalUint16(&port); got != "443" {
		t.Fatalf("uint16 = %q", got)
	}
	if got := formatOptionalUint64(nil); got != "" {
		t.Fatalf("nil uint64 = %q", got)
	}
	if got := formatOptionalUint64(&bytesVal); got != "2048" {
		t.Fatalf("uint64 = %q", got)
	}
}
