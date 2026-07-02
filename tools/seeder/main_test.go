//nolint:gosec // tests use deterministic pseudo-randomness for reproducible distribution checks.
package main

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestBuildBatchInsertAndCache(t *testing.T) {
	t.Parallel()

	sql := buildBatchInsert(2)
	if !strings.HasPrefix(sql, "INSERT INTO quiver.flow_records") {
		t.Fatalf("unexpected insert prefix: %s", sql)
	}
	if strings.Count(sql, "$") != 66 {
		t.Fatalf("placeholder count = %d, want 66", strings.Count(sql, "$"))
	}
	if !strings.Contains(sql, "$1") || !strings.Contains(sql, "$66") {
		t.Fatalf("missing first/last placeholders: %s", sql)
	}

	cached1 := getInsertSQL(2)
	cached2 := getInsertSQL(2)
	if cached1 != cached2 || cached1 != sql {
		t.Fatalf("cached SQL mismatch")
	}
}

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
	changed := buildIdempotencyKeyLocal(start.Add(time.Second), "192.168.1.10", "8.8.8.8", &srcPort, &dstPort, &bytesVal, &packetsVal)
	if changed == key1 {
		t.Fatal("key did not change when input changed")
	}
}

func TestFormatOptionalValues(t *testing.T) {
	t.Parallel()

	port := uint16(53)
	bytesVal := uint64(4096)
	if got := formatOptionalUint16(nil); got != "" {
		t.Fatalf("nil uint16 = %q", got)
	}
	if got := formatOptionalUint16(&port); got != "53" {
		t.Fatalf("uint16 = %q", got)
	}
	if got := formatOptionalUint64(nil); got != "" {
		t.Fatalf("nil uint64 = %q", got)
	}
	if got := formatOptionalUint64(&bytesVal); got != "4096" {
		t.Fatalf("uint64 = %q", got)
	}
}

func TestDistributeNormal(t *testing.T) {
	t.Parallel()

	if got := distributeNormal(rand.New(rand.NewSource(1)), 100, 0); got != nil {
		t.Fatalf("days <= 0 = %v, want nil", got)
	}
	counts := distributeNormal(rand.New(rand.NewSource(2)), 1000, 5)
	if len(counts) != 5 {
		t.Fatalf("len(counts) = %d, want 5", len(counts))
	}
	for i, count := range counts {
		if count <= 0 {
			t.Fatalf("counts[%d] = %d, want positive", i, count)
		}
	}
}
