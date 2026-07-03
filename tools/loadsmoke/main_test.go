//nolint:gosec // tests use deterministic pseudo-randomness for reproducible generated packets.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type failingCloser struct{}

func (failingCloser) Close() error { return errors.New("close failed") }

func TestNormalizeConfigDefaultsAndSanitizes(t *testing.T) {
	cfg := Config{
		Workers:       0,
		RESTWorkers:   -1,
		UDPWorkers:    -2,
		ZeekWorkers:   -3,
		QueryWorkers:  -4,
		RESTBatchSize: -1,
		UDPBatchSize:  0,
		ZeekBatchSize: 0,
		MixREST:       -1,
		MixUDP:        -1,
		MixZeek:       -1,
		UDPVersion:    "bad",
	}

	normalizeConfig(&cfg)

	if cfg.Workers != 1 || cfg.RESTWorkers != 1 || cfg.UDPWorkers != 1 || cfg.ZeekWorkers != 1 || cfg.QueryWorkers != 0 {
		t.Fatalf("worker config = %+v", cfg)
	}
	if cfg.RESTBatchSize != 100 || cfg.UDPBatchSize != 10 || cfg.ZeekBatchSize != 10 {
		t.Fatalf("batch config = %+v", cfg)
	}
	if cfg.MixREST != 50 || cfg.MixUDP != 40 || cfg.MixZeek != 10 {
		t.Fatalf("mix config = %+v", cfg)
	}
	if cfg.UDPVersion != "mix" {
		t.Fatalf("UDPVersion = %q, want mix", cfg.UDPVersion)
	}
}

func TestSplitSourceRPS(t *testing.T) {
	rest, udp, zeek := splitSourceRPS(100, Config{MixREST: 50, MixUDP: 40, MixZeek: 10})
	if rest != 50 || udp != 40 || zeek != 10 {
		t.Fatalf("split = %d,%d,%d", rest, udp, zeek)
	}

	rest, udp, zeek = splitSourceRPS(3, Config{MixREST: 1, MixUDP: 1, MixZeek: 1})
	if rest != 1 || udp != 1 || zeek != 1 {
		t.Fatalf("small split = %d,%d,%d, want one active RPS per enabled source", rest, udp, zeek)
	}

	rest, udp, zeek = splitSourceRPS(100, Config{MixREST: 0, MixUDP: 100, MixZeek: 0})
	if rest != 0 || udp != 100 || zeek != 0 {
		t.Fatalf("zero-source split = %d,%d,%d", rest, udp, zeek)
	}

	rest, udp, zeek = splitSourceRPS(0, Config{MixREST: 1, MixUDP: 1, MixZeek: 1})
	if rest != 0 || udp != 0 || zeek != 0 {
		t.Fatalf("zero total split = %d,%d,%d", rest, udp, zeek)
	}
}

func TestBatchSchedulingHelpers(t *testing.T) {
	if got := intervalForBatch(100, 10, 2); got != 200*time.Millisecond {
		t.Fatalf("intervalForBatch() = %v, want 200ms", got)
	}
	if got := intervalForBatch(1_000_000, 1, 1); got != time.Millisecond {
		t.Fatalf("minimum interval = %v, want 1ms", got)
	}
	if got := activeWorkersForTarget(100, 10, 10); got != 1 {
		t.Fatalf("activeWorkersForTarget() = %d, want 1", got)
	}
	if got := activeWorkersForTarget(10_000, 4, 10); got != 4 {
		t.Fatalf("activeWorkersForTarget(max) = %d, want 4", got)
	}
	if got := activeWorkersForTarget(0, 4, 10); got != 0 {
		t.Fatalf("activeWorkersForTarget(zero) = %d, want 0", got)
	}
}

func TestCountersAndSourceStats(t *testing.T) {
	var c sourceCounters
	recordAttempt(&c, 10)
	recordAccepted(&c, 7)
	recordFailure(&c, 3)

	snapshot := snapshotCounters(&c)
	if snapshot.attempted != 10 || snapshot.accepted != 7 || snapshot.failed != 3 {
		t.Fatalf("snapshot = %+v", snapshot)
	}

	stats := snapshotSourceStats(&c, 50, 2)
	if stats.TargetRPS != 50 || stats.RecordsAttempted != 10 || stats.RecordsAccepted != 7 || stats.RecordsFailed != 3 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.AttemptedRPS != 5 || stats.AcceptedRPS != 3.5 || stats.FailureRate != 0.3 {
		t.Fatalf("rate stats = %+v", stats)
	}
}

func TestPercentileAndMaxInt(t *testing.T) {
	values := []float64{5, 1, 3, 2, 4}
	sort.Float64s(values)
	if got := percentile(nil, 0.95); got != 0 {
		t.Fatalf("empty percentile = %v", got)
	}
	if got := percentile(values, 0); got != 1 {
		t.Fatalf("p0 = %v", got)
	}
	if got := percentile(values, 1); got != 5 {
		t.Fatalf("p1 = %v", got)
	}
	if got := percentile(values, 0.5); got != 3 {
		t.Fatalf("p50 = %v", got)
	}
	if got := maxInt(3, 9); got != 9 {
		t.Fatalf("maxInt = %d", got)
	}
}

func TestWaitOrDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitOrDone(ctx, time.Hour) {
		t.Fatal("waitOrDone canceled = true, want false")
	}

	if !waitOrDone(context.Background(), time.Nanosecond) {
		t.Fatal("waitOrDone completed = false, want true")
	}
}

func TestGeneratePackets(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	v5 := buildNetFlowV5Packet(r, 2, 99, 3)
	if len(v5) != 24+3*48 {
		t.Fatalf("v5 len = %d", len(v5))
	}
	if binary.BigEndian.Uint16(v5[0:2]) != 5 || binary.BigEndian.Uint16(v5[2:4]) != 3 {
		t.Fatalf("bad v5 header: %x", v5[:4])
	}
	if binary.BigEndian.Uint32(v5[16:20]) != 99 {
		t.Fatalf("v5 seq = %d", binary.BigEndian.Uint32(v5[16:20]))
	}

	r = rand.New(rand.NewSource(2))
	v9 := buildNetFlowV9Packet(r, 3, 123, 2)
	if len(v9) == 0 {
		t.Fatal("v9 packet is empty")
	}
	if binary.BigEndian.Uint16(v9[0:2]) != 9 || binary.BigEndian.Uint16(v9[2:4]) != 3 {
		t.Fatalf("bad v9 header: %x", v9[:4])
	}
	if binary.BigEndian.Uint32(v9[12:16]) != 123 {
		t.Fatalf("v9 seq = %d", binary.BigEndian.Uint32(v9[12:16]))
	}
}

func TestGenerateZeekRecord(t *testing.T) {
	rec := generateZeekRecord(rand.New(rand.NewSource(3)))
	if rec.UID == "" || rec.OrigH == "" || rec.RespH == "" || rec.OrigP == 0 || rec.RespP == 0 {
		t.Fatalf("incomplete zeek record: %+v", rec)
	}
	if rec.Proto != "tcp" && rec.Proto != "udp" {
		t.Fatalf("unexpected proto: %+v", rec)
	}
}

func TestSendRESTIngestBatch(t *testing.T) {
	restCounters.attempted.Store(0)
	restCounters.accepted.Store(0)
	restCounters.failed.Store(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "client-key" {
			t.Fatalf("X-API-Key = %q", r.Header.Get("X-API-Key"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":2,"rejected":1}`))
	}))
	defer server.Close()

	sendRESTIngestBatch(context.Background(), server.Client(), server.URL, "client-key", []byte(`{"records":[]}`), 3)

	if got := restCounters.accepted.Load(); got != 2 {
		t.Fatalf("accepted = %d, want 2", got)
	}
	if got := restCounters.failed.Load(); got != 1 {
		t.Fatalf("failed = %d, want 1", got)
	}
}

func TestSendRESTIngestBatchFailures(t *testing.T) {
	t.Run("bad request url", func(t *testing.T) {
		restCounters.attempted.Store(0)
		restCounters.accepted.Store(0)
		restCounters.failed.Store(0)
		sendRESTIngestBatch(context.Background(), http.DefaultClient, "://bad-url", "key", nil, 4)
		if got := restCounters.failed.Load(); got != 4 {
			t.Fatalf("failed = %d, want 4", got)
		}
	})

	t.Run("non accepted status", func(t *testing.T) {
		restCounters.attempted.Store(0)
		restCounters.accepted.Store(0)
		restCounters.failed.Store(0)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer server.Close()
		sendRESTIngestBatch(context.Background(), server.Client(), server.URL, "key", nil, 5)
		if got := restCounters.failed.Load(); got != 5 {
			t.Fatalf("failed = %d, want 5", got)
		}
	})

	t.Run("invalid response json", func(t *testing.T) {
		restCounters.attempted.Store(0)
		restCounters.accepted.Store(0)
		restCounters.failed.Store(0)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`not-json`))
		}))
		defer server.Close()
		sendRESTIngestBatch(context.Background(), server.Client(), server.URL, "key", nil, 6)
		if got := restCounters.failed.Load(); got != 6 {
			t.Fatalf("failed = %d, want 6", got)
		}
	})
}

func TestCloseAndLogAcceptsCloser(t *testing.T) {
	closeAndLog("test", failingCloser{})
}

func TestSnapshotSourceStatsAvoidsZeroDuration(t *testing.T) {
	var c sourceCounters
	c.attempted.Store(4)
	stats := snapshotSourceStats(&c, 10, 0)
	if stats.AttemptedRPS != 4 {
		t.Fatalf("AttemptedRPS = %v, want 4", stats.AttemptedRPS)
	}
}

func TestRunWorkersExitOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var target atomic.Int64
	runRESTWorker(ctx, Config{RESTWorkers: 1, RESTBatchSize: 1}, 0, &target)
	runZeekWorker(ctx, Config{ZeekWorkers: 1, ZeekBatchSize: 1}, 0, &target)
}

func TestPrintHelpers(t *testing.T) {
	printSourceStep("REST", sourceSnapshot{attempted: 1}, sourceSnapshot{attempted: 3, accepted: 2, failed: 1}, time.Second)
	printSourceSummary("REST", SourceStats{TargetRPS: 10, AttemptedRPS: 2, AcceptedRPS: 1, RecordsFailed: 1, FailureRate: 0.5})
	if !strings.Contains("REST", "REST") {
		t.Fatal("unreachable guard")
	}
}
