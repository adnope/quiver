package netflow

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/observability"
)

func TestCollectorPublishesAllowedPacketAndTracksSequenceGap(t *testing.T) {
	t.Parallel()

	publisher := &fakePublisher{}
	metrics := observability.NewRegistry()
	collector := newTestCollector(t, publisher, metrics)
	sourceIP := netip.MustParseAddr("10.10.0.1")

	if err := collector.HandlePacket(context.Background(), sourceIP, "", validV5Packet(10, 1)); err != nil {
		t.Fatalf("HandlePacket(first) error = %v", err)
	}
	if err := collector.HandlePacket(context.Background(), sourceIP, "", validV5Packet(12, 1)); err != nil {
		t.Fatalf("HandlePacket(gap) error = %v", err)
	}
	if len(publisher.raw) != 2 {
		t.Fatalf("raw events = %d, want 2", len(publisher.raw))
	}
	event := publisher.raw[0]
	if event.GetSource().GetSourceHost() != "netflow-v5-10.10.0.1" || event.GetSource().GetSourceIp() != "10.10.0.1" {
		t.Fatalf("source identity = %+v", event.GetSource())
	}
	body := string(metrics.WritePrometheus())
	if !strings.Contains(body, `netflow_sequence_gaps_total{collector_id="netflow-test",source_host="netflow-v5-10.10.0.1",source_type="netflow_v5"} 1`) {
		t.Fatalf("metrics missing sequence gap:\n%s", body)
	}
}

func TestCollectorDropsUnauthenticatedPacketWhenAuthRequired(t *testing.T) {
	t.Parallel()

	publisher := &fakePublisher{}
	metrics := observability.NewRegistry()
	collector := newTestCollector(t, publisher, metrics)
	collector.cfg.AuthRequired = true // Enable authentication requirement

	// Call HandlePacket with empty sourceHost (unauthenticated/direct)
	if err := collector.HandlePacket(context.Background(), netip.MustParseAddr("10.10.0.1"), "", validV5Packet(10, 1)); err != nil {
		t.Fatalf("HandlePacket() error = %v", err)
	}
	if len(publisher.raw) != 0 || len(publisher.deadLetters) != 0 {
		t.Fatalf("raw=%d dlq=%d, want packet drop only", len(publisher.raw), len(publisher.deadLetters))
	}
	if !strings.Contains(string(metrics.WritePrometheus()), `reason="auth_required"`) {
		t.Fatalf("missing auth_required metric:\n%s", metrics.WritePrometheus())
	}
}

func TestCollectorPublishesDLQForUnsupportedVersion(t *testing.T) {
	t.Parallel()

	publisher := &fakePublisher{}
	collector := newTestCollector(t, publisher, nil)
	packet := bytes.Repeat([]byte{0xab}, 64)
	binary.BigEndian.PutUint16(packet[0:2], 9)

	if err := collector.HandlePacket(context.Background(), netip.MustParseAddr("10.10.0.1"), "", packet); err != nil {
		t.Fatalf("HandlePacket() error = %v", err)
	}
	if len(publisher.deadLetters) != 1 {
		t.Fatalf("dead letters = %d, want 1", len(publisher.deadLetters))
	}
	debug := publisher.deadLetters[0].GetRawPayloadDebug()
	if publisher.deadLetters[0].GetError().GetErrorCode() != "unsupported_version" {
		t.Fatalf("error code = %q", publisher.deadLetters[0].GetError().GetErrorCode())
	}
	if !debug.GetMasked() || !debug.GetTruncated() || len(debug.GetData()) != 16 {
		t.Fatalf("debug payload = masked:%v truncated:%v len:%d", debug.GetMasked(), debug.GetTruncated(), len(debug.GetData()))
	}
}

func TestCollectorQueueFullDropsUDPRecordWithoutDLQ(t *testing.T) {
	t.Parallel()

	publisher := &fakePublisher{publishErr: kafka.ErrQueueFull}
	metrics := observability.NewRegistry()
	collector := newTestCollector(t, publisher, metrics)

	if err := collector.HandlePacket(context.Background(), netip.MustParseAddr("10.10.0.1"), "", validV5Packet(10, 1)); err != nil {
		t.Fatalf("HandlePacket() error = %v", err)
	}
	if len(publisher.deadLetters) != 0 {
		t.Fatalf("dead letters = %d, want 0", len(publisher.deadLetters))
	}
	if !strings.Contains(string(metrics.WritePrometheus()), `collector_dropped_events_total`) {
		t.Fatalf("missing drop metric:\n%s", metrics.WritePrometheus())
	}
}

func TestCollectorPropagatesNonQueuePublishError(t *testing.T) {
	t.Parallel()

	publisher := &fakePublisher{publishErr: errors.New("broker unavailable")}
	collector := newTestCollector(t, publisher, nil)

	err := collector.HandlePacket(context.Background(), netip.MustParseAddr("10.10.0.1"), "", validV5Packet(10, 1))
	if err == nil {
		t.Fatal("expected publish error")
	}
}

func newTestCollector(t *testing.T, publisher *fakePublisher, metrics *observability.Registry) *Collector {
	t.Helper()

	collector, err := NewCollector(CollectorConfig{
		CollectorID:       "netflow-test",
		ListenAddr:        "127.0.0.1:2055",
		ReadBufferBytes:   4096,
		PacketBufferBytes: 1500,
		AuthRequired:      false,
	}, 16, publisher, metrics, slog.Default())
	if err != nil {
		t.Fatalf("NewCollector() error = %v", err)
	}
	collector.now = func() time.Time { return time.Date(2026, 6, 18, 1, 0, 0, 0, time.UTC) }
	return collector
}

type fakePublisher struct {
	mu          sync.Mutex
	raw         []*flowv1.RawFlowEventEnvelope
	deadLetters []*flowv1.DeadLetterEvent
	publishErr  error
}

func (p *fakePublisher) PublishRaw(_ context.Context, event *flowv1.RawFlowEventEnvelope) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.publishErr != nil {
		return p.publishErr
	}
	p.raw = append(p.raw, event)
	return nil
}

func (p *fakePublisher) PublishDeadLetter(_ context.Context, event *flowv1.DeadLetterEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deadLetters = append(p.deadLetters, event)
	return nil
}

func (p *fakePublisher) Flush(context.Context) error {
	return nil
}

var _ kafka.RawEventPublisher = (*fakePublisher)(nil)

func TestCollectorPublishesDLQForShortPacket(t *testing.T) {
	t.Parallel()

	publisher := &fakePublisher{}
	collector := newTestCollector(t, publisher, nil)
	packet := []byte{0x00, 0x05, 0x00, 0x01} // too short

	if err := collector.HandlePacket(context.Background(), netip.MustParseAddr("10.10.0.1"), "", packet); err != nil {
		t.Fatalf("HandlePacket() error = %v", err)
	}
	if len(publisher.deadLetters) != 1 {
		t.Fatalf("dead letters = %d, want 1", len(publisher.deadLetters))
	}
	if publisher.deadLetters[0].GetError().GetErrorCode() != "malformed_packet" {
		t.Fatalf("error code = %q", publisher.deadLetters[0].GetError().GetErrorCode())
	}
	if !strings.Contains(publisher.deadLetters[0].GetError().GetErrorMessage(), "packet too short") {
		t.Fatalf("error message = %q", publisher.deadLetters[0].GetError().GetErrorMessage())
	}
}

func TestCollectorPublishesDLQForBadRecordCount(t *testing.T) {
	t.Parallel()

	publisher := &fakePublisher{}
	collector := newTestCollector(t, publisher, nil)

	// Case 1: Count is 0
	p1 := validV5Packet(1, 0)
	if err := collector.HandlePacket(context.Background(), netip.MustParseAddr("10.10.0.1"), "", p1); err != nil {
		t.Fatalf("HandlePacket(0) error = %v", err)
	}

	// Case 2: Count is 31
	p2 := validV5Packet(1, 31)
	if err := collector.HandlePacket(context.Background(), netip.MustParseAddr("10.10.0.1"), "", p2); err != nil {
		t.Fatalf("HandlePacket(31) error = %v", err)
	}

	// Case 3: Count/length mismatch
	p3 := validV5Packet(1, 2)
	p3 = p3[:len(p3)-10]
	if err := collector.HandlePacket(context.Background(), netip.MustParseAddr("10.10.0.1"), "", p3); err != nil {
		t.Fatalf("HandlePacket(mismatch) error = %v", err)
	}

	if len(publisher.deadLetters) != 3 {
		t.Fatalf("dead letters = %d, want 3", len(publisher.deadLetters))
	}
	for i, dlq := range publisher.deadLetters {
		if dlq.GetError().GetErrorCode() != "malformed_packet" {
			t.Fatalf("idx %d error code = %q", i, dlq.GetError().GetErrorCode())
		}
	}
}
