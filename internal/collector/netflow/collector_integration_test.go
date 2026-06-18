//go:build integration

package netflow

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
)

func TestNetFlowCollectorIntegrationUDP(t *testing.T) {
	publisher := &fakeIntegrationPublisher{}
	addr := "127.0.0.1:22055"

	cfg := config.NetFlowV5CollectorConfig{
		Enabled:         true,
		CollectorID:     "netflow-integration-01",
		ListenAddr:      addr,
		ReadBufferBytes: 1024,
		AllowedSources: []config.NetFlowAllowedSource{{
			SourceIP:     "127.0.0.1",
			SourceHost:   "router-test-host",
			SamplingRate: 1,
		}},
	}

	collector, err := NewCollector(cfg, 1500, publisher, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create NetFlow collector: %v", err)
	}
	collector.now = func() time.Time { return time.Date(2026, 6, 18, 2, 0, 0, 0, time.UTC) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start UDP server loop in a goroutine
	go func() {
		_ = collector.Run(ctx)
	}()

	// Give the UDP listener a moment to start
	time.Sleep(100 * time.Millisecond)

	// Send NetFlow UDP packet
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("Failed to dial collector UDP: %v", err)
	}
	defer conn.Close()

	packet := validV5Packet(101, 1)
	_, err = conn.Write(packet)
	if err != nil {
		t.Fatalf("Failed to send UDP packet: %v", err)
	}

	// Wait and verify publisher received the parsed flow event
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		publisher.mu.Lock()
		count := len(publisher.raw)
		publisher.mu.Unlock()
		if count > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if len(publisher.raw) != 1 {
		t.Fatalf("Expected 1 published record, got %d. Did the UDP packet reach the collector?", len(publisher.raw))
	}

	event := publisher.raw[0]
	if event.GetSource().GetSourceHost() != "router-test-host" {
		t.Errorf("Unexpected source host: %s", event.GetSource().GetSourceHost())
	}
	if event.GetPayload().GetNetflowV5().GetPacketSequence() != 101 {
		t.Errorf("Unexpected sequence: %d", event.GetPayload().GetNetflowV5().GetPacketSequence())
	}
}

type fakeIntegrationPublisher struct {
	mu          sync.Mutex
	raw         []*flowv1.RawFlowEventEnvelope
	deadLetters []*flowv1.DeadLetterEvent
}

func (p *fakeIntegrationPublisher) PublishRaw(ctx context.Context, event *flowv1.RawFlowEventEnvelope) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raw = append(p.raw, event)
	return nil
}

func (p *fakeIntegrationPublisher) PublishDeadLetter(ctx context.Context, event *flowv1.DeadLetterEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deadLetters = append(p.deadLetters, event)
	return nil
}

func (p *fakeIntegrationPublisher) Flush(ctx context.Context) error {
	return nil
}

var _ kafka.RawEventPublisher = (*fakeIntegrationPublisher)(nil)
