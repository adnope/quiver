package zeekconntcp

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
)

func TestCollectorPublishesValidTCPZeekLine(t *testing.T) {
	t.Parallel()

	publisher := newTCPTestPublisher()
	c := newRunningTestCollector(t, publisher)
	conn := dialCollector(t, c)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	if _, err := fmt.Fprintf(conn, "X-API-Key: zeek-key\n%s\n", validTCPZeekLine()); err != nil {
		t.Fatalf("write zeek line: %v", err)
	}

	event := publisher.waitRaw(t)
	if event.GetSource().GetCollectorId() != "zeek-conn-tcp-main" {
		t.Fatalf("collector_id = %q", event.GetSource().GetCollectorId())
	}
	if event.GetSource().GetSourceHost() != "zeek-probe-01" {
		t.Fatalf("source_host = %q", event.GetSource().GetSourceHost())
	}
	if event.GetPayload().GetZeekConn().GetUid() != "Ctcp001" {
		t.Fatalf("uid = %q", event.GetPayload().GetZeekConn().GetUid())
	}
}

func TestCollectorPublishesDLQAndKeepsConnectionAlive(t *testing.T) {
	t.Parallel()

	publisher := newTCPTestPublisher()
	c := newRunningTestCollector(t, publisher)
	conn := dialCollector(t, c)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	if _, err := fmt.Fprintf(conn, "X-API-Key: zeek-key\n"); err != nil {
		t.Fatalf("write auth preface: %v", err)
	}
	if _, err := fmt.Fprintf(conn, "{bad-json\n"); err != nil {
		t.Fatalf("write malformed line: %v", err)
	}
	_ = publisher.waitDLQ(t)
	if _, err := fmt.Fprintf(conn, "%s\n", validTCPZeekLine()); err != nil {
		t.Fatalf("write valid line: %v", err)
	}
	event := publisher.waitRaw(t)
	if event.GetPayload().GetZeekConn().GetUid() != "Ctcp001" {
		t.Fatalf("uid = %q", event.GetPayload().GetZeekConn().GetUid())
	}
}

func newRunningTestCollector(t *testing.T, publisher *tcpTestPublisher) *Collector {
	t.Helper()

	c, err := NewCollector(CollectorConfig{
		CollectorID: "zeek-conn-tcp-main",
		Settings: settings{
			ListenAddr:     "127.0.0.1:0",
			MaxConnections: 4,
			AuthTimeout:    config.Duration(time.Second),
			IdleTimeout:    config.Duration(5 * time.Second),
			MaxLineBytes:   4096,
			BatchSize:      1,
			FlushInterval:  config.Duration(10 * time.Millisecond),
		},
		DeadLetterMaxBytes: 1500,
	}, publisher, testAuthenticator(t), nil, nil)
	if err != nil {
		t.Fatalf("NewCollector() error = %v", err)
	}
	if err := c.Open(context.Background()); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = c.Close(context.Background())
	})
	go func() {
		_ = c.Run(ctx)
	}()
	return c
}

func dialCollector(t *testing.T, c *Collector) net.Conn {
	t.Helper()

	c.listenerMu.Lock()
	addr := c.listener.Addr().String()
	c.listenerMu.Unlock()
	dialer := &net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("DialTimeout() error = %v", err)
	}
	return conn
}

func validTCPZeekLine() string {
	return `{"ts":1718532921.25,"uid":"Ctcp001","id.orig_h":"192.168.1.50","id.orig_p":49152,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","service":"dns","duration":0.045,"orig_bytes":42,"resp_bytes":84,"orig_pkts":1,"resp_pkts":1,"conn_state":"SF"}`
}

type tcpTestPublisher struct {
	raw chan *flowv1.RawFlowEventEnvelope
	dlq chan *flowv1.DeadLetterEvent
}

func newTCPTestPublisher() *tcpTestPublisher {
	return &tcpTestPublisher{
		raw: make(chan *flowv1.RawFlowEventEnvelope, 16),
		dlq: make(chan *flowv1.DeadLetterEvent, 16),
	}
}

func (p *tcpTestPublisher) PublishRaw(_ context.Context, event *flowv1.RawFlowEventEnvelope) error {
	p.raw <- event
	return nil
}

func (p *tcpTestPublisher) PublishDeadLetter(_ context.Context, event *flowv1.DeadLetterEvent) error {
	p.dlq <- event
	return nil
}

func (p *tcpTestPublisher) Flush(context.Context) error {
	return nil
}

func (p *tcpTestPublisher) waitRaw(t *testing.T) *flowv1.RawFlowEventEnvelope {
	t.Helper()

	select {
	case event := <-p.raw:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for raw event")
		return nil
	}
}

func (p *tcpTestPublisher) waitDLQ(t *testing.T) *flowv1.DeadLetterEvent {
	t.Helper()

	select {
	case event := <-p.dlq:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for dead-letter event")
		return nil
	}
}

var _ kafka.RawEventPublisher = (*tcpTestPublisher)(nil)
