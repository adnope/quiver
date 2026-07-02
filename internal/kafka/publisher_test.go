package kafka

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

func TestPublisherPublishRawWaitsForAckAndEmitsProtobufRecord(t *testing.T) {
	t.Parallel()

	writer := newFakeWriter()
	publisher := newTestPublisher(t, writer, 4, 1)

	done := make(chan error, 1)
	go func() {
		done <- publisher.PublishRaw(context.Background(), validRawEvent())
	}()

	writer.waitStarted(t)
	assertNotDone(t, done, "PublishRaw returned before writer ACK")
	writer.ack(nil)

	if err := <-done; err != nil {
		t.Fatalf("PublishRaw() error = %v", err)
	}

	records := writer.records()
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	record := records[0]
	if record.Topic != "flow.raw" {
		t.Fatalf("topic = %q, want flow.raw", record.Topic)
	}
	if string(record.Key) != "netflow-main:router-core-01" {
		t.Fatalf("key = %q, want netflow-main:router-core-01", record.Key)
	}
	if len(record.Value) == 0 || record.Value[0] == '{' {
		t.Fatalf("value looks like JSON, want protobuf bytes: %q", record.Value)
	}
	var decoded flowv1.RawFlowEventEnvelope
	if err := proto.Unmarshal(record.Value, &decoded); err != nil {
		t.Fatalf("unmarshal raw protobuf value: %v", err)
	}
	if decoded.GetEventId() != validRawEvent().GetEventId() {
		t.Fatalf("decoded event_id = %q", decoded.GetEventId())
	}

	headers := headerMap(record.Headers)
	assertHeader(t, headers, "content-type", "application/x-protobuf")
	assertHeader(t, headers, "proto-message", "flow.v1.RawFlowEventEnvelope")
	assertHeader(t, headers, "schema-version", domain.RawSchemaVersion)
	assertHeader(t, headers, "source-type", "SOURCE_TYPE_NETFLOW_V5")
}

func TestPublisherPublishDeadLetterWaitsForAck(t *testing.T) {
	t.Parallel()

	writer := newFakeWriter()
	publisher := newTestPublisher(t, writer, 4, 1)

	done := make(chan error, 1)
	go func() {
		done <- publisher.PublishDeadLetter(context.Background(), validDeadLetterEvent())
	}()

	writer.waitStarted(t)
	assertNotDone(t, done, "PublishDeadLetter returned before writer ACK")
	writer.ack(nil)

	if err := <-done; err != nil {
		t.Fatalf("PublishDeadLetter() error = %v", err)
	}

	records := writer.records()
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	record := records[0]
	if record.Topic != "flow.dead_letter" {
		t.Fatalf("topic = %q, want flow.dead_letter", record.Topic)
	}
	if string(record.Key) != "netflow-main:router-core-01" {
		t.Fatalf("key = %q", record.Key)
	}
	var decoded flowv1.DeadLetterEvent
	if err := proto.Unmarshal(record.Value, &decoded); err != nil {
		t.Fatalf("unmarshal dead-letter protobuf value: %v", err)
	}
	if decoded.GetDeadLetterId() != validDeadLetterEvent().GetDeadLetterId() {
		t.Fatalf("decoded dead_letter_id = %q", decoded.GetDeadLetterId())
	}
	assertHeader(t, headerMap(record.Headers), "proto-message", "flow.v1.DeadLetterEvent")
}

func TestPublisherQueueFullIsTestable(t *testing.T) {
	t.Parallel()

	writer := newFakeWriter()
	publisher := newTestPublisher(t, writer, 1, 1)

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- publisher.PublishRaw(context.Background(), validRawEvent())
	}()
	writer.waitStarted(t)

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- publisher.PublishRaw(context.Background(), validRawEvent())
	}()
	waitQueueLen(t, publisher, 1)

	err := publisher.PublishRaw(context.Background(), validRawEvent())
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("PublishRaw() error = %v, want ErrQueueFull", err)
	}

	writer.ack(nil)
	if err := <-firstDone; err != nil {
		t.Fatalf("first PublishRaw() error = %v", err)
	}
	writer.waitStarted(t)
	writer.ack(nil)
	if err := <-secondDone; err != nil {
		t.Fatalf("second PublishRaw() error = %v", err)
	}
}

func TestPublisherPropagatesWriterErrorAndContextCancellation(t *testing.T) {
	t.Parallel()

	writer := newFakeWriter()
	publisher := newTestPublisher(t, writer, 4, 1)

	done := make(chan error, 1)
	go func() {
		done <- publisher.PublishRaw(context.Background(), validRawEvent())
	}()
	writer.waitStarted(t)
	writer.ack(errors.New("broker unavailable"))
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "broker unavailable") {
		t.Fatalf("PublishRaw() error = %v, want broker unavailable", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = publisher.PublishRaw(ctx, validRawEvent())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PublishRaw(canceled) error = %v, want context.Canceled", err)
	}
}

func TestPublisherFlushWaitsForInFlightProduces(t *testing.T) {
	t.Parallel()

	writer := newFakeWriter()
	publisher := newTestPublisher(t, writer, 4, 1)

	publishDone := make(chan error, 1)
	go func() {
		publishDone <- publisher.PublishRaw(context.Background(), validRawEvent())
	}()
	writer.waitStarted(t)

	flushDone := make(chan error, 1)
	go func() {
		flushDone <- publisher.Flush(context.Background())
	}()
	assertNotDone(t, flushDone, "Flush returned before in-flight publish ACK")

	writer.ack(nil)
	if err := <-publishDone; err != nil {
		t.Fatalf("PublishRaw() error = %v", err)
	}
	if err := <-flushDone; err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if writer.flushCount() != 1 {
		t.Fatalf("flush count = %d, want 1", writer.flushCount())
	}
}

func TestPublisherValidationAndConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.QueueSize = 0
	if _, err := NewPublisher(newFakeWriter(), cfg); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewPublisher(invalid cfg) error = %v, want ErrInvalidConfig", err)
	}
	if _, err := NewPublisher(nil, DefaultConfig()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewPublisher(nil writer) error = %v, want ErrInvalidConfig", err)
	}

	publisher := newTestPublisher(t, newFakeWriter(), 4, 1)
	event := validRawEvent()
	event.PartitionKey = "wrong"
	if err := publisher.PublishRaw(context.Background(), event); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("PublishRaw(invalid event) error = %v, want ErrInvalidEvent", err)
	}
}

func TestConfigFromApp(t *testing.T) {
	t.Parallel()

	appCfg := config.Default()
	appCfg.Kafka.Brokers = []string{"kafka:9092"}
	appCfg.Kafka.Topics.Raw = "raw-topic"
	appCfg.Kafka.Topics.DeadLetter = "dlq-topic"
	appCfg.Ingestion.PublishQueueSize = 123
	appCfg.Ingestion.PublisherWorkers = 2

	got := ConfigFromApp(appCfg)
	if got.RawTopic != "raw-topic" ||
		got.DeadLetterTopic != "dlq-topic" ||
		got.QueueSize != 123 ||
		got.Workers != 2 ||
		got.Brokers[0] != "kafka:9092" {
		t.Fatalf("ConfigFromApp() = %+v", got)
	}
}

func TestNewFranzWriterValidatesBrokers(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.Brokers = nil
	if _, err := NewFranzWriter(cfg); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewFranzWriter(no brokers) error = %v, want ErrInvalidConfig", err)
	}
}

func newTestPublisher(t *testing.T, writer *fakeWriter, queueSize int, workers int) *Publisher {
	t.Helper()

	cfg := DefaultConfig()
	cfg.QueueSize = queueSize
	cfg.Workers = workers
	publisher, err := NewPublisher(writer, cfg)
	if err != nil {
		t.Fatalf("NewPublisher() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := publisher.Close(ctx); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	})
	return publisher
}

type fakeWriter struct {
	mu      sync.Mutex
	started chan struct{}
	release chan error
	writes  []Record
	flushes int
	closed  bool
}

func newFakeWriter() *fakeWriter {
	return &fakeWriter{
		started: make(chan struct{}, 16),
		release: make(chan error, 16),
	}
}

func (w *fakeWriter) Produce(ctx context.Context, record Record) error {
	w.mu.Lock()
	w.writes = append(w.writes, cloneRecord(record))
	w.mu.Unlock()

	w.started <- struct{}{}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-w.release:
		return err
	}
}

func (w *fakeWriter) Flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushes++
	return nil
}

func (w *fakeWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
}

func (w *fakeWriter) waitStarted(t *testing.T) {
	t.Helper()

	select {
	case <-w.started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for fake writer to start produce")
	}
}

func (w *fakeWriter) ack(err error) {
	w.release <- err
}

func (w *fakeWriter) records() []Record {
	w.mu.Lock()
	defer w.mu.Unlock()
	records := make([]Record, len(w.writes))
	for i, record := range w.writes {
		records[i] = cloneRecord(record)
	}
	return records
}

func (w *fakeWriter) flushCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushes
}

func validRawEvent() *flowv1.RawFlowEventEnvelope {
	return &flowv1.RawFlowEventEnvelope{
		EventId:       "01934d7c-79b4-7000-8b69-001122334455",
		SchemaVersion: domain.RawSchemaVersion,
		Source:        validSource(),
		ReceivedAt:    timestamppb.New(time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC)),
		PartitionKey:  "netflow-main:router-core-01",
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_NetflowV5{
				NetflowV5: &flowv1.NetFlowV5Flow{
					PacketSequence:  42,
					RecordIndex:     0,
					SrcAddr:         "192.168.1.10",
					DstAddr:         "8.8.8.8",
					Packets:         3,
					Bytes:           420,
					FirstSwitchedMs: 1000,
					LastSwitchedMs:  2000,
					ProtocolNumber:  17,
				},
			},
		},
	}
}

func validDeadLetterEvent() *flowv1.DeadLetterEvent {
	return &flowv1.DeadLetterEvent{
		DeadLetterId:  "01934d7c-79b4-7000-8b69-001122334456",
		SchemaVersion: domain.RawSchemaVersion,
		Stage:         flowv1.IngestionStage_INGESTION_STAGE_PARSER,
		Source:        validSource(),
		ReceivedAt:    timestamppb.New(time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC)),
		FailedAt:      timestamppb.New(time.Date(2026, 6, 16, 10, 15, 21, 0, time.UTC)),
		Error: &flowv1.ErrorInfo{
			ErrorCode:    "invalid_json",
			ErrorMessage: "invalid zeek json line",
			Retryable:    false,
		},
		RawPayloadDebug: &flowv1.RawPayloadDebug{
			Masked:            true,
			Encoding:          flowv1.PayloadEncoding_PAYLOAD_ENCODING_TEXT,
			Data:              []byte(`{"token":"***MASKED***"}`),
			OriginalSizeBytes: 24,
		},
	}
}

func validSource() *flowv1.SourceIdentity {
	return &flowv1.SourceIdentity{
		CollectorId: "netflow-main",
		SourceType:  flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5,
		SourceHost:  "router-core-01",
	}
}

func headerMap(headers []Header) map[string]string {
	values := make(map[string]string, len(headers))
	for _, header := range headers {
		values[header.Key] = string(header.Value)
	}
	return values
}

func assertHeader(t *testing.T, headers map[string]string, key string, expected string) {
	t.Helper()

	if got := headers[key]; got != expected {
		t.Fatalf("header %q = %q, want %q", key, got, expected)
	}
}

func assertNotDone(t *testing.T, done <-chan error, message string) {
	t.Helper()

	select {
	case err := <-done:
		t.Fatalf("%s: %v", message, err)
	case <-time.After(20 * time.Millisecond):
	}
}

func waitQueueLen(t *testing.T, publisher *Publisher, expected int) {
	t.Helper()

	deadline := time.After(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for queue len %d; got %d", expected, len(publisher.queue))
		case <-ticker.C:
			if len(publisher.queue) == expected {
				return
			}
		}
	}
}

func TestPublisher_Healthy(t *testing.T) {
	t.Parallel()
	writer := &fakeWriter{}
	cfg := DefaultConfig()
	cfg.QueueSize = 10
	cfg.Workers = 1
	publisher, err := NewPublisher(writer, cfg)
	if err != nil {
		t.Fatalf("failed to create publisher: %v", err)
	}

	if !publisher.Healthy() {
		t.Error("expected publisher to be healthy initially")
	}

	// Stop/Close publisher
	_ = publisher.Close(context.Background())
	if publisher.Healthy() {
		t.Error("expected publisher to not be healthy after close")
	}
}

func TestRawPartitionKey(t *testing.T) {
	t.Parallel()
	source := &flowv1.SourceIdentity{CollectorId: "c", SourceHost: "h"}
	if got := RawPartitionKey(source); got != "c:h" {
		t.Errorf("RawPartitionKey() = %q, want c:h", got)
	}
}

func TestFranzWriterNil(t *testing.T) {
	t.Parallel()
	var nilWriter *FranzWriter
	if err := nilWriter.Produce(context.Background(), Record{}); err == nil {
		t.Error("expected error on nil FranzWriter Produce")
	}
	if err := nilWriter.Flush(context.Background()); err == nil {
		t.Error("expected error on nil FranzWriter Flush")
	}
	nilWriter.Close() // should not panic

	emptyWriter := &FranzWriter{}
	if err := emptyWriter.Produce(context.Background(), Record{}); err == nil {
		t.Error("expected error on empty FranzWriter Produce")
	}
	if err := emptyWriter.Flush(context.Background()); err == nil {
		t.Error("expected error on empty FranzWriter Flush")
	}
	emptyWriter.Close() // should not panic
}

func TestNewFranzPublisher_Validation(t *testing.T) {
	t.Parallel()
	// Invalid config should fail NewFranzPublisher
	_, err := NewFranzPublisher(Config{})
	if err == nil {
		t.Error("expected error for invalid Config in NewFranzPublisher")
	}
}

func TestValidateConfig_AllErrors(t *testing.T) {
	t.Parallel()

	base := DefaultConfig()

	tests := []struct {
		name    string
		modify  func(*Config)
		require bool
		errMsg  string
	}{
		{"missing brokers", func(c *Config) { c.Brokers = nil }, true, "brokers are required"},
		{"empty raw topic", func(c *Config) { c.RawTopic = "" }, false, "raw topic is required"},
		{"empty dead-letter topic", func(c *Config) { c.DeadLetterTopic = "" }, false, "dead-letter topic is required"},
		{"zero queue size", func(c *Config) { c.QueueSize = 0 }, false, "queue size must be positive"},
		{"zero workers", func(c *Config) { c.Workers = 0 }, false, "workers must be positive"},
		{"zero request timeout", func(c *Config) { c.RequestTimeout = 0 }, false, "request timeout must be positive"},
		{"zero delivery timeout", func(c *Config) { c.DeliveryTimeout = 0 }, false, "delivery timeout must be positive"},
		{"negative retries", func(c *Config) { c.MaxRetries = -1 }, false, "max retries cannot be negative"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := base
			cfg.Brokers = []string{"localhost:9092"}
			tc.modify(&cfg)
			err := validateConfig(cfg, tc.require)
			if err == nil || !strings.Contains(err.Error(), tc.errMsg) {
				t.Errorf("expected error containing %q, got %v", tc.errMsg, err)
			}
		})
	}
}

func TestPublisher_FlushEdgeCases(t *testing.T) {
	t.Parallel()

	writer := newFakeWriter()
	publisher := newTestPublisher(t, writer, 4, 1)

	// Canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := publisher.Flush(ctx); err == nil {
		t.Error("expected error for canceled context Flush")
	}

	// Close then flush
	_ = publisher.Close(context.Background())
	if err := publisher.Flush(context.Background()); err == nil {
		t.Error("expected error for flush after close")
	}
}

func TestPublisher_PublishDeadLetterNilContext(t *testing.T) {
	t.Parallel()

	writer := newFakeWriter()
	publisher := newTestPublisher(t, writer, 4, 1)
	defer func() { _ = publisher.Close(context.Background()) }()

	if err := publisher.PublishDeadLetter(context.TODO(), nil); err == nil {
		t.Error("expected error for invalid dead letter event")
	}
}
