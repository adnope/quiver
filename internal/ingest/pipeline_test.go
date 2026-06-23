package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/observability"
	"github.com/adnope/quiver/internal/storage/postgres"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProcessBatchSequential(t *testing.T) {
	t.Parallel()

	records := make([]*kgo.Record, 10)
	for i := 0; i < 10; i++ {
		records[i] = testRecord(t, i)
	}

	inserter := &fakeInserter{}
	dlq := &fakeDeadLetterPublisher{}
	sw, err := postgres.NewStorageWriter(config.StorageWriterConfig{
		BatchSize:      1000,
		MaxRetries:     0,
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
	}, inserter, dlq)
	if err != nil {
		t.Fatalf("failed to create storage writer: %v", err)
	}

	mockKafka := &mockKafkaClient{}
	metrics := observability.NewRegistry()
	mockPub := &mockPublisher{}

	pipeline := &Pipeline{
		cfg:           config.Default(),
		client:        mockKafka,
		storageWriter: sw,
		publisher:     mockPub,
		metrics:       metrics,
		logger:        newDiscardLogger(),
	}

	err = pipeline.processBatch(context.Background(), records)
	if err != nil {
		t.Fatalf("processBatch failed: %v", err)
	}

	if inserter.calls != 1 {
		t.Errorf("expected 1 inserter call, got %d", inserter.calls)
	}
	if mockKafka.commitCalls != 1 {
		t.Errorf("expected 1 commit call, got %d", mockKafka.commitCalls)
	}
	if len(mockPub.dlqEvents) != 0 {
		t.Errorf("expected 0 DLQ events, got %d", len(mockPub.dlqEvents))
	}
}

func TestProcessBatchConcurrentSuccess(t *testing.T) {
	t.Parallel()

	// 250 records to trigger concurrent process (> 200)
	records := make([]*kgo.Record, 250)
	for i := 0; i < 250; i++ {
		records[i] = testRecord(t, i)
	}

	inserter := &fakeInserter{}
	dlq := &fakeDeadLetterPublisher{}
	sw, err := postgres.NewStorageWriter(config.StorageWriterConfig{
		BatchSize:      1000,
		MaxRetries:     0,
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
	}, inserter, dlq)
	if err != nil {
		t.Fatalf("failed to create storage writer: %v", err)
	}

	mockKafka := &mockKafkaClient{}
	metrics := observability.NewRegistry()
	mockPub := &mockPublisher{}

	cfg := config.Default()
	cfg.StorageWriter.Concurrency = 4

	pipeline := &Pipeline{
		cfg:           cfg,
		client:        mockKafka,
		storageWriter: sw,
		publisher:     mockPub,
		metrics:       metrics,
		logger:        newDiscardLogger(),
	}

	err = pipeline.processBatch(context.Background(), records)
	if err != nil {
		t.Fatalf("processBatch failed: %v", err)
	}

	// Concurrency of 4 means we split 250 records into 4 chunks (63, 63, 62, 62).
	// Each chunk is processed concurrently and written using storageWriter.WriteBatch.
	// Since WriteBatch calls the inserter once (batchSize 1000 > chunk size),
	// we expect exactly 4 calls to the inserter.
	if inserter.calls != 4 {
		t.Errorf("expected 4 inserter calls, got %d", inserter.calls)
	}
	if mockKafka.commitCalls != 1 {
		t.Errorf("expected 1 overall commit call, got %d", mockKafka.commitCalls)
	}
	if len(mockPub.dlqEvents) != 0 {
		t.Errorf("expected 0 DLQ events, got %d", len(mockPub.dlqEvents))
	}
}

func TestProcessBatchConcurrentFailure(t *testing.T) {
	t.Parallel()

	records := make([]*kgo.Record, 250)
	for i := 0; i < 250; i++ {
		records[i] = testRecord(t, i)
	}

	inserter := &fakeInserter{
		failAfterCalls: 2, // fail on the 3rd insert call
	}
	dlq := &fakeDeadLetterPublisher{
		failPublish: true,
	}
	sw, err := postgres.NewStorageWriter(config.StorageWriterConfig{
		BatchSize:      1000,
		MaxRetries:     0,
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
	}, inserter, dlq)
	if err != nil {
		t.Fatalf("failed to create storage writer: %v", err)
	}

	mockKafka := &mockKafkaClient{}
	metrics := observability.NewRegistry()
	mockPub := &mockPublisher{}

	cfg := config.Default()
	cfg.StorageWriter.Concurrency = 4

	pipeline := &Pipeline{
		cfg:           cfg,
		client:        mockKafka,
		storageWriter: sw,
		publisher:     mockPub,
		metrics:       metrics,
		logger:        newDiscardLogger(),
	}

	err = pipeline.processBatch(context.Background(), records)
	if err == nil {
		t.Fatal("expected processBatch to fail, but it succeeded")
	}

	// Offsets must NOT be committed if any concurrent worker fails
	if mockKafka.commitCalls != 0 {
		t.Errorf("expected 0 overall commit calls on failure, got %d", mockKafka.commitCalls)
	}
}

func TestProcessBatchConcurrentPanic(t *testing.T) {
	t.Parallel()

	records := make([]*kgo.Record, 250)
	for i := 0; i < 250; i++ {
		records[i] = testRecord(t, i)
	}

	inserter := &fakeInserter{
		panicAfterCalls: 1, // panic on the 2nd insert call
	}
	dlq := &fakeDeadLetterPublisher{}
	sw, err := postgres.NewStorageWriter(config.StorageWriterConfig{
		BatchSize:      1000,
		MaxRetries:     0,
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
	}, inserter, dlq)
	if err != nil {
		t.Fatalf("failed to create storage writer: %v", err)
	}

	mockKafka := &mockKafkaClient{}
	metrics := observability.NewRegistry()
	mockPub := &mockPublisher{}

	cfg := config.Default()
	cfg.StorageWriter.Concurrency = 4

	pipeline := &Pipeline{
		cfg:           cfg,
		client:        mockKafka,
		storageWriter: sw,
		publisher:     mockPub,
		metrics:       metrics,
		logger:        newDiscardLogger(),
	}

	err = pipeline.processBatch(context.Background(), records)
	if err == nil {
		t.Fatal("expected processBatch to fail due to panic, but it succeeded")
	}

	if mockKafka.commitCalls != 0 {
		t.Errorf("expected 0 overall commit calls on panic, got %d", mockKafka.commitCalls)
	}
}

func TestProcessBatchConcurrentDeduplicationAndDLQ(t *testing.T) {
	t.Parallel()

	records := make([]*kgo.Record, 250)
	for i := 0; i < 250; i++ {
		if i == 50 {
			// One corrupt record to go to DLQ during validation/unmarshal
			records[i] = &kgo.Record{Value: []byte("invalid protobuf data")}
		} else {
			records[i] = testRecord(t, i)
		}
	}

	// Set database to deduplicate some records
	inserter := &fakeInserter{
		deduplicateCount: 10,
	}
	dlq := &fakeDeadLetterPublisher{}
	sw, err := postgres.NewStorageWriter(config.StorageWriterConfig{
		BatchSize:      1000,
		MaxRetries:     0,
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
	}, inserter, dlq)
	if err != nil {
		t.Fatalf("failed to create storage writer: %v", err)
	}

	mockKafka := &mockKafkaClient{}
	metrics := observability.NewRegistry()
	mockPub := &mockPublisher{}

	cfg := config.Default()
	cfg.StorageWriter.Concurrency = 4

	pipeline := &Pipeline{
		cfg:           cfg,
		client:        mockKafka,
		storageWriter: sw,
		publisher:     mockPub,
		metrics:       metrics,
		logger:        newDiscardLogger(),
	}

	err = pipeline.processBatch(context.Background(), records)
	if err != nil {
		t.Fatalf("processBatch failed: %v", err)
	}

	if mockKafka.commitCalls != 1 {
		t.Errorf("expected 1 overall commit call, got %d", mockKafka.commitCalls)
	}
	if len(mockPub.dlqEvents) != 1 {
		t.Errorf("expected 1 DLQ event on pipeline publisher, got %d", len(mockPub.dlqEvents))
	}
}

// Helper types & functions

type mockKafkaClient struct {
	commitCalls int
}

func (m *mockKafkaClient) PollRecords(ctx context.Context, num int) kgo.Fetches {
	return kgo.Fetches{}
}

func (m *mockKafkaClient) CommitRecords(ctx context.Context, records ...*kgo.Record) error {
	m.commitCalls++
	return nil
}

func (m *mockKafkaClient) Close() {}

type fakeInserter struct {
	mu               sync.Mutex
	calls            int
	failAfterCalls   int
	panicAfterCalls  int
	deduplicateCount int
}

func (i *fakeInserter) InsertFlowRecords(ctx context.Context, records []domain.NormalizedFlowRecord) (postgres.InsertResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.panicAfterCalls > 0 && i.calls >= i.panicAfterCalls {
		panic("database connection failure panic simulated")
	}

	if i.failAfterCalls > 0 && i.calls >= i.failAfterCalls {
		return postgres.InsertResult{}, errors.New("simulated database insert error")
	}

	i.calls++

	inserted := len(records)
	dedup := 0
	if i.deduplicateCount > 0 {
		if inserted > i.deduplicateCount {
			inserted -= i.deduplicateCount
			dedup = i.deduplicateCount
			i.deduplicateCount = 0
		} else {
			dedup = inserted
			inserted = 0
			i.deduplicateCount -= dedup
		}
	}

	return postgres.InsertResult{
		Attempted:    len(records),
		Inserted:     inserted,
		Deduplicated: dedup,
	}, nil
}

type fakeDeadLetterPublisher struct {
	mu          sync.Mutex
	events      []*flowv1.DeadLetterEvent
	failPublish bool
}

func (p *fakeDeadLetterPublisher) PublishDeadLetter(ctx context.Context, event *flowv1.DeadLetterEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failPublish {
		return errors.New("simulated DLQ publish error")
	}
	p.events = append(p.events, event)
	return nil
}

type mockPublisher struct {
	mu        sync.Mutex
	dlqEvents []*flowv1.DeadLetterEvent
}

func (m *mockPublisher) PublishRaw(ctx context.Context, event *flowv1.RawFlowEventEnvelope) error {
	return nil
}

func (m *mockPublisher) PublishDeadLetter(ctx context.Context, event *flowv1.DeadLetterEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dlqEvents = append(m.dlqEvents, event)
	return nil
}

func (m *mockPublisher) Flush(ctx context.Context) error {
	return nil
}

func makeUUIDv7(i int) string {
	return fmt.Sprintf("01934d7c-79b4-7000-8b69-%012x", i)
}

func testRecord(t *testing.T, i int) *kgo.Record {
	t.Helper()
	srcPort := uint32(51524)
	dstPort := uint32(53)
	envelope := &flowv1.RawFlowEventEnvelope{
		EventId:       makeUUIDv7(i),
		SchemaVersion: domain.RawSchemaVersion,
		Source: &flowv1.SourceIdentity{
			CollectorId: "rest-ingest-main",
			SourceType:  flowv1.SourceType_SOURCE_TYPE_REST_JSON,
			SourceHost:  "rest-client-host",
		},
		ReceivedAt:   timestamppb.New(time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC)),
		PartitionKey: "rest-ingest-main:rest-client-host",
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_RestFlow{
				RestFlow: &flowv1.RestFlowInput{
					EventStartTime: timestamppb.New(time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC)),
					Tuple: &flowv1.NetworkTuple{
						SrcIp:             proto.String("192.168.1.10"),
						DstIp:             proto.String("8.8.8.8"),
						SrcPort:           &srcPort,
						DstPort:           &dstPort,
						TransportProtocol: flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UDP,
						ProtocolNumber:    17,
					},
				},
			},
		},
	}
	bytes, err := proto.Marshal(envelope)
	if err != nil {
		t.Fatalf("failed to marshal protobuf envelope: %v", err)
	}
	return &kgo.Record{Value: bytes}
}

type discardLoggerHandler struct{}

func (h *discardLoggerHandler) Enabled(ctx context.Context, level slog.Level) bool { return false }
func (h *discardLoggerHandler) Handle(ctx context.Context, r slog.Record) error    { return nil }
func (h *discardLoggerHandler) WithAttrs(attrs []slog.Attr) slog.Handler           { return h }
func (h *discardLoggerHandler) WithGroup(name string) slog.Handler                 { return h }

func newDiscardLogger() *slog.Logger {
	return slog.New(&discardLoggerHandler{})
}
