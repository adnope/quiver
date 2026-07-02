package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/observability"
)

func TestStorageWriterInsertDuplicateAndCommit(t *testing.T) {
	t.Parallel()

	inserter := &fakeInserter{
		results: []InsertResult{{Attempted: 2, Inserted: 1, Deduplicated: 1}},
	}
	committer := &fakeCommitter{inserter: inserter}
	writer := newTestStorageWriter(t, inserter, &fakeDeadLetterPublisher{})
	result, err := writer.WriteBatch(context.Background(), []StorageBatchItem{
		{Record: validStorageRecord("01934d7c-79b4-7000-8b69-001122334455")},
		{Record: validStorageRecord("01934d7c-79b4-7000-8b69-001122334456")},
	}, committer)
	if err != nil {
		t.Fatalf("WriteBatch() error = %v", err)
	}
	if result.Inserted != 1 || result.Deduplicated != 1 || result.DeadLettered != 0 {
		t.Fatalf("result = %+v", result)
	}
	if !committer.committed || !committer.afterInsert {
		t.Fatalf("commit state = committed:%v afterInsert:%v", committer.committed, committer.afterInsert)
	}
}

func TestStorageWriterInvalidRecordPublishesDLQ(t *testing.T) {
	t.Parallel()

	dlq := &fakeDeadLetterPublisher{}
	writer := newTestStorageWriter(t, &fakeInserter{}, dlq)
	record := validStorageRecord("01934d7c-79b4-7000-8b69-001122334455")
	record.SchemaVersion = "bad"

	result, err := writer.WriteBatch(context.Background(), []StorageBatchItem{
		{Record: record, RawEvent: validRawStorageEvent(record.RawEventID)},
	}, &fakeCommitter{})
	if err != nil {
		t.Fatalf("WriteBatch() error = %v", err)
	}
	if result.DeadLettered != 1 || len(dlq.events) != 1 {
		t.Fatalf("result = %+v dlq=%d", result, len(dlq.events))
	}
	if dlq.events[0].GetStage() != flowv1.IngestionStage_INGESTION_STAGE_STORAGE_WRITER {
		t.Fatalf("stage = %s", dlq.events[0].GetStage())
	}
}

func TestStorageWriterIsolatesBadDatabaseRow(t *testing.T) {
	t.Parallel()

	inserter := &fakeInserter{badSourceHost: "bad-db"}
	dlq := &fakeDeadLetterPublisher{}
	writer := newTestStorageWriter(t, inserter, dlq)
	good := validStorageRecord("01934d7c-79b4-7000-8b69-001122334455")
	bad := validStorageRecord("01934d7c-79b4-7000-8b69-001122334456")
	bad.SourceHost = "bad-db"

	result, err := writer.WriteBatch(context.Background(), []StorageBatchItem{
		{Record: good, RawEvent: validRawStorageEvent(good.RawEventID)},
		{Record: bad, RawEvent: validRawStorageEvent(bad.RawEventID)},
	}, &fakeCommitter{})
	if err != nil {
		t.Fatalf("WriteBatch() error = %v", err)
	}
	if result.Inserted != 1 || result.DeadLettered != 1 {
		t.Fatalf("result = %+v", result)
	}
	if len(dlq.events) != 1 {
		t.Fatalf("dlq count = %d", len(dlq.events))
	}
}

func newTestStorageWriter(t *testing.T, inserter FlowRecordInserter, publisher DeadLetterPublisher) *StorageWriter {
	t.Helper()

	writer, err := NewStorageWriter(config.StorageWriterConfig{
		BatchSize:      1000,
		MaxRetries:     0,
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
	}, inserter, publisher)
	if err != nil {
		t.Fatalf("NewStorageWriter() error = %v", err)
	}
	writer.now = func() time.Time { return time.Date(2026, 6, 16, 10, 15, 30, 0, time.UTC) }
	writer.sleep = func(context.Context, time.Duration) error { return nil }
	return writer
}

type fakeInserter struct {
	mu            sync.Mutex
	calls         int
	results       []InsertResult
	badSourceHost string
}

func (i *fakeInserter) InsertFlowRecords(_ context.Context, records []domain.NormalizedFlowRecord) (InsertResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.calls++
	for _, record := range records {
		if i.badSourceHost != "" && record.SourceHost == i.badSourceHost {
			return InsertResult{}, errors.New("row violates storage constraint")
		}
	}
	if len(i.results) > 0 {
		result := i.results[0]
		i.results = i.results[1:]
		return result, nil
	}
	return InsertResult{Attempted: len(records), Inserted: len(records)}, nil
}

type fakeDeadLetterPublisher struct {
	events []*flowv1.DeadLetterEvent
}

func (p *fakeDeadLetterPublisher) PublishDeadLetter(_ context.Context, event *flowv1.DeadLetterEvent) error {
	p.events = append(p.events, event)
	return nil
}

type fakeCommitter struct {
	inserter    *fakeInserter
	committed   bool
	afterInsert bool
}

func (c *fakeCommitter) Commit(context.Context) error {
	c.committed = true
	if c.inserter == nil {
		c.afterInsert = true
		return nil
	}
	c.afterInsert = c.inserter.calls > 0
	return nil
}

func validStorageRecord(id string) domain.NormalizedFlowRecord {
	srcPort := uint16(51524)
	dstPort := uint16(53)
	bytesValue := uint64(420)
	packets := uint64(3)
	return domain.NormalizedFlowRecord{
		ID:                  id,
		SchemaVersion:       domain.FlowSchemaVersion,
		IdempotencyKey:      "sha256:" + id,
		RawEventID:          "01934d7c-79b4-7000-8b69-001122334457",
		SourceType:          domain.SourceTypeRESTJSON,
		CollectorID:         "rest-ingest-main",
		SourceHost:          "rest-client-host",
		IngestedAt:          time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC),
		NormalizedAt:        time.Date(2026, 6, 16, 10, 15, 21, 0, time.UTC),
		EventStartTime:      time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC),
		SrcIP:               netip.MustParseAddr("192.168.1.10"),
		DstIP:               netip.MustParseAddr("8.8.8.8"),
		SrcPort:             &srcPort,
		DstPort:             &dstPort,
		IPVersion:           4,
		TransportProtocol:   domain.TransportProtocolUDP,
		ProtocolNumber:      17,
		Bytes:               &bytesValue,
		Packets:             &packets,
		Direction:           domain.DirectionOutbound,
		NormalizationStatus: domain.NormalizationStatusOK,
		Attributes:          map[string]json.RawMessage{},
	}
}

func validRawStorageEvent(id string) *flowv1.RawFlowEventEnvelope {
	return &flowv1.RawFlowEventEnvelope{
		EventId:       id,
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
						SrcIp:             new("192.168.1.10"),
						DstIp:             new("8.8.8.8"),
						SrcPort:           new(uint32(51524)),
						DstPort:           new(uint32(53)),
						TransportProtocol: flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UDP,
						ProtocolNumber:    17,
					},
				},
			},
		},
	}
}

func TestStorageWriter_NewValidationErrors(t *testing.T) {
	t.Parallel()

	// Nil inserter
	_, err := NewStorageWriter(config.StorageWriterConfig{}, nil, &fakeDeadLetterPublisher{})
	if err == nil || !strings.Contains(err.Error(), "inserter is nil") {
		t.Errorf("expected inserter is nil error, got %v", err)
	}

	// Nil publisher
	_, err = NewStorageWriter(config.StorageWriterConfig{}, &fakeInserter{}, nil)
	if err == nil || !strings.Contains(err.Error(), "dead-letter publisher is nil") {
		t.Errorf("expected publisher is nil error, got %v", err)
	}

	// Invalid config fields
	cfg := config.StorageWriterConfig{BatchSize: 0}
	_, err = NewStorageWriter(cfg, &fakeInserter{}, &fakeDeadLetterPublisher{})
	if err == nil || !strings.Contains(err.Error(), "batch_size must be positive") {
		t.Errorf("expected batch size error, got %v", err)
	}
}

func TestStorageWriter_WithMetrics(t *testing.T) {
	t.Parallel()
	writer := newTestStorageWriter(t, &fakeInserter{}, &fakeDeadLetterPublisher{})
	metrics := &observability.Registry{} // Using pointer to Registry directly
	writer2 := writer.WithMetrics(metrics)
	if writer2.metrics != metrics {
		t.Error("expected metrics registry to be set on StorageWriter")
	}
}

func TestStorageWriter_Backoff(t *testing.T) {
	t.Parallel()
	writer := newTestStorageWriter(t, &fakeInserter{}, &fakeDeadLetterPublisher{})
	writer.initialBackoff = 10 * time.Millisecond
	writer.maxBackoff = 100 * time.Millisecond

	if d := writer.backoff(0); d != 10*time.Millisecond {
		t.Errorf("attempt 0 backoff = %v, want 10ms", d)
	}
	if d := writer.backoff(1); d != 20*time.Millisecond {
		t.Errorf("attempt 1 backoff = %v, want 20ms", d)
	}
	if d := writer.backoff(2); d != 40*time.Millisecond {
		t.Errorf("attempt 2 backoff = %v, want 40ms", d)
	}
	// Max cap
	if d := writer.backoff(10); d != 100*time.Millisecond {
		t.Errorf("attempt 10 backoff = %v, want 100ms", d)
	}
}

func TestSourceTypeToProto(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in  domain.SourceType
		out flowv1.SourceType
	}{
		{domain.SourceTypeUnknown, flowv1.SourceType_SOURCE_TYPE_UNSPECIFIED},
		{domain.SourceTypeNetFlowV5, flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5},
		{domain.SourceTypeZeekConnJSON, flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON},
		{domain.SourceTypeRESTJSON, flowv1.SourceType_SOURCE_TYPE_REST_JSON},
		{domain.SourceTypeNetFlowV9, flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9},
		{domain.SourceTypeSyslogCEF, flowv1.SourceType_SOURCE_TYPE_SYSLOG_CEF},
		{domain.SourceTypeSyslogLEEF, flowv1.SourceType_SOURCE_TYPE_SYSLOG_LEEF},
		{domain.SourceTypeSuricataEVE, flowv1.SourceType_SOURCE_TYPE_SURICATA_EVE_JSON},
		{domain.SourceType("invalid"), flowv1.SourceType_SOURCE_TYPE_UNSPECIFIED},
	}
	for _, tt := range tests {
		if got := sourceTypeToProto(tt.in); got != tt.out {
			t.Errorf("sourceTypeToProto(%q) = %v, want %v", tt.in, got, tt.out)
		}
	}
}

func TestSleepContext(t *testing.T) {
	t.Parallel()

	// 1. Successful sleep
	start := time.Now()
	err := sleepContext(context.Background(), time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected sleep error: %v", err)
	}
	if time.Since(start) < time.Millisecond {
		t.Error("sleep was too short")
	}

	// 2. Canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = sleepContext(ctx, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestStorageWriterDLQWithoutRawEvent(t *testing.T) {
	t.Parallel()

	dlq := &fakeDeadLetterPublisher{}
	writer := newTestStorageWriter(t, &fakeInserter{}, dlq)
	record := validStorageRecord("01934d7c-79b4-7000-8b69-001122334455")
	record.SchemaVersion = "bad" // fails validation

	result, err := writer.WriteBatch(context.Background(), []StorageBatchItem{
		{Record: record, RawEvent: nil}, // RawEvent is nil to trigger storageDebugPayload!
	}, &fakeCommitter{})
	if err != nil {
		t.Fatalf("WriteBatch() error = %v", err)
	}
	if result.DeadLettered != 1 || len(dlq.events) != 1 {
		t.Fatalf("result = %+v dlq=%d", result, len(dlq.events))
	}
	if dlq.events[0].GetRawPayloadDebug() == nil || !dlq.events[0].GetRawPayloadDebug().GetMasked() {
		t.Errorf("expected RawPayloadDebug to be set and masked")
	}
}

func TestStorageWriterRecordMetrics(t *testing.T) {
	t.Parallel()

	inserter := &fakeInserter{
		results: []InsertResult{{Attempted: 2, Inserted: 1, Deduplicated: 1}},
	}
	committer := &fakeCommitter{inserter: inserter}
	metrics := observability.NewRegistry()
	writer := newTestStorageWriter(t, inserter, &fakeDeadLetterPublisher{}).WithMetrics(metrics)

	_, err := writer.WriteBatch(context.Background(), []StorageBatchItem{
		{Record: validStorageRecord("01934d7c-79b4-7000-8b69-001122334455")},
		{Record: validStorageRecord("01934d7c-79b4-7000-8b69-001122334456")},
	}, committer)
	if err != nil {
		t.Fatalf("WriteBatch failed: %v", err)
	}

	prometheusOutput := string(metrics.WritePrometheus())
	if !strings.Contains(prometheusOutput, "storage_insert_batches_total") {
		t.Error("expected storage_insert_batches_total metric")
	}
	if !strings.Contains(prometheusOutput, "storage_insert_records_total") {
		t.Error("expected storage_insert_records_total metric")
	}
}
