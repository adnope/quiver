//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestStorageWriterIntegration(t *testing.T) {
	dsn := os.Getenv("QUIVER_TEST_DATABASE_DSN")
	if dsn == "" {
		dsn = os.Getenv("QUIVER_DATABASE_DSN")
	}
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/quiver?sslmode=disable"
	}

	// 1. Run Migrations
	migrator, err := migrate.New("file://migrations", dsn)
	if err != nil {
		t.Fatalf("Failed to create migrator: %v", err)
	}
	if err := migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("Failed to run migrations up: %v", err)
	}

	// 2. Open DB
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("Failed to open DB: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	// Clear out flow_records first for a clean slate
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, "DELETE FROM quiver.flow_records"); err != nil {
		t.Fatalf("Failed to clear flow_records: %v", err)
	}

	flowRepo, err := NewFlowRepository(db)
	if err != nil {
		t.Fatalf("Failed to create FlowRepository: %v", err)
	}

	dlq := &integrationDLQ{}
	writer, err := NewStorageWriter(config.StorageWriterConfig{
		BatchSize:      1000,
		MaxRetries:     2,
		InitialBackoff: config.Duration(10 * time.Millisecond),
		MaxBackoff:     config.Duration(50 * time.Millisecond),
	}, flowRepo, dlq)
	if err != nil {
		t.Fatalf("Failed to create StorageWriter: %v", err)
	}
	writer.now = func() time.Time { return time.Date(2026, 6, 18, 2, 0, 0, 0, time.UTC) }

	// Prepare data
	goodRecord1 := validIntegrationStorageRecord("01934d7c-79b4-7000-8b69-001122334455", "sha-dup-1")
	goodRecord2 := validIntegrationStorageRecord("01934d7c-79b4-7000-8b69-001122334456", "sha-dup-2")

	// 3. Write Batch
	committer := &integrationCommitter{}
	batchItems := []StorageBatchItem{
		{Record: goodRecord1, RawEvent: validIntegrationRawStorageEvent(goodRecord1.RawEventID)},
		{Record: goodRecord2, RawEvent: validIntegrationRawStorageEvent(goodRecord2.RawEventID)},
	}

	result, err := writer.WriteBatch(ctx, batchItems, committer)
	if err != nil {
		t.Fatalf("WriteBatch failed: %v", err)
	}

	if result.Inserted != 2 || result.Deduplicated != 0 || result.DeadLettered != 0 {
		t.Errorf("Unexpected result for first write: %+v", result)
	}
	if !committer.committed {
		t.Errorf("Kafka offsets were not committed on success")
	}

	// 4. Test Idempotency / Duplicate
	committer2 := &integrationCommitter{}
	result2, err := writer.WriteBatch(ctx, []StorageBatchItem{
		{Record: goodRecord1, RawEvent: validIntegrationRawStorageEvent(goodRecord1.RawEventID)},
	}, committer2)
	if err != nil {
		t.Fatalf("WriteBatch (idempotent retry) failed: %v", err)
	}
	if result2.Inserted != 0 || result2.Deduplicated != 1 || result2.DeadLettered != 0 {
		t.Errorf("Unexpected result for duplicate write: %+v", result2)
	}
	if !committer2.committed {
		t.Errorf("Kafka offsets were not committed on duplicate")
	}

	// 5. Test Batch Splitting and Database constraint violation
	// We violate event_end_time < event_start_time check constraint!
	badRecord := validIntegrationStorageRecord("01934d7c-79b4-7000-8b69-001122334457", "sha-dup-3")
	badRecord.EventStartTime = time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	badRecord.EventEndTime = &[]time.Time{time.Date(2026, 6, 18, 10, 0, 0, 0, time.UTC)}[0] // end < start

	goodRecord3 := validIntegrationStorageRecord("01934d7c-79b4-7000-8b69-001122334458", "sha-dup-4")

	committer3 := &integrationCommitter{}
	result3, err := writer.WriteBatch(ctx, []StorageBatchItem{
		{Record: badRecord, RawEvent: validIntegrationRawStorageEvent(badRecord.RawEventID)},
		{Record: goodRecord3, RawEvent: validIntegrationRawStorageEvent(goodRecord3.RawEventID)},
	}, committer3)
	if err != nil {
		t.Fatalf("WriteBatch with bad record failed: %v", err)
	}

	if result3.Inserted != 1 || result3.DeadLettered != 1 {
		t.Errorf("Unexpected split batch result: %+v", result3)
	}
	if len(dlq.events) != 1 {
		t.Errorf("Expected 1 dead-letter event, got %d", len(dlq.events))
	} else {
		dlqEvent := dlq.events[0]
		if dlqEvent.GetStage() != flowv1.IngestionStage_INGESTION_STAGE_STORAGE_WRITER {
			t.Errorf("Expected stage STORAGE_WRITER, got %s", dlqEvent.GetStage())
		}
		if dlqEvent.GetError().GetErrorCode() != "storage_write_failed" {
			t.Errorf("Expected error code storage_write_failed, got %s", dlqEvent.GetError().GetErrorCode())
		}
	}
	if !committer3.committed {
		t.Errorf("Kafka offsets were not committed on batch split resolution")
	}
}

type integrationDLQ struct {
	mu     sync.Mutex
	events []*flowv1.DeadLetterEvent
}

func (d *integrationDLQ) PublishDeadLetter(_ context.Context, event *flowv1.DeadLetterEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, event)
	return nil
}

type integrationCommitter struct {
	committed bool
}

func (c *integrationCommitter) Commit(context.Context) error {
	c.committed = true
	return nil
}

func validIntegrationStorageRecord(id string, idempotencyKey string) domain.NormalizedFlowRecord {
	srcPort := uint16(51524)
	dstPort := uint16(53)
	bytesValue := uint64(420)
	packets := uint64(3)
	return domain.NormalizedFlowRecord{
		ID:                  id,
		SchemaVersion:       domain.FlowSchemaVersion,
		IdempotencyKey:      idempotencyKey,
		RawEventID:          "01934d7c-79b4-7000-8b69-001122334457",
		SourceType:          domain.SourceTypeRESTJSON,
		CollectorID:         "rest-ingest-main",
		SourceHost:          "rest-client-host",
		IngestedAt:          time.Date(2026, 6, 18, 1, 0, 0, 0, time.UTC),
		NormalizedAt:        time.Date(2026, 6, 18, 1, 1, 0, 0, time.UTC),
		EventStartTime:      time.Date(2026, 6, 18, 1, 0, 0, 0, time.UTC),
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
		Attributes:          map[string]json.RawMessage{"client_ver": json.RawMessage(`"1.0"`)},
	}
}

func validIntegrationRawStorageEvent(id string) *flowv1.RawFlowEventEnvelope {
	return &flowv1.RawFlowEventEnvelope{
		EventId:       id,
		SchemaVersion: domain.RawSchemaVersion,
		Source: &flowv1.SourceIdentity{
			CollectorId: "rest-ingest-main",
			SourceType:  flowv1.SourceType_SOURCE_TYPE_REST_JSON,
			SourceHost:  "rest-client-host",
		},
		ReceivedAt:   timestamppb.New(time.Date(2026, 6, 18, 1, 0, 0, 0, time.UTC)),
		PartitionKey: "rest-ingest-main:rest-client-host",
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_RestFlow{
				RestFlow: &flowv1.RestFlowInput{
					EventStartTime: timestamppb.New(time.Date(2026, 6, 18, 1, 0, 0, 0, time.UTC)),
					Tuple: &flowv1.NetworkTuple{
						SrcIp:             testIntegrationStringPtr("192.168.1.10"),
						DstIp:             testIntegrationStringPtr("8.8.8.8"),
						SrcPort:           testIntegrationUint32Ptr(51524),
						DstPort:           testIntegrationUint32Ptr(53),
						TransportProtocol: flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UDP,
						ProtocolNumber:    17,
					},
				},
			},
		},
	}
}

func testIntegrationStringPtr(value string) *string {
	return &value
}

func testIntegrationUint32Ptr(value uint32) *uint32 {
	return &value
}
