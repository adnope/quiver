//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/domain"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func TestFlowRepositoryIntegration(t *testing.T) {
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

	// Prepare records
	seedTime := time.Date(2026, 6, 18, 5, 0, 0, 0, time.UTC)
	srcPort1 := uint16(12345)
	dstPort1 := uint16(80)
	bytes1 := uint64(500)
	packets1 := uint64(5)

	srcPort2 := uint16(54321)
	dstPort2 := uint16(443)
	bytes2 := uint64(1500)
	packets2 := uint64(10)

	rec1 := domain.NormalizedFlowRecord{
		ID:                  "01934d7c-79b4-7000-8b69-001122335501",
		SchemaVersion:       domain.FlowSchemaVersion,
		IdempotencyKey:      "sha-repo-1",
		RawEventID:          "01934d7c-79b4-7000-8b69-001122334401",
		SourceType:          domain.SourceTypeRESTJSON,
		CollectorID:         "rest-ingest-main",
		SourceHost:          "rest-client-host",
		IngestedAt:          seedTime,
		NormalizedAt:        seedTime,
		EventStartTime:      seedTime,
		SrcIP:               netip.MustParseAddr("192.168.1.10"),
		DstIP:               netip.MustParseAddr("8.8.8.8"),
		SrcPort:             &srcPort1,
		DstPort:             &dstPort1,
		IPVersion:           4,
		TransportProtocol:   domain.TransportProtocolTCP,
		ProtocolNumber:      6,
		Bytes:               &bytes1,
		Packets:             &packets1,
		Direction:           domain.DirectionOutbound,
		NormalizationStatus: domain.NormalizationStatusOK,
		Attributes:          map[string]json.RawMessage{},
	}

	rec2 := domain.NormalizedFlowRecord{
		ID:                  "01934d7c-79b4-7000-8b69-001122335502",
		SchemaVersion:       domain.FlowSchemaVersion,
		IdempotencyKey:      "sha-repo-2",
		RawEventID:          "01934d7c-79b4-7000-8b69-001122334402",
		SourceType:          domain.SourceTypeNetFlowV5,
		CollectorID:         "netflow-main",
		SourceHost:          "router-core-01",
		IngestedAt:          seedTime.Add(10 * time.Second),
		NormalizedAt:        seedTime.Add(10 * time.Second),
		EventStartTime:      seedTime.Add(10 * time.Second),
		SrcIP:               netip.MustParseAddr("10.0.0.1"),
		DstIP:               netip.MustParseAddr("192.168.1.10"),
		SrcPort:             &srcPort2,
		DstPort:             &dstPort2,
		IPVersion:           4,
		TransportProtocol:   domain.TransportProtocolUDP,
		ProtocolNumber:      17,
		Bytes:               &bytes2,
		Packets:             &packets2,
		Direction:           domain.DirectionInbound,
		NormalizationStatus: domain.NormalizationStatusOK,
		Attributes:          map[string]json.RawMessage{},
	}

	// Insert
	_, err = flowRepo.InsertFlowRecords(ctx, []domain.NormalizedFlowRecord{rec1, rec2})
	if err != nil {
		t.Fatalf("InsertFlowRecords failed: %v", err)
	}

	// 3. Test GetFlowByID
	t.Run("GetFlowByID", func(t *testing.T) {
		record, found, err := flowRepo.GetFlowByID(ctx, rec1.ID)
		if err != nil {
			t.Fatalf("GetFlowByID failed: %v", err)
		}
		if !found {
			t.Errorf("Expected to find record %s", rec1.ID)
		}
		if record.IdempotencyKey != rec1.IdempotencyKey {
			t.Errorf("Expected IdempotencyKey %s, got %s", rec1.IdempotencyKey, record.IdempotencyKey)
		}

		_, found, err = flowRepo.GetFlowByID(ctx, "01934d7c-79b4-7000-8b69-999999999999")
		if err != nil {
			t.Fatalf("GetFlowByID for non-existent ID failed: %v", err)
		}
		if found {
			t.Error("Expected not to find non-existent record")
		}

		_, _, err = flowRepo.GetFlowByID(ctx, "invalid-uuid")
		if err == nil {
			t.Error("Expected error for invalid UUID")
		}
	})

	// 4. Test SearchFlows with various filters
	t.Run("SearchFlows Filters", func(t *testing.T) {
		// Time range query
		searchQuery := FlowSearchQuery{
			From:  seedTime.Add(-10 * time.Minute),
			To:    seedTime.Add(10 * time.Minute),
			Limit: 10,
		}
		res, err := flowRepo.SearchFlows(ctx, searchQuery)
		if err != nil {
			t.Fatalf("SearchFlows failed: %v", err)
		}
		if len(res.Records) != 2 {
			t.Errorf("Expected 2 records, got %d", len(res.Records))
		}

		// Filter by SrcIP
		srcIPFilter := netip.MustParseAddr("10.0.0.1")
		searchQuery.SrcIP = &srcIPFilter
		res, err = flowRepo.SearchFlows(ctx, searchQuery)
		if err != nil {
			t.Fatalf("SearchFlows with SrcIP filter failed: %v", err)
		}
		if len(res.Records) != 1 {
			t.Errorf("Expected 1 record, got %d", len(res.Records))
		}
		if res.Records[0].ID != rec2.ID {
			t.Errorf("Expected record ID %s, got %s", rec2.ID, res.Records[0].ID)
		}

		// Filter by CIDR
		searchQuery.SrcIP = nil
		prefix := netip.MustParsePrefix("10.0.0.0/24")
		searchQuery.SrcCIDR = &prefix
		res, err = flowRepo.SearchFlows(ctx, searchQuery)
		if err != nil {
			t.Fatalf("SearchFlows with SrcCIDR filter failed: %v", err)
		}
		if len(res.Records) != 1 {
			t.Errorf("Expected 1 record, got %d", len(res.Records))
		}

		// Filter by SrcPort
		searchQuery.SrcCIDR = nil
		sport := uint16(12345)
		searchQuery.SrcPort = &sport
		res, err = flowRepo.SearchFlows(ctx, searchQuery)
		if err != nil {
			t.Fatalf("SearchFlows with SrcPort filter failed: %v", err)
		}
		if len(res.Records) != 1 || res.Records[0].ID != rec1.ID {
			t.Errorf("Expected record ID %s, got %d records", rec1.ID, len(res.Records))
		}

		// Filter by DstPortRange
		searchQuery.SrcPort = nil
		searchQuery.DstPortRange = &PortRange{From: 440, To: 450}
		res, err = flowRepo.SearchFlows(ctx, searchQuery)
		if err != nil {
			t.Fatalf("SearchFlows with DstPortRange filter failed: %v", err)
		}
		if len(res.Records) != 1 || res.Records[0].ID != rec2.ID {
			t.Errorf("Expected record ID %s, got %d records", rec2.ID, len(res.Records))
		}
	})

	// 5. Test TopPorts
	t.Run("TopPorts", func(t *testing.T) {
		query := AggregationQuery{
			From:      seedTime.Add(-10 * time.Minute),
			To:        seedTime.Add(10 * time.Minute),
			Metric:    AggregationMetricBytes,
			Limit:     10,
			Direction: AggregationDirectionSrc,
		}
		ports, err := flowRepo.TopPorts(ctx, query)
		if err != nil {
			t.Fatalf("TopPorts (src) failed: %v", err)
		}
		if len(ports) != 2 {
			t.Fatalf("Expected 2 port rows, got %d", len(ports))
		}
		// First port is 54321 with bytes 1500
		if ports[0].Port != 54321 || ports[0].Value != 1500 {
			t.Errorf("Expected first port 54321 with value 1500, got %d and %d", ports[0].Port, ports[0].Value)
		}

		query.Direction = AggregationDirectionDst
		portsDst, err := flowRepo.TopPorts(ctx, query)
		if err != nil {
			t.Fatalf("TopPorts (dst) failed: %v", err)
		}
		if len(portsDst) != 2 {
			t.Fatalf("Expected 2 dst port rows, got %d", len(portsDst))
		}
	})

	// 6. Test ProtocolDistribution
	t.Run("ProtocolDistribution", func(t *testing.T) {
		query := AggregationQuery{
			From:   seedTime.Add(-10 * time.Minute),
			To:     seedTime.Add(10 * time.Minute),
			Metric: AggregationMetricPackets,
			Limit:  10,
		}
		protocols, err := flowRepo.ProtocolDistribution(ctx, query)
		if err != nil {
			t.Fatalf("ProtocolDistribution failed: %v", err)
		}
		if len(protocols) != 2 {
			t.Fatalf("Expected 2 protocol rows, got %d", len(protocols))
		}
		// First protocol is UDP (17) with packets 10
		if protocols[0].ProtocolNumber != 17 || protocols[0].Value != 10 {
			t.Errorf("Expected first protocol UDP (17) with packets 10, got %d and %d", protocols[0].ProtocolNumber, protocols[0].Value)
		}
	})
}
