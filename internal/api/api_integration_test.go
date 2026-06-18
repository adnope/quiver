//go:build integration

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/observability"
	"github.com/adnope/quiver/internal/storage/postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func TestAPIIntegrationWithTimescaleDB(t *testing.T) {
	dsn := os.Getenv("QUIVER_TEST_DATABASE_DSN")
	if dsn == "" {
		dsn = os.Getenv("QUIVER_DATABASE_DSN")
	}
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/quiver?sslmode=disable"
	}

	// 1. Run Migrations
	migrator, err := migrate.New("file://../storage/postgres/migrations", dsn)
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

	// Clear out database flow_records
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "DELETE FROM quiver.flow_records"); err != nil {
		t.Fatalf("Failed to clear flow_records: %v", err)
	}

	flowRepo, err := postgres.NewFlowRepository(db)
	if err != nil {
		t.Fatalf("Failed to create FlowRepository: %v", err)
	}

	// Seed some records directly in the DB so query works
	seedTime := time.Date(2026, 6, 18, 2, 0, 0, 0, time.UTC)
	rec1 := validDomainRecord("01934d7c-79b4-7000-8b69-001122330001", "sha-seed-1", seedTime, "192.168.1.10", "8.8.8.8", 80, 1000, 10)
	rec2 := validDomainRecord("01934d7c-79b4-7000-8b69-001122330002", "sha-seed-2", seedTime.Add(10*time.Second), "192.168.1.20", "8.8.8.8", 443, 2000, 20)
	rec3 := validDomainRecord("01934d7c-79b4-7000-8b69-001122330003", "sha-seed-3", seedTime.Add(20*time.Second), "8.8.8.8", "192.168.1.10", 53, 500, 5)

	_, err = flowRepo.InsertFlowRecords(ctx, []domain.NormalizedFlowRecord{rec1, rec2, rec3})
	if err != nil {
		t.Fatalf("Failed to seed flow records: %v", err)
	}

	// Configuration for test
	cfg := config.Default()
	cfg.API.Cursor.HMACSecretEnv = "HMAC_SECRET"
	cfg.API.Keys = []config.APIKeyConfig{
		{Name: "admin", KeyEnv: "ADMIN_KEY", Scopes: []string{"ingest", "query", "metrics"}},
		{Name: "client", KeyEnv: "CLIENT_KEY", Scopes: []string{"query"}},
	}
	cfg.RestIngest.Enabled = true
	cfg.RestIngest.APIKeys = []config.RESTAPIKeyConfig{
		{Name: "client", SourceHost: "client-host", KeyEnv: "CLIENT_KEY"},
	}

	lookupEnv := func(key string) string {
		switch key {
		case "HMAC_SECRET":
			return "verysecretkey_mustbe32byteslong!!!"
		case "ADMIN_KEY":
			return "adminsecret123"
		case "CLIENT_KEY":
			return "clientsecret456"
		default:
			return ""
		}
	}

	metrics := observability.NewRegistry()
	publisher := &fakePublisher{}
	server, err := NewServerWithObservability(cfg, publisher, flowRepo, flowRepo, lookupEnv, metrics, StaticHealthChecker{Value: HealthOK})
	if err != nil {
		t.Fatalf("Failed to create Server: %v", err)
	}

	// 3. Test Query API: GET /api/v1/flows
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/flows?from=%s&to=%s&limit=2", seedTime.Add(-10*time.Minute).Format(time.RFC3339), seedTime.Add(10*time.Minute).Format(time.RFC3339)), nil)
	req.Header.Set("X-API-Key", "clientsecret456")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/flows returned status %d: %s", w.Code, w.Body.String())
	}

	var searchResp struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &searchResp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(searchResp.Items) != 2 {
		t.Errorf("Expected 2 records, got %d", len(searchResp.Items))
	}

	// Verify cursor pagination works
	if searchResp.NextCursor == "" {
		t.Error("Expected next_cursor to be populated")
	} else {
		reqPagination := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/flows?from=%s&to=%s&cursor=%s", seedTime.Add(-10*time.Minute).Format(time.RFC3339), seedTime.Add(10*time.Minute).Format(time.RFC3339), searchResp.NextCursor), nil)
		reqPagination.Header.Set("X-API-Key", "clientsecret456")
		wPagination := httptest.NewRecorder()
		server.Handler().ServeHTTP(wPagination, reqPagination)

		if wPagination.Code != http.StatusOK {
			t.Errorf("Pagination query returned status %d: %s", wPagination.Code, wPagination.Body.String())
		}
	}

	// 4. Test Query aggregations
	reqAgg := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/aggregations/top-talkers?from=%s&to=%s&direction=src", seedTime.Add(-10*time.Minute).Format(time.RFC3339), seedTime.Add(10*time.Minute).Format(time.RFC3339)), nil)
	reqAgg.Header.Set("X-API-Key", "clientsecret456")
	wAgg := httptest.NewRecorder()
	server.Handler().ServeHTTP(wAgg, reqAgg)

	if wAgg.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/aggregations/top-talkers returned status %d: %s", wAgg.Code, wAgg.Body.String())
	}

	// 5. Test metrics auth & output
	reqMetrics := httptest.NewRequest("GET", "/metrics", nil)
	reqMetrics.Header.Set("X-API-Key", "adminsecret123")
	wMetrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(wMetrics, reqMetrics)

	if wMetrics.Code != http.StatusOK {
		t.Fatalf("GET /metrics returned status %d: %s", wMetrics.Code, wMetrics.Body.String())
	}
	if !strings.Contains(wMetrics.Body.String(), "http_requests_total") {
		t.Errorf("Metrics missing expected metric name: %s", wMetrics.Body.String())
	}
}

func validDomainRecord(id string, idempotencyKey string, start time.Time, src, dst string, dstPort uint16, bytes uint64, packets uint64) domain.NormalizedFlowRecord {
	srcPort := uint16(12345)
	return domain.NormalizedFlowRecord{
		ID:                  id,
		SchemaVersion:       domain.FlowSchemaVersion,
		IdempotencyKey:      idempotencyKey,
		RawEventID:          "01934d7c-79b4-7000-8b69-001122334457",
		SourceType:          domain.SourceTypeRESTJSON,
		CollectorID:         "rest-ingest-main",
		SourceHost:          "rest-client-host",
		IngestedAt:          start,
		NormalizedAt:        start,
		EventStartTime:      start,
		SrcIP:               netip.MustParseAddr(src),
		DstIP:               netip.MustParseAddr(dst),
		SrcPort:             &srcPort,
		DstPort:             &dstPort,
		IPVersion:           4,
		TransportProtocol:   domain.TransportProtocolTCP,
		ProtocolNumber:      6,
		Bytes:               &bytes,
		Packets:             &packets,
		Direction:           domain.DirectionOutbound,
		NormalizationStatus: domain.NormalizationStatusOK,
		Attributes:          map[string]json.RawMessage{},
	}
}

type fakePublisher struct{}

func (p *fakePublisher) PublishRaw(ctx context.Context, event *flowv1.RawFlowEventEnvelope) error {
	return nil
}

func (p *fakePublisher) PublishDeadLetter(ctx context.Context, event *flowv1.DeadLetterEvent) error {
	return nil
}

func (p *fakePublisher) Flush(ctx context.Context) error {
	return nil
}

var _ kafka.RawEventPublisher = (*fakePublisher)(nil)
