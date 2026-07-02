//go:build integration

package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
)

func TestDB_Integration(t *testing.T) {
	dsn := os.Getenv("QUIVER_TEST_DATABASE_DSN")
	if dsn == "" {
		dsn = os.Getenv("QUIVER_DATABASE_DSN")
	}
	if dsn == "" {
		t.Skip("skipping database integration test")
	}

	cfg := config.DatabaseConfig{
		DSN:             dsn,
		Schema:          "quiver",
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: config.Duration(time.Hour),
		ConnMaxIdleTime: config.Duration(time.Hour),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	storageCfg := config.StorageConfig{
		Retention: config.RetentionConfig{
			FlowRecordsDays: 30,
		},
		Columnstore: config.ColumnstoreConfig{
			Enabled: true,
			After:   config.Duration(time.Hour),
		},
	}

	err = ApplyStoragePolicies(ctx, db, storageCfg)
	if err != nil {
		t.Logf("ApplyStoragePolicies result: %v", err)
	}

	storageCfg.Columnstore.Enabled = false
	_ = ApplyStoragePolicies(ctx, db, storageCfg)

	storageCfg.Columnstore.Enabled = true
	_ = ApplyStoragePolicies(ctx, db, storageCfg)
}
