package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
)

func TestDB_IsAlreadyExistsError(t *testing.T) {
	t.Parallel()

	if isAlreadyExistsError(nil) {
		t.Error("nil error should not be already exists")
	}
	if !isAlreadyExistsError(errors.New("relation already exists")) {
		t.Error("relation already exists should match")
	}
	if !isAlreadyExistsError(errors.New("error code 42710 occurred")) {
		t.Error("error code 42710 should match")
	}
	if isAlreadyExistsError(errors.New("generic error")) {
		t.Error("generic error should not match")
	}
}

func TestDB_ConfigurePool_Errors(t *testing.T) {
	t.Parallel()

	err := ConfigurePool(nil, config.DatabaseConfig{})
	if err == nil {
		t.Error("expected error for nil DB")
	}

	db := &sql.DB{}
	cfg := config.DatabaseConfig{}

	err = ConfigurePool(db, cfg)
	if err == nil {
		t.Error("expected error for missing DSN")
	}

	cfg.DSN = "dsn"
	err = ConfigurePool(db, cfg)
	if err == nil {
		t.Error("expected error for missing Schema")
	}

	cfg.Schema = "quiver"
	cfg.MaxOpenConns = -1
	err = ConfigurePool(db, cfg)
	if err == nil {
		t.Error("expected error for negative MaxOpenConns")
	}

	cfg.MaxOpenConns = 10
	cfg.MaxIdleConns = -1
	err = ConfigurePool(db, cfg)
	if err == nil {
		t.Error("expected error for negative MaxIdleConns")
	}

	cfg.MaxIdleConns = 20
	err = ConfigurePool(db, cfg)
	if err == nil {
		t.Error("expected error for MaxIdleConns > MaxOpenConns")
	}

	cfg.MaxIdleConns = 5
	cfg.ConnMaxLifetime = config.Duration(-time.Hour)
	err = ConfigurePool(db, cfg)
	if err == nil {
		t.Error("expected error for negative ConnMaxLifetime")
	}

	cfg.ConnMaxLifetime = config.Duration(time.Hour)
	cfg.ConnMaxIdleTime = config.Duration(-time.Hour)
	err = ConfigurePool(db, cfg)
	if err == nil {
		t.Error("expected error for negative ConnMaxIdleTime")
	}
}

func TestDB_Open_Errors(t *testing.T) {
	t.Parallel()

	var nilCtx context.Context
	_, err := Open(nilCtx, config.DatabaseConfig{})
	if err == nil {
		t.Error("expected error for nil context")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Open(ctx, config.DatabaseConfig{})
	if err == nil {
		t.Error("expected error for canceled context")
	}

	_, err = Open(context.Background(), config.DatabaseConfig{})
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestDB_ApplyStoragePolicies_NilDB(t *testing.T) {
	t.Parallel()

	err := ApplyStoragePolicies(context.Background(), nil, config.StorageConfig{})
	if err == nil {
		t.Error("expected error for nil DB")
	}
}
