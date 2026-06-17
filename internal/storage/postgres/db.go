package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/adnope/quiver/internal/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var ErrInvalidDatabaseConfig = errors.New("postgres: invalid database config")

func Open(ctx context.Context, cfg config.DatabaseConfig) (*sql.DB, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is nil", ErrInvalidDatabaseConfig)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := validateDatabaseConfig(cfg); err != nil {
		return nil, err
	}

	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open postgres driver: %w", err)
	}
	if err := ConfigurePool(db, cfg); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, errors.Join(err, fmt.Errorf("close postgres after pool config failure: %w", closeErr))
		}
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, errors.Join(
				fmt.Errorf("ping postgres: %w", err),
				fmt.Errorf("close postgres after ping failure: %w", closeErr),
			)
		}
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return db, nil
}

func ConfigurePool(db *sql.DB, cfg config.DatabaseConfig) error {
	if db == nil {
		return fmt.Errorf("%w: db is nil", ErrInvalidDatabaseConfig)
	}
	if err := validateDatabaseConfig(cfg); err != nil {
		return err
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime.Std())
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime.Std())
	return nil
}

func validateDatabaseConfig(cfg config.DatabaseConfig) error {
	if strings.TrimSpace(cfg.DSN) == "" {
		return fmt.Errorf("%w: dsn is required", ErrInvalidDatabaseConfig)
	}
	if strings.TrimSpace(cfg.Schema) == "" {
		return fmt.Errorf("%w: schema is required", ErrInvalidDatabaseConfig)
	}
	if cfg.MaxOpenConns <= 0 {
		return fmt.Errorf("%w: max_open_conns must be positive", ErrInvalidDatabaseConfig)
	}
	if cfg.MaxIdleConns <= 0 {
		return fmt.Errorf("%w: max_idle_conns must be positive", ErrInvalidDatabaseConfig)
	}
	if cfg.MaxIdleConns > cfg.MaxOpenConns {
		return fmt.Errorf("%w: max_idle_conns cannot exceed max_open_conns", ErrInvalidDatabaseConfig)
	}
	if cfg.ConnMaxLifetime <= 0 {
		return fmt.Errorf("%w: conn_max_lifetime must be positive", ErrInvalidDatabaseConfig)
	}
	if cfg.ConnMaxIdleTime <= 0 {
		return fmt.Errorf("%w: conn_max_idle_time must be positive", ErrInvalidDatabaseConfig)
	}
	return nil
}
