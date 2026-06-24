package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/adnope/quiver/internal/config"
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

func ApplyStoragePolicies(ctx context.Context, db *sql.DB, cfg config.StorageConfig) error {
	if db == nil {
		return fmt.Errorf("%w: db is nil", ErrInvalidDatabaseConfig)
	}

	if _, err := db.ExecContext(ctx, "SELECT remove_retention_policy('quiver.flow_records', if_exists => true)"); err != nil {
		if !isAlreadyExistsError(err) {
			return fmt.Errorf("remove old retention policy: %w", err)
		}
	}

	retentionDays := cfg.Retention.FlowRecordsDays
	if retentionDays > 0 {
		query := fmt.Sprintf("SELECT add_retention_policy('quiver.flow_records', INTERVAL '%d days', if_not_exists => true)", retentionDays)
		if _, err := db.ExecContext(ctx, query); err != nil {
			if !isAlreadyExistsError(err) {
				return fmt.Errorf("add retention policy: %w", err)
			}
		}
	}

	if _, err := db.ExecContext(ctx, "CALL remove_columnstore_policy('quiver.flow_records', if_exists => true)"); err != nil {
		if !isAlreadyExistsError(err) {
			return fmt.Errorf("remove old columnstore policy: %w", err)
		}
	}
	if cfg.Columnstore.Enabled {
		afterSecs := int64(cfg.Columnstore.After.Std().Seconds())
		if afterSecs > 0 {
			alterQuery := `ALTER TABLE quiver.flow_records SET (
				timescaledb.enable_columnstore = true,
				timescaledb.segmentby = 'source_type,collector_id,source_host',
				timescaledb.orderby = 'event_start_time DESC'
			)`
			if _, err := db.ExecContext(ctx, alterQuery); err != nil {
				if !isAlreadyExistsError(err) {
					return fmt.Errorf("enable columnstore alter table: %w", err)
				}
			}
			query := fmt.Sprintf("CALL add_columnstore_policy('quiver.flow_records', after => INTERVAL '%d seconds', if_not_exists => true)", afterSecs)
			if _, err := db.ExecContext(ctx, query); err != nil {
				if !isAlreadyExistsError(err) {
					return fmt.Errorf("add columnstore policy: %w", err)
				}
			}
		}
	} else {
		if _, err := db.ExecContext(ctx, "ALTER TABLE quiver.flow_records SET (timescaledb.enable_columnstore = false)"); err != nil {
			if !isAlreadyExistsError(err) {
				return fmt.Errorf("disable columnstore alter table: %w", err)
			}
		}
	}

	return nil
}

func isAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "already exists") || strings.Contains(errStr, "42710")
}
