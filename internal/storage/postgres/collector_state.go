package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/adnope/quiver/internal/domain"
)

var ErrInvalidState = errors.New("postgres: invalid collector state")

type CollectorStateStore interface {
	Load(ctx context.Context, key string) (CollectorState, bool, error)
	Save(ctx context.Context, state CollectorState) error
}

type CollectorState struct {
	StateKey    string            `json:"state_key"`
	CollectorID string            `json:"collector_id"`
	SourceType  domain.SourceType `json:"source_type"`
	SourceHost  string            `json:"source_host"`
	State       json.RawMessage   `json:"state"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type StateStore struct {
	db *sql.DB
}

func NewStateStore(db *sql.DB) (*StateStore, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: db is nil", ErrInvalidState)
	}
	return &StateStore{db: db}, nil
}

func (s *StateStore) Load(ctx context.Context, key string) (CollectorState, bool, error) {
	if ctx == nil {
		return CollectorState{}, false, fmt.Errorf("%w: context is nil", ErrInvalidState)
	}
	if err := ctx.Err(); err != nil {
		return CollectorState{}, false, fmt.Errorf("load collector state: %w", err)
	}
	if s == nil || s.db == nil {
		return CollectorState{}, false, fmt.Errorf("%w: db is nil", ErrInvalidState)
	}
	if strings.TrimSpace(key) == "" {
		return CollectorState{}, false, fmt.Errorf("%w: state_key is required", ErrInvalidState)
	}

	var state CollectorState
	var sourceType string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT state_key, collector_id, source_type, source_host, state, updated_at
FROM quiver.collector_states
WHERE state_key = $1`,
		key,
	).Scan(
		&state.StateKey,
		&state.CollectorID,
		&sourceType,
		&state.SourceHost,
		&state.State,
		&state.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CollectorState{}, false, nil
		}
		return CollectorState{}, false, fmt.Errorf("query collector state: %w", err)
	}
	state.SourceType = domain.SourceType(sourceType)
	if err := ValidateCollectorState(state); err != nil {
		return CollectorState{}, false, err
	}
	return state, true, nil
}

func (s *StateStore) Save(ctx context.Context, state CollectorState) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", ErrInvalidState)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("save collector state: %w", err)
	}
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: db is nil", ErrInvalidState)
	}
	if err := ValidateCollectorState(state); err != nil {
		return err
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO quiver.collector_states (
    state_key,
    collector_id,
    source_type,
    source_host,
    state,
    updated_at
) VALUES ($1, $2, $3, $4, $5::jsonb, now())
ON CONFLICT (state_key) DO UPDATE SET
    collector_id = EXCLUDED.collector_id,
    source_type = EXCLUDED.source_type,
    source_host = EXCLUDED.source_host,
    state = EXCLUDED.state,
    updated_at = now()`,
		state.StateKey,
		state.CollectorID,
		string(state.SourceType),
		state.SourceHost,
		[]byte(state.State),
	)
	if err != nil {
		return fmt.Errorf("upsert collector state: %w", err)
	}
	return nil
}

func ValidateCollectorState(state CollectorState) error {
	if strings.TrimSpace(state.StateKey) == "" {
		return fmt.Errorf("%w: state_key is required", ErrInvalidState)
	}
	if strings.TrimSpace(state.CollectorID) == "" {
		return fmt.Errorf("%w: collector_id is required", ErrInvalidState)
	}
	if !domain.ValidSourceType(state.SourceType) {
		return fmt.Errorf("%w: invalid source_type", ErrInvalidState)
	}
	if strings.TrimSpace(state.SourceHost) == "" {
		return fmt.Errorf("%w: source_host is required", ErrInvalidState)
	}
	if len(state.State) == 0 || !json.Valid(state.State) {
		return fmt.Errorf("%w: state must be valid json", ErrInvalidState)
	}
	return nil
}
