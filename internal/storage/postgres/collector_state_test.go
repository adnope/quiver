package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
)

const fakeStateDriverName = "quiver_state_store_test"

var (
	registerFakeStateDriver sync.Once
	fakeStateMu             sync.Mutex
	fakeStateDatabases      = map[string]map[string]fakeStateRow{}
)

func TestStateStoreSaveThenLoad(t *testing.T) {
	t.Parallel()

	db := openFakeStateDB(t)
	store, err := NewStateStore(db)
	if err != nil {
		t.Fatalf("NewStateStore() error = %v", err)
	}

	state := validCollectorState(t)
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, found, err := store.Load(context.Background(), state.StateKey)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !found {
		t.Fatal("Load() found = false, want true")
	}
	if loaded.StateKey != state.StateKey ||
		loaded.CollectorID != state.CollectorID ||
		loaded.SourceType != state.SourceType ||
		loaded.SourceHost != state.SourceHost {
		t.Fatalf("loaded state metadata = %+v, want %+v", loaded, state)
	}
	if loaded.UpdatedAt.IsZero() {
		t.Fatal("loaded updated_at is zero")
	}

	var loadedState genericState
	if err := json.Unmarshal(loaded.State, &loadedState); err != nil {
		t.Fatalf("unmarshal loaded state: %v", err)
	}
	if loadedState.Offset != 128 || loadedState.Cursor != "first" {
		t.Fatalf("loaded state = %+v", loadedState)
	}

	updatedState := state
	updatedState.State = json.RawMessage(`{"cursor":"second","offset":256}`)
	if err := store.Save(context.Background(), updatedState); err != nil {
		t.Fatalf("Save(updated) error = %v", err)
	}

	loaded, found, err = store.Load(context.Background(), state.StateKey)
	if err != nil {
		t.Fatalf("Load(updated) error = %v", err)
	}
	if !found {
		t.Fatal("Load(updated) found = false, want true")
	}
	if err := json.Unmarshal(loaded.State, &loadedState); err != nil {
		t.Fatalf("unmarshal updated state: %v", err)
	}
	if loadedState.Offset != 256 || loadedState.Cursor != "second" {
		t.Fatalf("updated state = %+v", loadedState)
	}
}

func TestStateStoreLoadMissing(t *testing.T) {
	t.Parallel()

	db := openFakeStateDB(t)
	store, err := NewStateStore(db)
	if err != nil {
		t.Fatalf("NewStateStore() error = %v", err)
	}

	_, found, err := store.Load(context.Background(), "missing")
	if err != nil {
		t.Fatalf("Load(missing) error = %v", err)
	}
	if found {
		t.Fatal("Load(missing) found = true, want false")
	}
}

func TestStateStoreRejectsInvalidState(t *testing.T) {
	t.Parallel()

	db := openFakeStateDB(t)
	store, err := NewStateStore(db)
	if err != nil {
		t.Fatalf("NewStateStore() error = %v", err)
	}

	state := validCollectorState(t)
	state.State = json.RawMessage(`{invalid-json`)
	err = store.Save(context.Background(), state)
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Save(invalid) error = %v, want ErrInvalidState", err)
	}
}

func TestStateStoreHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	db := openFakeStateDB(t)
	store, err := NewStateStore(db)
	if err != nil {
		t.Fatalf("NewStateStore() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err = store.Load(ctx, "state-key")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Load(canceled) error = %v, want context.Canceled", err)
	}
	err = store.Save(ctx, validCollectorState(t))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Save(canceled) error = %v, want context.Canceled", err)
	}
}

func TestStateStoreConstructorsValidateInputs(t *testing.T) {
	t.Parallel()

	if _, err := NewStateStore(nil); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("NewStateStore(nil) error = %v, want ErrInvalidState", err)
	}
	var nilStore *StateStore
	if _, _, err := nilStore.Load(context.Background(), "state-key"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("nil StateStore.Load() error = %v, want ErrInvalidState", err)
	}
	if err := nilStore.Save(context.Background(), validCollectorState(t)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("nil StateStore.Save() error = %v, want ErrInvalidState", err)
	}

	invalid := validCollectorState(t)
	invalid.SourceHost = ""
	if err := ValidateCollectorState(invalid); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("ValidateCollectorState(invalid) error = %v, want ErrInvalidState", err)
	}
}

func TestConfigurePool(t *testing.T) {
	t.Parallel()

	db := openFakeStateDB(t)
	cfg := config.Default().Database
	cfg.DSN = "fake://pool"

	if err := ConfigurePool(db, cfg); err != nil {
		t.Fatalf("ConfigurePool() error = %v", err)
	}
	if got := db.Stats().MaxOpenConnections; got != cfg.MaxOpenConns {
		t.Fatalf("MaxOpenConnections = %d, want %d", got, cfg.MaxOpenConns)
	}

	cfg.MaxIdleConns = cfg.MaxOpenConns + 1
	if err := ConfigurePool(db, cfg); !errors.Is(err, ErrInvalidDatabaseConfig) {
		t.Fatalf("ConfigurePool(invalid) error = %v, want ErrInvalidDatabaseConfig", err)
	}
	if err := ConfigurePool(nil, config.Default().Database); !errors.Is(err, ErrInvalidDatabaseConfig) {
		t.Fatalf("ConfigurePool(nil) error = %v, want ErrInvalidDatabaseConfig", err)
	}
}

func TestOpenHonorsCanceledContextBeforeDial(t *testing.T) {
	t.Parallel()

	cfg := config.Default().Database
	cfg.DSN = "postgres://user:pass@127.0.0.1:1/quiver?sslmode=disable"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	db, err := Open(ctx, cfg)
	if db != nil {
		t.Fatal("Open(canceled) returned non-nil db")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Open(canceled) error = %v, want context.Canceled", err)
	}
}

func validCollectorState(t *testing.T) CollectorState {
	t.Helper()

	state := CollectorState{
		StateKey:    "rest-ingest-main:rest_json:rest-demo-client",
		CollectorID: "rest-ingest-main",
		SourceType:  domain.SourceTypeRESTJSON,
		SourceHost:  "rest-demo-client",
		State:       json.RawMessage(`{"cursor":"first","offset":128}`),
	}
	if err := ValidateCollectorState(state); err != nil {
		t.Fatalf("ValidateCollectorState() error = %v", err)
	}
	return state
}

type genericState struct {
	Cursor string `json:"cursor"`
	Offset int64  `json:"offset"`
}

func openFakeStateDB(t *testing.T) *sql.DB {
	t.Helper()

	registerFakeStateDriver.Do(func() {
		sql.Register(fakeStateDriverName, fakeStateDriver{})
	})
	dsn := fmt.Sprintf("%s-%d", strings.NewReplacer("/", "-", " ", "-").Replace(t.Name()), time.Now().UnixNano())

	fakeStateMu.Lock()
	fakeStateDatabases[dsn] = map[string]fakeStateRow{}
	fakeStateMu.Unlock()

	db, err := sql.Open(fakeStateDriverName, dsn)
	if err != nil {
		t.Fatalf("open fake sql db: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close fake sql db: %v", err)
		}
		fakeStateMu.Lock()
		delete(fakeStateDatabases, dsn)
		fakeStateMu.Unlock()
	})
	return db
}

type fakeStateDriver struct{}

func (fakeStateDriver) Open(name string) (driver.Conn, error) {
	return fakeStateConn{dsn: name}, nil
}

type fakeStateConn struct {
	dsn string
}

func (c fakeStateConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("fake state driver does not support prepared statements")
}

func (c fakeStateConn) Close() error {
	return nil
}

func (c fakeStateConn) Begin() (driver.Tx, error) {
	return nil, errors.New("fake state driver does not support transactions")
}

func (c fakeStateConn) Ping(ctx context.Context) error {
	return ctx.Err()
}

func (c fakeStateConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !strings.Contains(query, "INSERT INTO quiver.collector_states") {
		return nil, fmt.Errorf("unexpected exec query: %s", query)
	}
	if len(args) != 5 {
		return nil, fmt.Errorf("exec arg count = %d, want 5", len(args))
	}

	stateKey, err := namedString(args[0])
	if err != nil {
		return nil, fmt.Errorf("state_key: %w", err)
	}
	collectorID, err := namedString(args[1])
	if err != nil {
		return nil, fmt.Errorf("collector_id: %w", err)
	}
	sourceType, err := namedString(args[2])
	if err != nil {
		return nil, fmt.Errorf("source_type: %w", err)
	}
	sourceHost, err := namedString(args[3])
	if err != nil {
		return nil, fmt.Errorf("source_host: %w", err)
	}
	stateJSON, err := namedBytes(args[4])
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}

	fakeStateMu.Lock()
	defer fakeStateMu.Unlock()
	database, ok := fakeStateDatabases[c.dsn]
	if !ok {
		return nil, fmt.Errorf("unknown fake database %q", c.dsn)
	}
	database[stateKey] = fakeStateRow{
		stateKey:    stateKey,
		collectorID: collectorID,
		sourceType:  sourceType,
		sourceHost:  sourceHost,
		state:       stateJSON,
		updatedAt:   time.Now().UTC(),
	}
	return driver.RowsAffected(1), nil
}

func (c fakeStateConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !strings.Contains(query, "FROM quiver.collector_states") {
		return nil, fmt.Errorf("unexpected query: %s", query)
	}
	if len(args) != 1 {
		return nil, fmt.Errorf("query arg count = %d, want 1", len(args))
	}
	stateKey, err := namedString(args[0])
	if err != nil {
		return nil, fmt.Errorf("state_key: %w", err)
	}

	fakeStateMu.Lock()
	row, ok := fakeStateDatabases[c.dsn][stateKey]
	fakeStateMu.Unlock()
	if !ok {
		return &fakeRows{}, nil
	}
	return &fakeRows{
		values: []driver.Value{
			row.stateKey,
			row.collectorID,
			row.sourceType,
			row.sourceHost,
			append([]byte(nil), row.state...),
			row.updatedAt,
		},
	}, nil
}

type fakeStateRow struct {
	stateKey    string
	collectorID string
	sourceType  string
	sourceHost  string
	state       []byte
	updatedAt   time.Time
}

type fakeRows struct {
	values   []driver.Value
	consumed bool
}

func (r *fakeRows) Columns() []string {
	return []string{"state_key", "collector_id", "source_type", "source_host", "state", "updated_at"}
}

func (r *fakeRows) Close() error {
	return nil
}

func (r *fakeRows) Next(dest []driver.Value) error {
	if r.consumed || len(r.values) == 0 {
		return io.EOF
	}
	copy(dest, r.values)
	r.consumed = true
	return nil
}

func namedString(arg driver.NamedValue) (string, error) {
	value, ok := arg.Value.(string)
	if !ok {
		return "", fmt.Errorf("value has type %T, want string", arg.Value)
	}
	return value, nil
}

func namedBytes(arg driver.NamedValue) ([]byte, error) {
	switch value := arg.Value.(type) {
	case []byte:
		return append([]byte(nil), value...), nil
	case string:
		return []byte(value), nil
	default:
		return nil, fmt.Errorf("value has type %T, want []byte", arg.Value)
	}
}
