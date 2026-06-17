package zeek

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/storage/postgres"
)

func TestCollectorProcessesCompleteLinesAndLeavesPartialEOF(t *testing.T) {
	t.Parallel()

	path := writeZeekFile(t, validConnLine()+"\n"+"{bad-json\n"+"{\"ts\":1718532921")
	state := newMemoryStateStore()
	publisher := &fakePublisher{}
	collector := newTestCollector(t, path, state, publisher)

	if err := collector.ProcessOnce(context.Background()); err != nil {
		t.Fatalf("ProcessOnce() error = %v", err)
	}
	if len(publisher.raw) != 1 {
		t.Fatalf("raw events = %d, want 1", len(publisher.raw))
	}
	if len(publisher.deadLetters) != 1 {
		t.Fatalf("dead letters = %d, want 1", len(publisher.deadLetters))
	}
	saved, found, err := state.Load(context.Background(), "zeek-test-state")
	if err != nil || !found {
		t.Fatalf("state Load() found=%v err=%v", found, err)
	}
	var zeekState postgres.ZeekState
	if err := json.Unmarshal(saved.State, &zeekState); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	wantOffset := int64(len(validConnLine()+"\n") + len("{bad-json\n"))
	if zeekState.Offset != wantOffset {
		t.Fatalf("offset = %d, want %d", zeekState.Offset, wantOffset)
	}
	if string(publisher.deadLetters[0].GetRawPayloadDebug().GetData()) != `{"masked":true}` {
		t.Fatalf("DLQ payload was not redacted: %q", publisher.deadLetters[0].GetRawPayloadDebug().GetData())
	}
}

func TestCollectorStateOverridesStartPosition(t *testing.T) {
	t.Parallel()

	path := writeZeekFile(t, validConnLine()+"\n")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	deviceID, inode := fileIdentity(info)
	state := newMemoryStateStore()
	initial, err := postgres.NewZeekCollectorState("zeek-test-state", "zeek-test", "zeek-host", postgres.ZeekState{
		FilePath:        path,
		DeviceID:        deviceID,
		Inode:           inode,
		Offset:          0,
		LastFileSize:    info.Size(),
		LastCommittedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("NewZeekCollectorState() error = %v", err)
	}
	if err := state.Save(context.Background(), initial); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	publisher := &fakePublisher{}
	collector := newTestCollector(t, path, state, publisher)
	collector.cfg.StartPosition = "end"

	if err := collector.ProcessOnce(context.Background()); err != nil {
		t.Fatalf("ProcessOnce() error = %v", err)
	}
	if len(publisher.raw) != 1 {
		t.Fatalf("raw events = %d, want 1", len(publisher.raw))
	}
}

func TestCollectorQueueFullDoesNotCommitOffset(t *testing.T) {
	t.Parallel()

	path := writeZeekFile(t, validConnLine()+"\n")
	state := newMemoryStateStore()
	publisher := &fakePublisher{publishErr: kafka.ErrQueueFull}
	collector := newTestCollector(t, path, state, publisher)

	err := collector.ProcessOnce(context.Background())
	if !errors.Is(err, kafka.ErrQueueFull) {
		t.Fatalf("ProcessOnce() error = %v, want ErrQueueFull", err)
	}
	if _, found, err := state.Load(context.Background(), "zeek-test-state"); err != nil || found {
		t.Fatalf("state found=%v err=%v, want no committed offset", found, err)
	}
}

func newTestCollector(t *testing.T, path string, state postgres.CollectorStateStore, publisher *fakePublisher) *Collector {
	t.Helper()

	collector, err := NewCollector(config.ZeekCollectorConfig{
		Enabled:       true,
		CollectorID:   "zeek-test",
		SourceHost:    "zeek-host",
		FilePath:      path,
		PollInterval:  config.Duration(time.Millisecond),
		StartPosition: "beginning",
		MaxLineBytes:  4096,
		StateKey:      "zeek-test-state",
	}, state, publisher, nil, slog.Default())
	if err != nil {
		t.Fatalf("NewCollector() error = %v", err)
	}
	collector.now = func() time.Time { return time.Date(2026, 6, 18, 1, 0, 0, 0, time.UTC) }
	return collector
}

func writeZeekFile(t *testing.T, content string) string {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "conn-*.log")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	return file.Name()
}

func validConnLine() string {
	return `{"ts":1718532920.125,"uid":"C1","id.orig_h":"192.0.2.10","id.orig_p":51524,"id.resp_h":"198.51.100.20","id.resp_p":443,"proto":"tcp","orig_bytes":120,"resp_bytes":340}`
}

type fakePublisher struct {
	mu          sync.Mutex
	raw         []*flowv1.RawFlowEventEnvelope
	deadLetters []*flowv1.DeadLetterEvent
	publishErr  error
}

func (p *fakePublisher) PublishRaw(_ context.Context, event *flowv1.RawFlowEventEnvelope) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.publishErr != nil {
		return p.publishErr
	}
	p.raw = append(p.raw, event)
	return nil
}

func (p *fakePublisher) PublishDeadLetter(_ context.Context, event *flowv1.DeadLetterEvent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deadLetters = append(p.deadLetters, event)
	return nil
}

func (p *fakePublisher) Flush(context.Context) error {
	return nil
}

type memoryStateStore struct {
	mu     sync.Mutex
	states map[string]postgres.CollectorState
}

func newMemoryStateStore() *memoryStateStore {
	return &memoryStateStore{states: map[string]postgres.CollectorState{}}
}

func (s *memoryStateStore) Load(_ context.Context, key string) (postgres.CollectorState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, found := s.states[key]
	return state, found, nil
}

func (s *memoryStateStore) Save(_ context.Context, state postgres.CollectorState) error {
	if err := postgres.ValidateCollectorState(state); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.StateKey] = state
	return nil
}

var _ kafka.RawEventPublisher = (*fakePublisher)(nil)
var _ postgres.CollectorStateStore = (*memoryStateStore)(nil)
