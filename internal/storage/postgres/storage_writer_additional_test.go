package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/observability"
)

type errorInserter struct {
	errs  []error
	calls int
}

func (i *errorInserter) InsertFlowRecords(context.Context, []domain.NormalizedFlowRecord) (InsertResult, error) {
	i.calls++
	if len(i.errs) == 0 {
		return InsertResult{Attempted: 1, Inserted: 1}, nil
	}
	err := i.errs[0]
	i.errs = i.errs[1:]
	if err != nil {
		return InsertResult{}, err
	}
	return InsertResult{Attempted: 1, Inserted: 1}, nil
}

type failingDeadLetterPublisher struct{}

func (failingDeadLetterPublisher) PublishDeadLetter(context.Context, *flowv1.DeadLetterEvent) error {
	return errors.New("dlq publish failed")
}

type failingCommitter struct{}

func (failingCommitter) Commit(context.Context) error { return errors.New("commit failed") }

func TestStorageWriterRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	writer := newTestStorageWriter(t, &fakeInserter{}, &fakeDeadLetterPublisher{})
	var nilCtx context.Context
	if _, err := writer.WriteBatch(nilCtx, nil, nil); !errors.Is(err, ErrInvalidStorageWriter) {
		t.Fatalf("WriteBatch(nil ctx) error = %v, want ErrInvalidStorageWriter", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := writer.WriteBatch(ctx, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("WriteBatch(canceled) error = %v, want context.Canceled", err)
	}
	var nilWriter *StorageWriter
	if _, err := nilWriter.WriteBatch(context.Background(), nil, nil); !errors.Is(err, ErrInvalidStorageWriter) {
		t.Fatalf("nil writer error = %v, want ErrInvalidStorageWriter", err)
	}
}

func TestStorageWriterNewValidationCoversAllConfigFields(t *testing.T) {
	t.Parallel()

	base := config.StorageWriterConfig{
		BatchSize:      1,
		MaxRetries:     0,
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
	}

	cfg := base
	cfg.MaxRetries = -1
	if _, err := NewStorageWriter(cfg, &fakeInserter{}, &fakeDeadLetterPublisher{}); !errors.Is(err, ErrInvalidStorageWriter) {
		t.Fatalf("negative max retries error = %v", err)
	}
	cfg = base
	cfg.InitialBackoff = 0
	if _, err := NewStorageWriter(cfg, &fakeInserter{}, &fakeDeadLetterPublisher{}); !errors.Is(err, ErrInvalidStorageWriter) {
		t.Fatalf("zero initial backoff error = %v", err)
	}
	cfg = base
	cfg.MaxBackoff = 0
	if _, err := NewStorageWriter(cfg, &fakeInserter{}, &fakeDeadLetterPublisher{}); !errors.Is(err, ErrInvalidStorageWriter) {
		t.Fatalf("zero max backoff error = %v", err)
	}
}

func TestStorageWriterRetriesTransientInsertError(t *testing.T) {
	t.Parallel()

	inserter := &errorInserter{errs: []error{errors.New("temporary failure"), nil}}
	writer, err := NewStorageWriter(config.StorageWriterConfig{
		BatchSize:      1,
		MaxRetries:     1,
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
	}, inserter, &fakeDeadLetterPublisher{})
	if err != nil {
		t.Fatalf("NewStorageWriter() error = %v", err)
	}
	writer.sleep = func(context.Context, time.Duration) error { return nil }

	result, err := writer.WriteBatch(context.Background(), []StorageBatchItem{{Record: validStorageRecord("01934d7c-79b4-7000-8b69-001122334455")}}, nil)
	if err != nil {
		t.Fatalf("WriteBatch() error = %v", err)
	}
	if inserter.calls != 2 || result.Inserted != 1 {
		t.Fatalf("calls=%d result=%+v", inserter.calls, result)
	}
}

func TestStorageWriterStopsRetryingOnCheckConstraint(t *testing.T) {
	t.Parallel()

	inserter := &errorInserter{errs: []error{errors.New("violates check constraint")}}
	dlq := &fakeDeadLetterPublisher{}
	writer := newTestStorageWriter(t, inserter, dlq)
	result, err := writer.WriteBatch(context.Background(), []StorageBatchItem{{Record: validStorageRecord("01934d7c-79b4-7000-8b69-001122334455")}}, nil)
	if err != nil {
		t.Fatalf("WriteBatch() error = %v", err)
	}
	if inserter.calls != 1 || result.DeadLettered != 1 || len(dlq.events) != 1 {
		t.Fatalf("calls=%d result=%+v dlq=%d", inserter.calls, result, len(dlq.events))
	}
}

func TestStorageWriterPropagatesSleepAndCommitErrors(t *testing.T) {
	t.Parallel()

	inserter := &errorInserter{errs: []error{errors.New("temporary failure")}}
	writer, err := NewStorageWriter(config.StorageWriterConfig{
		BatchSize:      1,
		MaxRetries:     1,
		InitialBackoff: config.Duration(time.Millisecond),
		MaxBackoff:     config.Duration(time.Millisecond),
	}, inserter, &fakeDeadLetterPublisher{})
	if err != nil {
		t.Fatalf("NewStorageWriter() error = %v", err)
	}
	writer.sleep = func(context.Context, time.Duration) error { return context.Canceled }
	_, err = writer.insertWithRetry(context.Background(), []domain.NormalizedFlowRecord{
		validStorageRecord("01934d7c-79b4-7000-8b69-001122334455"),
	})
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "wait before storage retry") {
		t.Fatalf("sleep error = %v, want wrapped context.Canceled", err)
	}

	writer = newTestStorageWriter(t, &fakeInserter{}, &fakeDeadLetterPublisher{})
	_, err = writer.WriteBatch(context.Background(), []StorageBatchItem{
		{Record: validStorageRecord("01934d7c-79b4-7000-8b69-001122334456")},
	}, failingCommitter{})
	if err == nil || !strings.Contains(err.Error(), "commit storage offsets") {
		t.Fatalf("commit error = %v", err)
	}
}

func TestStorageWriterPropagatesDeadLetterPublishError(t *testing.T) {
	t.Parallel()

	writer := newTestStorageWriter(t, &fakeInserter{}, failingDeadLetterPublisher{})
	record := validStorageRecord("01934d7c-79b4-7000-8b69-001122334455")
	record.SchemaVersion = "bad"
	_, err := writer.WriteBatch(context.Background(), []StorageBatchItem{{Record: record, RawEvent: validRawStorageEvent(record.RawEventID)}}, nil)
	if err == nil || !strings.Contains(err.Error(), "publish storage dead-letter") {
		t.Fatalf("dead-letter publish error = %v", err)
	}
}

func TestStorageWriterHelpers(t *testing.T) {
	t.Parallel()

	if isCheckConstraintViolation(nil) {
		t.Fatal("nil check constraint error = true")
	}
	if !isCheckConstraintViolation(errors.New("SQLSTATE 23514")) {
		t.Fatal("23514 should be detected as check constraint")
	}
	if isCheckConstraintViolation(errors.New("temporary")) {
		t.Fatal("temporary error should not be check constraint")
	}

	writer := newTestStorageWriter(t, &fakeInserter{}, &fakeDeadLetterPublisher{})
	writer.metrics = observability.NewRegistry()
	addIntMetric(writer.metrics, "test_counter", nil, 0)
	addIntMetric(writer.metrics, "test_counter", nil, 2)
	output := string(writer.metrics.WritePrometheus())
	if !strings.Contains(output, "test_counter") {
		t.Fatalf("metric output = %s", output)
	}

	debug := storageDebugPayload(validStorageRecord("01934d7c-79b4-7000-8b69-001122334455"))
	if !strings.Contains(string(debug), "idempotency_key") {
		t.Fatalf("debug payload = %s", debug)
	}
}
