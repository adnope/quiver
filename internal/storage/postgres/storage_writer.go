package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/observability"
	"github.com/adnope/quiver/internal/validation"
)

var ErrInvalidStorageWriter = errors.New("postgres: invalid storage writer")

type FlowRecordInserter interface {
	InsertFlowRecords(ctx context.Context, records []domain.NormalizedFlowRecord) (InsertResult, error)
}

type DeadLetterPublisher interface {
	PublishDeadLetter(ctx context.Context, event *flowv1.DeadLetterEvent) error
}

type OffsetCommitter interface {
	Commit(ctx context.Context) error
}

type StorageBatchItem struct {
	Record   domain.NormalizedFlowRecord
	RawEvent *flowv1.RawFlowEventEnvelope
}

type StorageWriteResult struct {
	Attempted    int
	Inserted     int
	Deduplicated int
	DeadLettered int
}

type StorageWriter struct {
	inserter          FlowRecordInserter
	deadLetters       DeadLetterPublisher
	batchSize         int
	insertConcurrency int
	maxRetries        int
	initialBackoff    time.Duration
	maxBackoff        time.Duration
	now               func() time.Time
	sleep             func(context.Context, time.Duration) error
	metrics           *observability.Registry
}

func NewStorageWriter(
	cfg config.StorageWriterConfig,
	inserter FlowRecordInserter,
	deadLetters DeadLetterPublisher,
) (*StorageWriter, error) {
	if inserter == nil {
		return nil, fmt.Errorf("%w: inserter is nil", ErrInvalidStorageWriter)
	}
	if deadLetters == nil {
		return nil, fmt.Errorf("%w: dead-letter publisher is nil", ErrInvalidStorageWriter)
	}
	if cfg.BatchSize <= 0 {
		return nil, fmt.Errorf("%w: batch_size must be positive", ErrInvalidStorageWriter)
	}
	if cfg.InsertConcurrency <= 0 || cfg.InsertConcurrency > config.DefaultMaxStorageInsertConcurrency {
		return nil, fmt.Errorf("%w: insert_concurrency must be within 1..32", ErrInvalidStorageWriter)
	}
	if cfg.MaxRetries < 0 {
		return nil, fmt.Errorf("%w: max_retries cannot be negative", ErrInvalidStorageWriter)
	}
	if cfg.InitialBackoff <= 0 || cfg.MaxBackoff <= 0 {
		return nil, fmt.Errorf("%w: backoff durations must be positive", ErrInvalidStorageWriter)
	}
	return &StorageWriter{
		inserter:          inserter,
		deadLetters:       deadLetters,
		batchSize:         cfg.BatchSize,
		insertConcurrency: cfg.InsertConcurrency,
		maxRetries:        cfg.MaxRetries,
		initialBackoff:    cfg.InitialBackoff.Std(),
		maxBackoff:        cfg.MaxBackoff.Std(),
		now:               time.Now,
		sleep:             sleepContext,
	}, nil
}

func (w *StorageWriter) WithMetrics(metrics *observability.Registry) *StorageWriter {
	if w != nil {
		w.metrics = metrics
	}
	return w
}

func (w *StorageWriter) WriteBatch(
	ctx context.Context,
	items []StorageBatchItem,
	committer OffsetCommitter,
) (StorageWriteResult, error) {
	if ctx == nil {
		return StorageWriteResult{}, fmt.Errorf("%w: context is nil", ErrInvalidStorageWriter)
	}
	if err := ctx.Err(); err != nil {
		return StorageWriteResult{}, fmt.Errorf("write storage batch: %w", err)
	}
	if w == nil || w.inserter == nil || w.deadLetters == nil {
		return StorageWriteResult{}, fmt.Errorf("%w: writer is not initialized", ErrInvalidStorageWriter)
	}
	start := time.Now()

	var result StorageWriteResult
	valid := make([]StorageBatchItem, 0, len(items))
	for _, item := range items {
		result.Attempted++
		if err := domain.ValidateNormalizedFlowRecord(item.Record); err != nil {
			if err := w.publishStorageDeadLetter(ctx, item, err); err != nil {
				return StorageWriteResult{}, err
			}
			result.DeadLettered++
			continue
		}
		valid = append(valid, item)
	}

	insertResult, err := w.writeValidItems(ctx, valid)
	if err != nil {
		return StorageWriteResult{}, err
	}
	result.Inserted += insertResult.Inserted
	result.Deduplicated += insertResult.Deduplicated
	result.DeadLettered += insertResult.DeadLettered

	if committer != nil {
		if err := committer.Commit(ctx); err != nil {
			return StorageWriteResult{}, fmt.Errorf("commit storage offsets: %w", err)
		}
	}
	w.recordMetrics(result, start)
	return result, nil
}

func (w *StorageWriter) writeValidItems(ctx context.Context, items []StorageBatchItem) (StorageWriteResult, error) {
	chunks := splitStorageBatchItems(items, w.batchSize)
	if len(chunks) == 0 {
		return StorageWriteResult{}, nil
	}
	if w.insertConcurrency == 1 || len(chunks) == 1 {
		return w.writeValidItemsSerial(ctx, chunks)
	}
	return w.writeValidItemsParallel(ctx, chunks)
}

func (w *StorageWriter) writeValidItemsSerial(ctx context.Context, chunks [][]StorageBatchItem) (StorageWriteResult, error) {
	var result StorageWriteResult
	for _, chunk := range chunks {
		insertResult, err := w.insertWithIsolation(ctx, chunk)
		if err != nil {
			return StorageWriteResult{}, err
		}
		result.Inserted += insertResult.Inserted
		result.Deduplicated += insertResult.Deduplicated
		result.DeadLettered += insertResult.DeadLettered
	}
	return result, nil
}

type storageInsertChunkResult struct {
	result StorageWriteResult
	err    error
}

func (w *StorageWriter) writeValidItemsParallel(ctx context.Context, chunks [][]StorageBatchItem) (StorageWriteResult, error) {
	workerCount := min(w.insertConcurrency, len(chunks))
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan []StorageBatchItem)
	results := make(chan storageInsertChunkResult, len(chunks))
	var wg sync.WaitGroup
	for range workerCount {
		wg.Go(func() {
			for chunk := range jobs {
				if err := workCtx.Err(); err != nil {
					results <- storageInsertChunkResult{err: err}
					continue
				}
				insertResult, err := w.insertWithIsolation(workCtx, chunk)
				if err != nil {
					cancel()
				}
				results <- storageInsertChunkResult{result: insertResult, err: err}
			}
		})
	}

	dispatched := 0
	for _, chunk := range chunks {
		if err := workCtx.Err(); err != nil {
			break
		}
		select {
		case jobs <- chunk:
			dispatched++
		case <-workCtx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	close(results)

	var result StorageWriteResult
	var firstErr error
	for insertResult := range results {
		if insertResult.err != nil && firstErr == nil {
			firstErr = insertResult.err
		}
		result.Inserted += insertResult.result.Inserted
		result.Deduplicated += insertResult.result.Deduplicated
		result.DeadLettered += insertResult.result.DeadLettered
	}
	if firstErr != nil {
		return StorageWriteResult{}, firstErr
	}
	if dispatched < len(chunks) {
		if err := workCtx.Err(); err != nil {
			return StorageWriteResult{}, fmt.Errorf("write storage chunks: %w", err)
		}
		return StorageWriteResult{}, fmt.Errorf("write storage chunks: dispatched %d of %d chunks", dispatched, len(chunks))
	}
	return result, nil
}

func splitStorageBatchItems(items []StorageBatchItem, batchSize int) [][]StorageBatchItem {
	if len(items) == 0 {
		return nil
	}
	chunks := make([][]StorageBatchItem, 0, (len(items)+batchSize-1)/batchSize)
	for len(items) > 0 {
		size := min(len(items), batchSize)
		chunks = append(chunks, items[:size])
		items = items[size:]
	}
	return chunks
}

func (w *StorageWriter) insertWithIsolation(ctx context.Context, items []StorageBatchItem) (StorageWriteResult, error) {
	records := make([]domain.NormalizedFlowRecord, len(items))
	for i, item := range items {
		records[i] = item.Record
	}
	insertResult, err := w.insertWithRetry(ctx, records)
	if err == nil {
		return StorageWriteResult{
			Attempted:    insertResult.Attempted,
			Inserted:     insertResult.Inserted,
			Deduplicated: insertResult.Deduplicated,
		}, nil
	}
	if len(items) == 1 {
		if dlqErr := w.publishStorageDeadLetter(ctx, items[0], err); dlqErr != nil {
			return StorageWriteResult{}, dlqErr
		}
		return StorageWriteResult{Attempted: 1, DeadLettered: 1}, nil
	}
	mid := len(items) / 2
	left, leftErr := w.insertWithIsolation(ctx, items[:mid])
	if leftErr != nil {
		return StorageWriteResult{}, leftErr
	}
	right, rightErr := w.insertWithIsolation(ctx, items[mid:])
	if rightErr != nil {
		return StorageWriteResult{}, rightErr
	}
	return StorageWriteResult{
		Attempted:    left.Attempted + right.Attempted,
		Inserted:     left.Inserted + right.Inserted,
		Deduplicated: left.Deduplicated + right.Deduplicated,
		DeadLettered: left.DeadLettered + right.DeadLettered,
	}, nil
}

func (w *StorageWriter) recordMetrics(result StorageWriteResult, start time.Time) {
	if w.metrics == nil {
		return
	}
	w.metrics.Inc("storage_insert_batches_total", map[string]string{"status": "ok"})
	addIntMetric(w.metrics, "storage_insert_records_total", map[string]string{"status": "inserted"}, result.Inserted)
	addIntMetric(w.metrics, "storage_deduplicated_records_total", nil, result.Deduplicated)
	addIntMetric(w.metrics, "storage_bad_rows_total", map[string]string{"reason": "invalid_or_isolated"}, result.DeadLettered)
	w.metrics.ObserveDuration("storage_insert_duration", nil, start)
}

func addIntMetric(metrics *observability.Registry, name string, labels map[string]string, value int) {
	if value <= 0 {
		return
	}
	// Storage counters are bounded by the configured batch size and validated as non-negative.
	metrics.Add(name, labels, uint64(value))
}

func (w *StorageWriter) insertWithRetry(ctx context.Context, records []domain.NormalizedFlowRecord) (InsertResult, error) {
	var lastErr error
	for attempt := 0; attempt <= w.maxRetries; attempt++ {
		result, err := w.inserter.InsertFlowRecords(ctx, records)
		if err == nil {
			return result, nil
		}
		lastErr = err
		if isCheckConstraintViolation(err) {
			break
		}
		if attempt == w.maxRetries {
			break
		}
		delay := w.backoff(attempt)
		if sleepErr := w.sleep(ctx, delay); sleepErr != nil {
			return InsertResult{}, fmt.Errorf("wait before storage retry: %w", sleepErr)
		}
	}
	return InsertResult{}, fmt.Errorf("insert storage batch after retries: %w", lastErr)
}

func isCheckConstraintViolation(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "violates check constraint") || strings.Contains(errStr, "23514")
}

func (w *StorageWriter) backoff(attempt int) time.Duration {
	delay := w.initialBackoff
	for range attempt {
		delay *= 2
		if delay >= w.maxBackoff {
			return w.maxBackoff
		}
	}
	return delay
}

func (w *StorageWriter) publishStorageDeadLetter(ctx context.Context, item StorageBatchItem, cause error) error {
	event, err := w.storageDeadLetterEvent(item, cause)
	if err != nil {
		return err
	}
	if err := validation.ValidateDeadLetterEvent(event); err != nil {
		return fmt.Errorf("validate storage dead-letter: %w", err)
	}
	if err := w.deadLetters.PublishDeadLetter(ctx, event); err != nil {
		return fmt.Errorf("publish storage dead-letter: %w", err)
	}
	return nil
}

func (w *StorageWriter) storageDeadLetterEvent(item StorageBatchItem, cause error) (*flowv1.DeadLetterEvent, error) {
	now := w.now()
	deadLetterID, err := domain.NewUUIDv7(now)
	if err != nil {
		return nil, fmt.Errorf("generate storage dead-letter id: %w", err)
	}
	event := &flowv1.DeadLetterEvent{
		DeadLetterId:  deadLetterID,
		SchemaVersion: domain.RawSchemaVersion,
		Stage:         flowv1.IngestionStage_INGESTION_STAGE_STORAGE_WRITER,
		ReceivedAt:    timestamppb.New(item.Record.IngestedAt.UTC()),
		FailedAt:      timestamppb.New(now.UTC()),
		Error: &flowv1.ErrorInfo{
			ErrorCode:    "storage_write_failed",
			ErrorMessage: cause.Error(),
			Retryable:    false,
		},
	}
	if item.RawEvent != nil {
		event.Source = item.RawEvent.GetSource()
		event.RawEvent = item.RawEvent
		return event, nil
	}
	event.Source = &flowv1.SourceIdentity{
		CollectorId: item.Record.CollectorID,
		SourceHost:  item.Record.SourceHost,
		SourceType:  sourceTypeToProto(item.Record.SourceType),
	}
	debugPayload := storageDebugPayload(item.Record)
	event.RawPayloadDebug = &flowv1.RawPayloadDebug{
		Masked:            true,
		Encoding:          flowv1.PayloadEncoding_PAYLOAD_ENCODING_TEXT,
		Data:              debugPayload,
		OriginalSizeBytes: uint64(len(debugPayload)),
	}
	return event, nil
}

func storageDebugPayload(record domain.NormalizedFlowRecord) []byte {
	payload := map[string]string{
		"id":              record.ID,
		"idempotency_key": record.IdempotencyKey,
		"raw_event_id":    record.RawEventID,
		"source_type":     string(record.SourceType),
		"collector_id":    record.CollectorID,
		"source_host":     record.SourceHost,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return []byte(`{}`)
	}
	return data
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func sourceTypeToProto(sourceType domain.SourceType) flowv1.SourceType {
	switch sourceType {
	case domain.SourceTypeUnknown:
		return flowv1.SourceType_SOURCE_TYPE_UNSPECIFIED
	case domain.SourceTypeNetFlowV5:
		return flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5
	case domain.SourceTypeZeekConnJSON:
		return flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON
	case domain.SourceTypeRESTJSON:
		return flowv1.SourceType_SOURCE_TYPE_REST_JSON
	case domain.SourceTypeNetFlowV9:
		return flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9
	case domain.SourceTypeSyslogCEF:
		return flowv1.SourceType_SOURCE_TYPE_SYSLOG_CEF
	case domain.SourceTypeSyslogLEEF:
		return flowv1.SourceType_SOURCE_TYPE_SYSLOG_LEEF
	case domain.SourceTypeSuricataEVE:
		return flowv1.SourceType_SOURCE_TYPE_SURICATA_EVE_JSON
	default:
		return flowv1.SourceType_SOURCE_TYPE_UNSPECIFIED
	}
}
