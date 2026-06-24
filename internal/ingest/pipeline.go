package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/normalize"
	"github.com/adnope/quiver/internal/observability"
	"github.com/adnope/quiver/internal/storage/postgres"
	"github.com/adnope/quiver/internal/validation"
)

type kafkaClient interface {
	PollRecords(ctx context.Context, num int) kgo.Fetches
	CommitRecords(ctx context.Context, records ...*kgo.Record) error
	Close()
}

type Pipeline struct {
	cfg           config.Config
	client        kafkaClient
	storageWriter *postgres.StorageWriter
	publisher     kafka.RawEventPublisher
	logger        *slog.Logger
	metrics       *observability.Registry
	wg            sync.WaitGroup
	cancel        context.CancelFunc
	ctx           context.Context
}

type franzCommitter struct {
	client  kafkaClient
	records []*kgo.Record
}

func (c *franzCommitter) Commit(ctx context.Context) error {
	if len(c.records) == 0 {
		return nil
	}
	return c.client.CommitRecords(ctx, c.records...)
}

func NewPipeline(
	cfg config.Config,
	storageWriter *postgres.StorageWriter,
	publisher kafka.RawEventPublisher,
	metrics *observability.Registry,
	logger *slog.Logger,
) (*Pipeline, error) {
	if storageWriter == nil {
		return nil, errors.New("pipeline: storage writer is nil")
	}
	if publisher == nil {
		return nil, errors.New("pipeline: publisher is nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Kafka.Brokers...),
		kgo.ConsumerGroup("flow-storage-writer"),
		kgo.ConsumeTopics(cfg.Kafka.Topics.Raw),
		kgo.DisableAutoCommit(),
	}

	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("pipeline: create kafka client: %w", err)
	}

	return &Pipeline{
		cfg:           cfg,
		client:        client,
		storageWriter: storageWriter,
		publisher:     publisher,
		logger:        logger,
		metrics:       metrics,
	}, nil
}

func (p *Pipeline) Start(ctx context.Context) {
	runCtx, cancel := context.WithCancel(ctx)
	p.ctx = runCtx
	p.cancel = cancel
	p.wg.Add(1)
	go p.run(runCtx)
	p.wg.Add(1)
	go p.pollKafkaLag(runCtx)
}

func (p *Pipeline) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	p.client.Close()
}

func (p *Pipeline) pollKafkaLag(ctx context.Context) {
	defer p.wg.Done()
	if p.metrics == nil {
		return
	}
	client, ok := p.client.(*kgo.Client)
	if !ok || client == nil {
		return
	}

	admin := kadm.NewClient(client)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.collectKafkaLag(ctx, admin)
		}
	}
}

func (p *Pipeline) collectKafkaLag(ctx context.Context, admin *kadm.Client) {
	if p.metrics == nil || admin == nil {
		return
	}

	pollCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	lags, err := admin.Lag(pollCtx, "flow-storage-writer")
	if err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			p.logger.Error("failed to poll kafka consumer lag", slog.Any("error", err))
		}
		return
	}

	for _, groupLag := range lags.Sorted() {
		if err := groupLag.Error(); err != nil {
			p.logger.Error("failed to describe kafka consumer lag", slog.String("group", groupLag.Group), slog.Any("error", err))
			continue
		}
		for _, partitionLag := range groupLag.Lag.Sorted() {
			if partitionLag.Err != nil {
				p.logger.Error(
					"failed to calculate kafka partition lag",
					slog.String("topic", partitionLag.Topic),
					slog.Int("partition", int(partitionLag.Partition)),
					slog.Any("error", partitionLag.Err),
				)
				continue
			}
			if partitionLag.Lag < 0 {
				continue
			}
			p.metrics.Set("kafka_consumer_lag", map[string]string{
				"topic":     partitionLag.Topic,
				"partition": strconv.Itoa(int(partitionLag.Partition)),
			}, uint64(partitionLag.Lag))
		}
	}
}

func (p *Pipeline) run(ctx context.Context) {
	defer p.wg.Done()
	p.logger.Info("ingestion pipeline started", slog.String("topic", p.cfg.Kafka.Topics.Raw))

	batchSize := p.cfg.StorageWriter.BatchSize
	if batchSize <= 0 {
		batchSize = 1000
	}
	flushInterval := p.cfg.StorageWriter.FlushInterval.Std()
	if flushInterval <= 0 {
		flushInterval = time.Second
	}

	for {
		if err := ctx.Err(); err != nil {
			return
		}

		pollCtx, pollCancel := context.WithTimeout(ctx, flushInterval)
		fetches := p.client.PollRecords(pollCtx, batchSize)
		pollCancel()

		if errs := fetches.Errors(); len(errs) > 0 {
			for _, err := range errs {
				if !errors.Is(err.Err, context.DeadlineExceeded) && !errors.Is(err.Err, context.Canceled) {
					p.logger.Error("kafka consumer fetch error", slog.String("topic", err.Topic), slog.Int("partition", int(err.Partition)), slog.Any("error", err.Err))
				}
			}
		}

		records := fetches.Records()
		if len(records) == 0 {
			continue
		}

		p.logger.Debug("fetched records from kafka", slog.Int("count", len(records)))
		for {
			if err := ctx.Err(); err != nil {
				return
			}
			err := p.processBatch(ctx, records)
			if err == nil {
				break
			}
			p.logger.Error("retrying batch process after failure", slog.Any("error", err))
			retryTimer := time.NewTimer(2 * time.Second)
			select {
			case <-ctx.Done():
				retryTimer.Stop()
				return
			case <-retryTimer.C:
			}
		}
	}
}

func (p *Pipeline) processBatch(ctx context.Context, records []*kgo.Record) error {
	if len(records) < 200 {
		return p.processBatchSequential(ctx, records)
	}
	return p.processBatchConcurrent(ctx, records)
}

func (p *Pipeline) processBatchSequential(ctx context.Context, records []*kgo.Record) error {
	batchItems := make([]postgres.StorageBatchItem, 0, len(records))

	for _, krec := range records {
		var envelope flowv1.RawFlowEventEnvelope
		if err := proto.Unmarshal(krec.Value, &envelope); err != nil {
			p.logger.Error("failed to unmarshal RawFlowEventEnvelope from kafka", slog.Any("error", err))
			if err := p.publishCorruptRecordToDLQ(ctx, krec, err); err != nil {
				return fmt.Errorf("publish corrupt record to DLQ: %w", err)
			}
			p.metric("flow_records_failed_total", map[string]string{"reason": "unmarshal_failed"})
			continue
		}

		p.metric("flow_records_received_total", map[string]string{
			"collector_id": envelope.GetSource().GetCollectorId(),
			"source_type":  envelope.GetSource().GetSourceType().String(),
		})

		if err := validation.ValidateRawEventEnvelope(&envelope); err != nil {
			p.logger.Error("raw event validation failed in pipeline", slog.Any("error", err))
			if err := p.publishRawEventToDLQ(ctx, &envelope, "invalid_raw_envelope", err.Error()); err != nil {
				return fmt.Errorf("publish invalid raw envelope to DLQ: %w", err)
			}
			p.metric("flow_records_failed_total", map[string]string{"reason": "validation_failed"})
			continue
		}
		p.metric("flow_records_validated_total", map[string]string{
			"collector_id": envelope.GetSource().GetCollectorId(),
			"source_type":  envelope.GetSource().GetSourceType().String(),
		})

		opts := normalize.Options{
			Now:           time.Now,
			LocalNetworks: domain.DefaultLocalNetworks(),
		}
		normalized, err := normalize.NormalizeRawEvent(&envelope, opts)
		if err != nil {
			p.logger.Error("normalization failed in pipeline", slog.Any("error", err))
			if err := p.publishRawEventToDLQ(ctx, &envelope, "normalization_failed", err.Error()); err != nil {
				return fmt.Errorf("publish normalization failure to DLQ: %w", err)
			}
			p.metric("flow_records_failed_total", map[string]string{"reason": "normalization_failed"})
			continue
		}
		p.metric("flow_records_normalized_total", map[string]string{
			"collector_id": envelope.GetSource().GetCollectorId(),
			"source_type":  envelope.GetSource().GetSourceType().String(),
		})

		batchItems = append(batchItems, postgres.StorageBatchItem{
			Record:   normalized,
			RawEvent: &envelope,
		})
	}

	committer := &franzCommitter{client: p.client, records: records}
	writeResult, err := p.storageWriter.WriteBatch(ctx, batchItems, committer)
	if err != nil {
		return fmt.Errorf("write storage batch: %w", err)
	}

	p.logger.Debug("batch processed successfully",
		slog.Int("attempted", writeResult.Attempted),
		slog.Int("inserted", writeResult.Inserted),
		slog.Int("deduplicated", writeResult.Deduplicated),
		slog.Int("dead_lettered", writeResult.DeadLettered),
	)

	if p.metrics != nil {
		p.metrics.Add("flow_records_stored_total", nil, uint64(writeResult.Inserted))                                               //nolint:gosec
		p.metrics.Add("flow_records_failed_total", map[string]string{"reason": "storage_failed"}, uint64(writeResult.DeadLettered)) //nolint:gosec
	}

	return nil
}

func (p *Pipeline) processBatchConcurrent(ctx context.Context, records []*kgo.Record) error {
	concurrency := p.cfg.StorageWriter.Concurrency
	if concurrency <= 0 {
		concurrency = 8
	}

	chunks := splitRecords(records, concurrency)
	var wg sync.WaitGroup
	errs := make([]error, len(chunks))
	batchItemChunks := make([][]postgres.StorageBatchItem, len(chunks))

	for i, chunk := range chunks {
		wg.Add(1)
		go func(workerIdx int, chunkRecords []*kgo.Record) {
			defer wg.Done()

			defer func() {
				if r := recover(); r != nil {
					errs[workerIdx] = fmt.Errorf("consumer worker panicked: %v", r)
				}
			}()

			batchItems := make([]postgres.StorageBatchItem, 0, len(chunkRecords))
			for _, krec := range chunkRecords {
				var envelope flowv1.RawFlowEventEnvelope
				if err := proto.Unmarshal(krec.Value, &envelope); err != nil {
					p.logger.Error("failed to unmarshal RawFlowEventEnvelope from kafka", slog.Any("error", err))
					if err := p.publishCorruptRecordToDLQ(ctx, krec, err); err != nil {
						errs[workerIdx] = fmt.Errorf("publish corrupt record to DLQ: %w", err)
						return
					}
					p.metric("flow_records_failed_total", map[string]string{"reason": "unmarshal_failed"})
					continue
				}

				p.metric("flow_records_received_total", map[string]string{
					"collector_id": envelope.GetSource().GetCollectorId(),
					"source_type":  envelope.GetSource().GetSourceType().String(),
				})

				if err := validation.ValidateRawEventEnvelope(&envelope); err != nil {
					p.logger.Error("raw event validation failed in pipeline", slog.Any("error", err))
					if err := p.publishRawEventToDLQ(ctx, &envelope, "invalid_raw_envelope", err.Error()); err != nil {
						errs[workerIdx] = fmt.Errorf("publish invalid raw envelope to DLQ: %w", err)
						return
					}
					p.metric("flow_records_failed_total", map[string]string{"reason": "validation_failed"})
					continue
				}
				p.metric("flow_records_validated_total", map[string]string{
					"collector_id": envelope.GetSource().GetCollectorId(),
					"source_type":  envelope.GetSource().GetSourceType().String(),
				})

				opts := normalize.Options{
					Now:           time.Now,
					LocalNetworks: domain.DefaultLocalNetworks(),
				}
				normalized, err := normalize.NormalizeRawEvent(&envelope, opts)
				if err != nil {
					p.logger.Error("normalization failed in pipeline", slog.Any("error", err))
					if err := p.publishRawEventToDLQ(ctx, &envelope, "normalization_failed", err.Error()); err != nil {
						errs[workerIdx] = fmt.Errorf("publish normalization failure to DLQ: %w", err)
						return
					}
					p.metric("flow_records_failed_total", map[string]string{"reason": "normalization_failed"})
					continue
				}
				p.metric("flow_records_normalized_total", map[string]string{
					"collector_id": envelope.GetSource().GetCollectorId(),
					"source_type":  envelope.GetSource().GetSourceType().String(),
				})

				batchItems = append(batchItems, postgres.StorageBatchItem{
					Record:   normalized,
					RawEvent: &envelope,
				})
			}

			batchItemChunks[workerIdx] = batchItems
		}(i, chunk)
	}

	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return err
		}
	}

	totalBatchItems := 0
	for _, chunkItems := range batchItemChunks {
		totalBatchItems += len(chunkItems)
	}

	allBatchItems := make([]postgres.StorageBatchItem, 0, totalBatchItems)
	for _, chunkItems := range batchItemChunks {
		allBatchItems = append(allBatchItems, chunkItems...)
	}

	committer := &franzCommitter{client: p.client, records: records}

	if len(allBatchItems) == 0 {
		if err := committer.Commit(ctx); err != nil {
			return fmt.Errorf("commit storage offsets after empty batch: %w", err)
		}
		p.logger.Debug("batch processed successfully",
			slog.Int("attempted", 0),
			slog.Int("inserted", 0),
			slog.Int("deduplicated", 0),
			slog.Int("dead_lettered", 0),
		)
		return nil
	}

	writeResult, err := p.writeMergedStorageBatch(ctx, allBatchItems, committer)
	if err != nil {
		return fmt.Errorf("write merged storage batch: %w", err)
	}

	p.logger.Debug("batch processed successfully",
		slog.Int("attempted", writeResult.Attempted),
		slog.Int("inserted", writeResult.Inserted),
		slog.Int("deduplicated", writeResult.Deduplicated),
		slog.Int("dead_lettered", writeResult.DeadLettered),
	)

	if p.metrics != nil {
		p.metrics.Add("flow_records_stored_total", nil, uint64(writeResult.Inserted))                                               //nolint:gosec
		p.metrics.Add("flow_records_failed_total", map[string]string{"reason": "storage_failed"}, uint64(writeResult.DeadLettered)) //nolint:gosec
	}

	return nil
}

func (p *Pipeline) writeMergedStorageBatch(
	ctx context.Context,
	items []postgres.StorageBatchItem,
	committer postgres.OffsetCommitter,
) (result postgres.StorageWriteResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("storage write panicked: %v", r)
		}
	}()

	return p.storageWriter.WriteBatch(ctx, items, committer)
}

func splitRecords(records []*kgo.Record, concurrency int) [][]*kgo.Record {
	if len(records) == 0 {
		return nil
	}
	if concurrency <= 0 {
		concurrency = 8
	}
	if concurrency > len(records) {
		concurrency = len(records)
	}

	chunks := make([][]*kgo.Record, concurrency)
	base := len(records) / concurrency
	rem := len(records) % concurrency

	start := 0
	for i := 0; i < concurrency; i++ {
		size := base
		if i < rem {
			size++
		}
		chunks[i] = records[start : start+size]
		start += size
	}
	return chunks
}

func (p *Pipeline) publishCorruptRecordToDLQ(ctx context.Context, krec *kgo.Record, unmarshalErr error) error {
	deadLetterID, err := domain.NewUUIDv7(time.Now())
	if err != nil {
		return fmt.Errorf("generate dead-letter id: %w", err)
	}
	event := &flowv1.DeadLetterEvent{
		DeadLetterId:  deadLetterID,
		SchemaVersion: domain.RawSchemaVersion,
		Stage:         flowv1.IngestionStage_INGESTION_STAGE_VALIDATION,
		FailedAt:      timestamppb.New(time.Now().UTC()),
		Error: &flowv1.ErrorInfo{
			ErrorCode:    "unmarshal_failed",
			ErrorMessage: unmarshalErr.Error(),
		},
		RawPayloadDebug: &flowv1.RawPayloadDebug{
			Masked:            true,
			Encoding:          flowv1.PayloadEncoding_PAYLOAD_ENCODING_RAW_BYTES,
			Data:              krec.Value,
			Sha256:            sha256Hex(krec.Value),
			OriginalSizeBytes: uint64(len(krec.Value)),
		},
	}
	return p.publisher.PublishDeadLetter(ctx, event)
}

func (p *Pipeline) publishRawEventToDLQ(ctx context.Context, envelope *flowv1.RawFlowEventEnvelope, code, message string) error {
	deadLetterID, err := domain.NewUUIDv7(time.Now())
	if err != nil {
		return fmt.Errorf("generate dead-letter id: %w", err)
	}
	stage := flowv1.IngestionStage_INGESTION_STAGE_NORMALIZER
	if code == "invalid_raw_envelope" {
		stage = flowv1.IngestionStage_INGESTION_STAGE_VALIDATION
	}
	event := &flowv1.DeadLetterEvent{
		DeadLetterId:  deadLetterID,
		SchemaVersion: domain.RawSchemaVersion,
		Stage:         stage,
		Source:        envelope.GetSource(),
		ReceivedAt:    envelope.GetReceivedAt(),
		FailedAt:      timestamppb.New(time.Now().UTC()),
		Error: &flowv1.ErrorInfo{
			ErrorCode:    code,
			ErrorMessage: message,
		},
		RawEvent: envelope,
	}
	return p.publisher.PublishDeadLetter(ctx, event)
}

func (p *Pipeline) metric(name string, labels map[string]string) {
	if p.metrics != nil {
		p.metrics.Inc(name, labels)
	}
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
