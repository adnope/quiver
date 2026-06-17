package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/normalize"
	"github.com/adnope/quiver/internal/observability"
	"github.com/adnope/quiver/internal/storage/postgres"
	"github.com/adnope/quiver/internal/validation"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Pipeline struct {
	cfg           config.Config
	client        *kgo.Client
	storageWriter *postgres.StorageWriter
	publisher     kafka.RawEventPublisher
	logger        *slog.Logger
	metrics       *observability.Registry
	wg            sync.WaitGroup
	cancel        context.CancelFunc
	ctx           context.Context
}

type franzCommitter struct {
	client  *kgo.Client
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
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.wg.Add(1)
	go p.run()
}

func (p *Pipeline) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	p.client.Close()
}

func (p *Pipeline) run() {
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
		if err := p.ctx.Err(); err != nil {
			return
		}

		pollCtx, pollCancel := context.WithTimeout(p.ctx, flushInterval)
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
			if err := p.ctx.Err(); err != nil {
				return
			}
			err := p.processBatch(p.ctx, records)
			if err == nil {
				break
			}
			p.logger.Error("retrying batch process after failure", slog.Any("error", err))
			retryTimer := time.NewTimer(2 * time.Second)
			select {
			case <-p.ctx.Done():
				retryTimer.Stop()
				return
			case <-retryTimer.C:
			}
		}
	}
}

func (p *Pipeline) processBatch(ctx context.Context, records []*kgo.Record) error {
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
