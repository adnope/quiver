package kafka

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adnope/quiver/internal/config"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/validation"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultQueueSize       = 10000
	DefaultWorkerCount     = 4
	DefaultRequestTimeout  = 10 * time.Second
	DefaultDeliveryTimeout = 30 * time.Second
	DefaultMaxRetries      = 10

	rawProtoMessage        = "flow.v1.RawFlowEventEnvelope"
	deadLetterProtoMessage = "flow.v1.DeadLetterEvent"
	protobufContentType    = "application/x-protobuf"
)

var (
	ErrInvalidConfig   = errors.New("kafka: invalid publisher config")
	ErrInvalidEvent    = errors.New("kafka: invalid event")
	ErrQueueFull       = errors.New("kafka: publish queue full")
	ErrPublisherClosed = errors.New("kafka: publisher closed")
)

type RawEventPublisher interface {
	PublishRaw(ctx context.Context, event *flowv1.RawFlowEventEnvelope) error
	PublishDeadLetter(ctx context.Context, event *flowv1.DeadLetterEvent) error
	Flush(ctx context.Context) error
}

type Config struct {
	Brokers         []string
	RawTopic        string
	DeadLetterTopic string
	QueueSize       int
	Workers         int
	RequestTimeout  time.Duration
	DeliveryTimeout time.Duration
	MaxRetries      int
}

type Header struct {
	Key   string
	Value []byte
}

type Record struct {
	Topic   string
	Key     []byte
	Value   []byte
	Headers []Header
}

type RecordWriter interface {
	Produce(ctx context.Context, record Record) error
	Flush(ctx context.Context) error
	Close()
}

type Publisher struct {
	cfg        Config
	writer     RecordWriter
	queue      chan publishRequest
	closeMu    sync.RWMutex
	closed     atomic.Bool
	workers    sync.WaitGroup
	inflightMu sync.Mutex
	inflight   sync.WaitGroup
}

type publishRequest struct {
	ctx    context.Context
	record Record
	result chan error
}

func DefaultConfig() Config {
	return Config{
		RawTopic:        "flow.raw",
		DeadLetterTopic: "flow.dead_letter",
		QueueSize:       DefaultQueueSize,
		Workers:         DefaultWorkerCount,
		RequestTimeout:  DefaultRequestTimeout,
		DeliveryTimeout: DefaultDeliveryTimeout,
		MaxRetries:      DefaultMaxRetries,
	}
}

func ConfigFromApp(cfg config.Config) Config {
	kafkaCfg := DefaultConfig()
	kafkaCfg.Brokers = append([]string(nil), cfg.Kafka.Brokers...)
	kafkaCfg.RawTopic = cfg.Kafka.Topics.Raw
	kafkaCfg.DeadLetterTopic = cfg.Kafka.Topics.DeadLetter
	kafkaCfg.QueueSize = cfg.Ingestion.PublishQueueSize
	kafkaCfg.Workers = cfg.Ingestion.PublisherWorkers
	return kafkaCfg
}

func NewPublisher(writer RecordWriter, cfg Config) (*Publisher, error) {
	if writer == nil {
		return nil, fmt.Errorf("%w: writer is nil", ErrInvalidConfig)
	}
	if err := validateConfig(cfg, false); err != nil {
		return nil, err
	}

	publisher := &Publisher{
		cfg:    cfg,
		writer: writer,
		queue:  make(chan publishRequest, cfg.QueueSize),
	}
	publisher.workers.Add(cfg.Workers)
	for range cfg.Workers {
		go publisher.worker()
	}
	return publisher, nil
}

func (p *Publisher) PublishRaw(ctx context.Context, event *flowv1.RawFlowEventEnvelope) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", ErrInvalidEvent)
	}
	if err := validation.ValidateRawEventEnvelope(event); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}

	value, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	if err != nil {
		return fmt.Errorf("%w: marshal raw event: %w", ErrInvalidEvent, err)
	}
	record := Record{
		Topic: p.cfg.RawTopic,
		Key:   []byte(validation.PartitionKey(event.GetSource())),
		Value: value,
		Headers: kafkaHeaders(
			rawProtoMessage,
			event.GetSchemaVersion(),
			event.GetSource().GetSourceType(),
		),
	}
	return p.publish(ctx, record)
}

func (p *Publisher) PublishDeadLetter(ctx context.Context, event *flowv1.DeadLetterEvent) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", ErrInvalidEvent)
	}
	if err := validation.ValidateDeadLetterEvent(event); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}

	value, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
	if err != nil {
		return fmt.Errorf("%w: marshal dead-letter event: %w", ErrInvalidEvent, err)
	}
	record := Record{
		Topic: p.cfg.DeadLetterTopic,
		Key:   []byte(validation.PartitionKey(event.GetSource())),
		Value: value,
		Headers: kafkaHeaders(
			deadLetterProtoMessage,
			event.GetSchemaVersion(),
			event.GetSource().GetSourceType(),
		),
	}
	return p.publish(ctx, record)
}

func (p *Publisher) Flush(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", ErrInvalidEvent)
	}
	if p == nil || p.writer == nil {
		return fmt.Errorf("%w: publisher is nil", ErrPublisherClosed)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("flush kafka publisher: %w", err)
	}

	p.closeMu.RLock()
	defer p.closeMu.RUnlock()
	if p.closed.Load() {
		return ErrPublisherClosed
	}

	p.inflightMu.Lock()
	defer p.inflightMu.Unlock()
	if err := p.waitForInflight(ctx); err != nil {
		return err
	}
	if err := p.writer.Flush(ctx); err != nil {
		return fmt.Errorf("flush kafka writer: %w", err)
	}
	return nil
}

func (p *Publisher) Healthy() bool {
	if p == nil {
		return false
	}
	return !p.closed.Load()
}

func (p *Publisher) Close(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is nil", ErrInvalidEvent)
	}
	if p == nil || p.writer == nil {
		return nil
	}
	if p.closed.CompareAndSwap(false, true) {
		p.closeMu.Lock()
		close(p.queue)
		p.closeMu.Unlock()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.workers.Wait()
		p.writer.Close()
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("close kafka publisher: %w", ctx.Err())
	case <-done:
		return nil
	}
}

func (p *Publisher) publish(ctx context.Context, record Record) error {
	if p == nil || p.writer == nil {
		return fmt.Errorf("%w: publisher is nil", ErrPublisherClosed)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("publish kafka record: %w", err)
	}

	result := make(chan error, 1)
	request := publishRequest{ctx: ctx, record: cloneRecord(record), result: result}

	p.closeMu.RLock()
	defer p.closeMu.RUnlock()
	if p.closed.Load() {
		return ErrPublisherClosed
	}

	p.inflightMu.Lock()
	p.inflight.Add(1)
	select {
	case p.queue <- request:
		p.inflightMu.Unlock()
	default:
		p.inflight.Done()
		p.inflightMu.Unlock()
		return ErrQueueFull
	}

	select {
	case <-ctx.Done():
		return fmt.Errorf("publish kafka record: %w", ctx.Err())
	case err := <-result:
		if err != nil {
			return err
		}
		return nil
	}
}

func (p *Publisher) waitForInflight(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.inflight.Wait()
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("flush kafka publisher: %w", ctx.Err())
	case <-done:
		return nil
	}
}

func (p *Publisher) worker() {
	defer p.workers.Done()
	for request := range p.queue {
		err := p.writer.Produce(request.ctx, request.record)
		if err != nil {
			request.result <- fmt.Errorf("produce kafka record: %w", err)
			p.inflight.Done()
			continue
		}
		request.result <- nil
		p.inflight.Done()
	}
}

func validateConfig(cfg Config, requireBrokers bool) error {
	if requireBrokers && len(cfg.Brokers) == 0 {
		return fmt.Errorf("%w: brokers are required", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.RawTopic) == "" {
		return fmt.Errorf("%w: raw topic is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.DeadLetterTopic) == "" {
		return fmt.Errorf("%w: dead-letter topic is required", ErrInvalidConfig)
	}
	if cfg.QueueSize <= 0 {
		return fmt.Errorf("%w: queue size must be positive", ErrInvalidConfig)
	}
	if cfg.Workers <= 0 {
		return fmt.Errorf("%w: workers must be positive", ErrInvalidConfig)
	}
	if cfg.RequestTimeout <= 0 {
		return fmt.Errorf("%w: request timeout must be positive", ErrInvalidConfig)
	}
	if cfg.DeliveryTimeout <= 0 {
		return fmt.Errorf("%w: delivery timeout must be positive", ErrInvalidConfig)
	}
	if cfg.MaxRetries < 0 {
		return fmt.Errorf("%w: max retries cannot be negative", ErrInvalidConfig)
	}
	return nil
}

func kafkaHeaders(protoMessage string, schemaVersion string, sourceType flowv1.SourceType) []Header {
	return []Header{
		{Key: "content-type", Value: []byte(protobufContentType)},
		{Key: "proto-message", Value: []byte(protoMessage)},
		{Key: "schema-version", Value: []byte(schemaVersion)},
		{Key: "source-type", Value: []byte(sourceType.String())},
	}
}

func cloneRecord(record Record) Record {
	cloned := Record{
		Topic:   record.Topic,
		Key:     append([]byte(nil), record.Key...),
		Value:   append([]byte(nil), record.Value...),
		Headers: make([]Header, len(record.Headers)),
	}
	for i, header := range record.Headers {
		cloned.Headers[i] = Header{
			Key:   header.Key,
			Value: append([]byte(nil), header.Value...),
		}
	}
	return cloned
}

var _ RawEventPublisher = (*Publisher)(nil)

func RawPartitionKey(source *flowv1.SourceIdentity) string {
	return validation.PartitionKey(source)
}
