package kafka

import (
	"context"
	"fmt"

	"github.com/twmb/franz-go/pkg/kgo"
)

type FranzWriter struct {
	client *kgo.Client
}

func NewFranzWriter(cfg Config) (*FranzWriter, error) {
	if err := validateConfig(cfg, true); err != nil {
		return nil, err
	}

	client, err := kgo.NewClient(
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.ProducerBatchCompression(kgo.Lz4Compression()),
		kgo.ProduceRequestTimeout(cfg.RequestTimeout),
		kgo.RecordDeliveryTimeout(cfg.DeliveryTimeout),
		kgo.RecordRetries(cfg.MaxRetries),
	)
	if err != nil {
		return nil, fmt.Errorf("create franz kafka client: %w", err)
	}
	return &FranzWriter{client: client}, nil
}

func NewFranzPublisher(cfg Config) (*Publisher, error) {
	writer, err := NewFranzWriter(cfg)
	if err != nil {
		return nil, err
	}
	publisher, err := NewPublisher(writer, cfg)
	if err != nil {
		writer.Close()
		return nil, err
	}
	return publisher, nil
}

func (w *FranzWriter) Produce(ctx context.Context, record Record) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("%w: franz writer is nil", ErrPublisherClosed)
	}
	kafkaRecord := &kgo.Record{
		Topic:   record.Topic,
		Key:     append([]byte(nil), record.Key...),
		Value:   append([]byte(nil), record.Value...),
		Headers: toFranzHeaders(record.Headers),
	}
	if err := w.client.ProduceSync(ctx, kafkaRecord).FirstErr(); err != nil {
		return fmt.Errorf("produce sync: %w", err)
	}
	return nil
}

func (w *FranzWriter) Flush(ctx context.Context) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("%w: franz writer is nil", ErrPublisherClosed)
	}
	if err := w.client.Flush(ctx); err != nil {
		return fmt.Errorf("flush franz client: %w", err)
	}
	return nil
}

func (w *FranzWriter) Close() {
	if w == nil || w.client == nil {
		return
	}
	w.client.Close()
}

func toFranzHeaders(headers []Header) []kgo.RecordHeader {
	converted := make([]kgo.RecordHeader, len(headers))
	for i, header := range headers {
		converted[i] = kgo.RecordHeader{
			Key:   header.Key,
			Value: append([]byte(nil), header.Value...),
		}
	}
	return converted
}
