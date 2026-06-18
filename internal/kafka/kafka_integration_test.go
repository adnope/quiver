//go:build integration

package kafka

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestKafkaIntegrationPublishAndConsume(t *testing.T) {
	brokers := os.Getenv("QUIVER_TEST_KAFKA_BROKERS")
	if brokers == "" {
		brokers = os.Getenv("QUIVER_KAFKA_BROKERS")
	}
	if brokers == "" {
		brokers = "localhost:9094" // Default port exposed by docker-compose.yml
	}

	cfg := DefaultConfig()
	cfg.Brokers = strings.Split(brokers, ",")

	// Pre-create topics via admin client to avoid auto-creation latency in KRaft mode
	adminCl, err := kgo.NewClient(kgo.SeedBrokers(cfg.Brokers...))
	if err != nil {
		t.Fatalf("Failed to create admin client: %v", err)
	}
	adm := kadm.NewClient(adminCl)
	preCtx, preCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer preCancel()
	_, _ = adm.CreateTopic(preCtx, 1, 1, nil, "flow.raw.integration.test")
	_, _ = adm.CreateTopic(preCtx, 1, 1, nil, "flow.dead_letter.integration.test")
	adminCl.Close()
	// Wait briefly for metadata to propagate
	time.Sleep(2 * time.Second)
	cfg.RawTopic = "flow.raw.integration.test"
	cfg.DeadLetterTopic = "flow.dead_letter.integration.test"

	// Create real Franz Kafka client
	writer, err := NewFranzWriter(cfg)
	if err != nil {
		t.Fatalf("Failed to create FranzWriter: %v", err)
	}
	defer writer.Close()

	publisher, err := NewPublisher(writer, cfg)
	if err != nil {
		t.Fatalf("Failed to create Publisher: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = publisher.Close(ctx)
	}()

	// Construct message
	event := &flowv1.RawFlowEventEnvelope{
		EventId:       "01934d7c-79b4-7000-8b69-001122334455",
		SchemaVersion: domain.RawSchemaVersion,
		Source: &flowv1.SourceIdentity{
			CollectorId: "netflow-integration-test",
			SourceType:  flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5,
			SourceHost:  "router-integration-01",
		},
		ReceivedAt:   timestamppb.New(time.Now().UTC()),
		PartitionKey: "netflow-integration-test:router-integration-01",
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_NetflowV5{
				NetflowV5: &flowv1.NetFlowV5Flow{
					PacketSequence: 99,
					RecordIndex:    1,
					SrcAddr:        "10.0.0.5",
					DstAddr:        "10.0.0.6",
					Packets:        100,
					Bytes:          5000,
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1. Publish Raw message (with retries for topic auto-creation latency)
	var pubErr error
	for range 5 {
		pubErr = publisher.PublishRaw(ctx, event)
		if pubErr == nil {
			break
		}
		t.Logf("PublishRaw failed (retrying in 2s): %v", pubErr)
		time.Sleep(2 * time.Second)
	}
	if pubErr != nil {
		t.Fatalf("PublishRaw failed after retries: %v", pubErr)
	}

	// 2. Consume from topic to verify
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ConsumeTopics(cfg.RawTopic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		t.Fatalf("Failed to create consumer client: %v", err)
	}
	defer cl.Close()

	// Poll records
	var record *kgo.Record
	pollCtx, pollCancel := context.WithTimeout(ctx, 10*time.Second)
	defer pollCancel()

	fetches := cl.PollRecords(pollCtx, 1)
	if fetches.Err() != nil {
		if errors.Is(fetches.Err(), context.DeadlineExceeded) {
			t.Fatalf("Timed out waiting for message from topic %s. Is Kafka brokers (%v) reachable?", cfg.RawTopic, cfg.Brokers)
		}
		t.Fatalf("Fetch error: %v", fetches.Err())
	}

	iter := fetches.RecordIter()
	if !iter.Done() {
		record = iter.Next()
	}

	if record == nil {
		t.Fatal("No records consumed from Kafka")
	}

	// Assertions
	if string(record.Key) != "netflow-integration-test:router-integration-01" {
		t.Errorf("Unexpected key: %s", record.Key)
	}

	var decoded flowv1.RawFlowEventEnvelope
	if err := proto.Unmarshal(record.Value, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal Protobuf value: %v", err)
	}

	if decoded.GetEventId() != event.EventId {
		t.Errorf("Expected EventId %s, got %s", event.EventId, decoded.GetEventId())
	}

	netflowVal := decoded.GetPayload().GetNetflowV5()
	if netflowVal == nil {
		t.Fatal("NetFlow v5 payload is nil")
	}

	if netflowVal.PacketSequence != 99 || netflowVal.Bytes != 5000 {
		t.Errorf("Mismatch in payload values: seq=%d bytes=%d", netflowVal.PacketSequence, netflowVal.Bytes)
	}

	// Check headers
	headers := make(map[string]string)
	for _, h := range record.Headers {
		headers[h.Key] = string(h.Value)
	}

	if headers["content-type"] != "application/x-protobuf" {
		t.Errorf("content-type header mismatch: %s", headers["content-type"])
	}
	if headers["proto-message"] != "flow.v1.RawFlowEventEnvelope" {
		t.Errorf("proto-message header mismatch: %s", headers["proto-message"])
	}
	if headers["schema-version"] != domain.RawSchemaVersion {
		t.Errorf("schema-version header mismatch: %s", headers["schema-version"])
	}
	if headers["source-type"] != "SOURCE_TYPE_NETFLOW_V5" {
		t.Errorf("source-type header mismatch: %s", headers["source-type"])
	}
}
