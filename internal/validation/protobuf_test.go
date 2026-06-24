package validation

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

func TestValidateRawEventEnvelope(t *testing.T) {
	t.Parallel()

	event := validRawEvent()
	if err := ValidateRawEventEnvelope(event); err != nil {
		t.Fatalf("valid raw event failed validation: %v", err)
	}

	data, err := proto.Marshal(event)
	if err != nil {
		t.Fatalf("marshal raw event: %v", err)
	}
	if len(data) == 0 || data[0] == '{' {
		t.Fatalf("raw event encoded as JSON-like bytes: %q", data)
	}

	var decoded flowv1.RawFlowEventEnvelope
	if err := proto.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal raw event: %v", err)
	}
	if decoded.GetEventId() != event.GetEventId() {
		t.Fatalf("decoded event id = %q", decoded.GetEventId())
	}
}

func TestValidateRawEventEnvelopeFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*flowv1.RawFlowEventEnvelope)
		expected string
	}{
		{
			name: "missing payload",
			mutate: func(event *flowv1.RawFlowEventEnvelope) {
				event.Payload = nil
			},
			expected: "payload",
		},
		{
			name: "bad partition key",
			mutate: func(event *flowv1.RawFlowEventEnvelope) {
				event.PartitionKey = "wrong"
			},
			expected: "partition_key",
		},
		{
			name: "source mismatch",
			mutate: func(event *flowv1.RawFlowEventEnvelope) {
				event.Source.SourceType = flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON
			},
			expected: "payload variant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			event := validRawEvent()
			tt.mutate(event)
			err := ValidateRawEventEnvelope(event)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.expected) {
				t.Fatalf("error %q does not contain %q", err, tt.expected)
			}
		})
	}
}

func TestValidateDeadLetterEvent(t *testing.T) {
	t.Parallel()

	event := &flowv1.DeadLetterEvent{
		DeadLetterId:  "01934d7c-79b4-7000-8b69-001122334455",
		SchemaVersion: domain.RawSchemaVersion,
		Stage:         flowv1.IngestionStage_INGESTION_STAGE_PARSER,
		Source:        validSource(),
		ReceivedAt:    timestamppb.New(time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC)),
		FailedAt:      timestamppb.New(time.Date(2026, 6, 16, 10, 15, 21, 0, time.UTC)),
		Error: &flowv1.ErrorInfo{
			ErrorCode:    "invalid_json",
			ErrorMessage: "invalid zeek json line",
			Retryable:    false,
		},
		RawPayloadDebug: &flowv1.RawPayloadDebug{
			Masked:            true,
			Encoding:          flowv1.PayloadEncoding_PAYLOAD_ENCODING_TEXT,
			Data:              []byte(`{"token":"***MASKED***"}`),
			OriginalSizeBytes: 24,
		},
	}

	if err := ValidateDeadLetterEvent(event); err != nil {
		t.Fatalf("valid dead-letter event failed validation: %v", err)
	}

	data, err := proto.Marshal(event)
	if err != nil {
		t.Fatalf("marshal dead-letter event: %v", err)
	}
	var decoded flowv1.DeadLetterEvent
	if err := proto.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal dead-letter event: %v", err)
	}
	if decoded.GetError().GetErrorCode() != "invalid_json" {
		t.Fatalf("decoded error code = %q", decoded.GetError().GetErrorCode())
	}
}

func TestValidateDeadLetterEventRejectsUnmaskedDebugPayload(t *testing.T) {
	t.Parallel()

	event := &flowv1.DeadLetterEvent{
		DeadLetterId:  "01934d7c-79b4-7000-8b69-001122334455",
		SchemaVersion: domain.RawSchemaVersion,
		Stage:         flowv1.IngestionStage_INGESTION_STAGE_PARSER,
		Source:        validSource(),
		FailedAt:      timestamppb.Now(),
		Error:         &flowv1.ErrorInfo{ErrorCode: "invalid_json"},
		RawPayloadDebug: &flowv1.RawPayloadDebug{
			Masked:   false,
			Encoding: flowv1.PayloadEncoding_PAYLOAD_ENCODING_TEXT,
			Data:     []byte(`{"token":"secret"}`),
		},
	}

	err := ValidateDeadLetterEvent(event)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "masked") {
		t.Fatalf("error %q does not mention masked payload", err)
	}
}

func validRawEvent() *flowv1.RawFlowEventEnvelope {
	receivedAt := timestamppb.New(time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC))
	return &flowv1.RawFlowEventEnvelope{
		EventId:       "01934d7c-79b4-7000-8b69-001122334455",
		SchemaVersion: domain.RawSchemaVersion,
		Source:        validSource(),
		ReceivedAt:    receivedAt,
		PartitionKey:  "netflow-main:router-core-01",
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_NetflowV5{
				NetflowV5: &flowv1.NetFlowV5Flow{
					PacketSequence:  42,
					RecordIndex:     0,
					SrcAddr:         "192.168.1.10",
					DstAddr:         "8.8.8.8",
					Packets:         3,
					Bytes:           420,
					FirstSwitchedMs: 1000,
					LastSwitchedMs:  2000,
					ProtocolNumber:  17,
				},
			},
		},
	}
}

func validSource() *flowv1.SourceIdentity {
	return &flowv1.SourceIdentity{
		CollectorId: "netflow-main",
		SourceType:  flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5,
		SourceHost:  "router-core-01",
	}
}
