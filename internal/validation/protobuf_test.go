package validation

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
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

func TestNetFlowV9DecodedFieldsRoundTrip(t *testing.T) {
	t.Parallel()

	name := "IPV4_SRC_ADDR"
	flow := &flowv1.NetFlowV9Flow{
		SourceId:       7,
		TemplateId:     256,
		RecordIndex:    3,
		PacketSequence: 99,
		DecodedFields: []*flowv1.NetFlowV9DecodedField{
			{FieldId: 8, FieldLength: 4, Name: &name, Value: &flowv1.NetFlowV9DecodedField_StringValue{StringValue: "192.0.2.10"}},
			{FieldId: 27, FieldLength: 16, Value: &flowv1.NetFlowV9DecodedField_StringValue{StringValue: "2001:db8::10"}},
			{FieldId: 1, FieldLength: 8, Value: &flowv1.NetFlowV9DecodedField_UnsignedValue{UnsignedValue: ^uint64(0)}},
			{FieldId: 82, FieldLength: 8, Value: &flowv1.NetFlowV9DecodedField_StringValue{StringValue: "eth0"}},
			{FieldId: 400, FieldLength: 4, Value: &flowv1.NetFlowV9DecodedField_BytesValue{BytesValue: []byte{0, 1, 2, 3}}},
			{FieldId: 400, FieldLength: 2, Value: &flowv1.NetFlowV9DecodedField_BytesValue{BytesValue: []byte{4, 5}}},
		},
	}
	event := validNetFlowV9Event(flow)
	if err := ValidateRawEventEnvelope(event); err != nil {
		t.Fatalf("ValidateRawEventEnvelope() error = %v", err)
	}

	encoded, err := proto.Marshal(event)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}
	var decoded flowv1.RawFlowEventEnvelope
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	fields := decoded.GetPayload().GetNetflowV9().GetDecodedFields()
	if len(fields) != 6 {
		t.Fatalf("decoded field count = %d, want 6", len(fields))
	}
	if fields[2].GetUnsignedValue() != ^uint64(0) {
		t.Fatalf("uint64 value = %d, want max uint64", fields[2].GetUnsignedValue())
	}
	if fields[4].GetFieldId() != fields[5].GetFieldId() || !bytes.Equal(fields[5].GetBytesValue(), []byte{4, 5}) {
		t.Fatalf("duplicate fields lost order: %+v", fields)
	}
}

func TestNetFlowV9LegacyStructOnlyPayloadRemainsValid(t *testing.T) {
	t.Parallel()

	fields, err := structpb.NewStruct(map[string]any{"IPV4_SRC_ADDR": "192.0.2.10"})
	if err != nil {
		t.Fatalf("structpb.NewStruct() error = %v", err)
	}
	legacy := &flowv1.NetFlowV9Flow{SourceId: 7, TemplateId: 256, RecordIndex: 1, Fields: fields}
	encoded, err := proto.Marshal(legacy)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}
	var decoded flowv1.NetFlowV9Flow
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	if err := ValidateRawEventEnvelope(validNetFlowV9Event(&decoded)); err != nil {
		t.Fatalf("legacy v9 payload failed validation: %v", err)
	}
	if len(decoded.GetDecodedFields()) != 0 || decoded.GetFields().GetFields()["IPV4_SRC_ADDR"].GetStringValue() != "192.0.2.10" {
		t.Fatalf("legacy fields changed after unmarshal: %+v", decoded.GetFields())
	}
}

func TestNetFlowV9DecodedFieldValidationFailures(t *testing.T) {
	t.Parallel()

	unknownValueWire := protowire.AppendTag(nil, 99, protowire.VarintType)
	unknownValueWire = protowire.AppendVarint(unknownValueWire, 1)
	var unknownValue flowv1.NetFlowV9DecodedField
	if err := proto.Unmarshal(unknownValueWire, &unknownValue); err != nil {
		t.Fatalf("proto.Unmarshal() error = %v", err)
	}
	unknownValue.FieldId = 1
	unknownValue.FieldLength = 1

	tests := []struct {
		name  string
		field *flowv1.NetFlowV9DecodedField
	}{
		{name: "unknown oneof", field: &unknownValue},
		{name: "zero field length", field: &flowv1.NetFlowV9DecodedField{FieldId: 1, Value: &flowv1.NetFlowV9DecodedField_UnsignedValue{UnsignedValue: 1}}},
		{name: "oversized unsigned field", field: &flowv1.NetFlowV9DecodedField{FieldId: 1, FieldLength: 9, Value: &flowv1.NetFlowV9DecodedField_UnsignedValue{UnsignedValue: 1}}},
		{name: "byte length mismatch", field: &flowv1.NetFlowV9DecodedField{FieldId: 400, FieldLength: 4, Value: &flowv1.NetFlowV9DecodedField_BytesValue{BytesValue: []byte{1}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateRawEventEnvelope(validNetFlowV9Event(&flowv1.NetFlowV9Flow{
				SourceId:      7,
				TemplateId:    256,
				DecodedFields: []*flowv1.NetFlowV9DecodedField{tt.field},
			}))
			if err == nil {
				t.Fatal("expected validation error")
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

func validNetFlowV9Event(flow *flowv1.NetFlowV9Flow) *flowv1.RawFlowEventEnvelope {
	event := validRawEvent()
	event.Source.SourceType = flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9
	event.Payload.Payload = &flowv1.RawEventPayload_NetflowV9{NetflowV9: flow}
	return event
}

func TestPartitionKey(t *testing.T) {
	t.Parallel()
	if got := PartitionKey(nil); got != "" {
		t.Errorf("PartitionKey(nil) = %q, want empty", got)
	}
	source := &flowv1.SourceIdentity{CollectorId: "col", SourceHost: "host"}
	if got := PartitionKey(source); got != "col:host" {
		t.Errorf("PartitionKey() = %q, want col:host", got)
	}
}

func TestValidateRawEventEnvelopeEdgeCases(t *testing.T) {
	t.Parallel()

	// nil event
	if err := ValidateRawEventEnvelope(nil); err == nil {
		t.Error("expected error for nil event")
	}

	// invalid uuidv7
	ev := validRawEvent()
	ev.EventId = "not-uuidv7"
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for invalid UUIDv7 event_id")
	}

	// bad schema version
	ev = validRawEvent()
	ev.SchemaVersion = "99.0"
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for invalid schema version")
	}

	// nil received_at
	ev = validRawEvent()
	ev.ReceivedAt = nil
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for nil received_at")
	}

	// invalid received_at
	ev = validRawEvent()
	ev.ReceivedAt = &timestamppb.Timestamp{Nanos: -1} // invalid nanos
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for invalid received_at")
	}

	// nil payload
	ev = validRawEvent()
	ev.Payload = &flowv1.RawEventPayload{Payload: nil}
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for nil payload wrapper")
	}
}

func TestValidateSourceIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		source  *flowv1.SourceIdentity
		wantErr bool
	}{
		{"nil source", nil, true},
		{"empty collector_id", &flowv1.SourceIdentity{CollectorId: "", SourceType: flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5, SourceHost: "h"}, true},
		{"unspecified source_type", &flowv1.SourceIdentity{CollectorId: "c", SourceType: flowv1.SourceType_SOURCE_TYPE_UNSPECIFIED, SourceHost: "h"}, true},
		{"empty source_host", &flowv1.SourceIdentity{CollectorId: "c", SourceType: flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5, SourceHost: ""}, true},
		{"unknown source_type", &flowv1.SourceIdentity{CollectorId: "c", SourceType: 999, SourceHost: "h"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := validRawEvent()
			ev.Source = tt.source
			ev.PartitionKey = PartitionKey(tt.source)
			err := ValidateRawEventEnvelope(ev)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateRawEventEnvelope() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePayloadMatchesSourceAll(t *testing.T) {
	t.Parallel()

	// Test Netflow V5
	ev := validRawEvent()
	ev.Source.SourceType = flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5
	ev.Payload.Payload = &flowv1.RawEventPayload_NetflowV5{NetflowV5: &flowv1.NetFlowV5Flow{}}
	if err := ValidateRawEventEnvelope(ev); err != nil {
		t.Errorf("Netflow V5 validation failed: %v", err)
	}

	// Test Zeek Conn JSON
	ev = validRawEvent()
	ev.Source.SourceType = flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON
	ev.Payload.Payload = &flowv1.RawEventPayload_ZeekConn{ZeekConn: &flowv1.ZeekConnFlow{}}
	if err := ValidateRawEventEnvelope(ev); err != nil {
		t.Errorf("Zeek Conn JSON validation failed: %v", err)
	}

	// Test REST JSON
	ev = validRawEvent()
	ev.Source.SourceType = flowv1.SourceType_SOURCE_TYPE_REST_JSON
	ev.Payload.Payload = &flowv1.RawEventPayload_RestFlow{RestFlow: &flowv1.RestFlowInput{}}
	if err := ValidateRawEventEnvelope(ev); err != nil {
		t.Errorf("REST JSON validation failed: %v", err)
	}

	// Test Syslog CEF / LEEF
	ev = validRawEvent()
	ev.Source.SourceType = flowv1.SourceType_SOURCE_TYPE_SYSLOG_CEF
	ev.Payload.Payload = &flowv1.RawEventPayload_Syslog{Syslog: &flowv1.SyslogFlow{}}
	if err := ValidateRawEventEnvelope(ev); err != nil {
		t.Errorf("Syslog CEF validation failed: %v", err)
	}

	ev = validRawEvent()
	ev.Source.SourceType = flowv1.SourceType_SOURCE_TYPE_SYSLOG_LEEF
	ev.Payload.Payload = &flowv1.RawEventPayload_Syslog{Syslog: &flowv1.SyslogFlow{}}
	if err := ValidateRawEventEnvelope(ev); err != nil {
		t.Errorf("Syslog LEEF validation failed: %v", err)
	}

	// Test Suricata EVE JSON (should fail as not defined)
	ev = validRawEvent()
	ev.Source.SourceType = flowv1.SourceType_SOURCE_TYPE_SURICATA_EVE_JSON
	ev.Payload.Payload = &flowv1.RawEventPayload_RestFlow{RestFlow: &flowv1.RestFlowInput{}} // Mismatched or any payload
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for Suricata EVE JSON")
	}

	// Test Mismatch
	ev = validRawEvent()
	ev.Source.SourceType = flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5
	ev.Payload.Payload = &flowv1.RawEventPayload_ZeekConn{ZeekConn: &flowv1.ZeekConnFlow{}}
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for mismatched source and payload")
	}
}

func TestValidateNetFlowV9Fields(t *testing.T) {
	t.Parallel()

	// nil field in decoded fields
	ev := validNetFlowV9Event(&flowv1.NetFlowV9Flow{
		DecodedFields: []*flowv1.NetFlowV9DecodedField{nil},
	})
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for nil decoded field")
	}

	// field_id = 0
	ev = validNetFlowV9Event(&flowv1.NetFlowV9Flow{
		DecodedFields: []*flowv1.NetFlowV9DecodedField{{FieldId: 0, FieldLength: 4}},
	})
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for field_id = 0")
	}

	// length = 0
	ev = validNetFlowV9Event(&flowv1.NetFlowV9Flow{
		DecodedFields: []*flowv1.NetFlowV9DecodedField{{FieldId: 1, FieldLength: 0}},
	})
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for field_length = 0")
	}

	// blank name when name is non-nil
	blankName := "  "
	ev = validNetFlowV9Event(&flowv1.NetFlowV9Flow{
		DecodedFields: []*flowv1.NetFlowV9DecodedField{{FieldId: 1, FieldLength: 4, Name: &blankName}},
	})
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for blank field name")
	}

	// unsigned value exceeds length limit
	ev = validNetFlowV9Event(&flowv1.NetFlowV9Flow{
		DecodedFields: []*flowv1.NetFlowV9DecodedField{{
			FieldId: 1, FieldLength: 2,
			Value: &flowv1.NetFlowV9DecodedField_UnsignedValue{UnsignedValue: 65536}, // 2^16 requires 2 bytes, 65536 requires >2 bytes
		}},
	})
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for unsigned value exceeding field length")
	}

	// string value exceeds length
	ev = validNetFlowV9Event(&flowv1.NetFlowV9Flow{
		DecodedFields: []*flowv1.NetFlowV9DecodedField{{
			FieldId: 99, FieldLength: 2,
			Value: &flowv1.NetFlowV9DecodedField_StringValue{StringValue: "abc"}, // length 3 > 2
		}},
	})
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for string exceeding field length")
	}

	// invalid UTF-8 string
	ev = validNetFlowV9Event(&flowv1.NetFlowV9Flow{
		DecodedFields: []*flowv1.NetFlowV9DecodedField{{
			FieldId: 99, FieldLength: 10,
			Value: &flowv1.NetFlowV9DecodedField_StringValue{StringValue: "\xff\xfe\xfd"},
		}},
	})
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for invalid UTF-8 string")
	}

	// IPv4 invalid address format
	ev = validNetFlowV9Event(&flowv1.NetFlowV9Flow{
		DecodedFields: []*flowv1.NetFlowV9DecodedField{{
			FieldId: 8, FieldLength: 4, // IPv4 field ID
			Value: &flowv1.NetFlowV9DecodedField_StringValue{StringValue: "invalid-ip"},
		}},
	})
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for invalid IPv4 address")
	}

	// IPv4 invalid length
	ev = validNetFlowV9Event(&flowv1.NetFlowV9Flow{
		DecodedFields: []*flowv1.NetFlowV9DecodedField{{
			FieldId: 8, FieldLength: 5,
			Value: &flowv1.NetFlowV9DecodedField_StringValue{StringValue: "1.1.1.1"},
		}},
	})
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for IPv4 with incorrect length")
	}

	// IPv6 invalid address format
	ev = validNetFlowV9Event(&flowv1.NetFlowV9Flow{
		DecodedFields: []*flowv1.NetFlowV9DecodedField{{
			FieldId: 27, FieldLength: 16, // IPv6 field ID
			Value: &flowv1.NetFlowV9DecodedField_StringValue{StringValue: "invalid-ip6"},
		}},
	})
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for invalid IPv6 address")
	}

	// IPv6 invalid length
	ev = validNetFlowV9Event(&flowv1.NetFlowV9Flow{
		DecodedFields: []*flowv1.NetFlowV9DecodedField{{
			FieldId: 27, FieldLength: 15,
			Value: &flowv1.NetFlowV9DecodedField_StringValue{StringValue: "::1"},
		}},
	})
	if err := ValidateRawEventEnvelope(ev); err == nil {
		t.Error("expected error for IPv6 with incorrect length")
	}
}

func TestValidateDeadLetterEventEdgeCases(t *testing.T) {
	t.Parallel()

	// nil event
	if err := ValidateDeadLetterEvent(nil); err == nil {
		t.Error("expected error for nil DeadLetterEvent")
	}

	validDL := func() *flowv1.DeadLetterEvent {
		return &flowv1.DeadLetterEvent{
			DeadLetterId:  "01934d7c-79b4-7000-8b69-001122334455",
			SchemaVersion: domain.RawSchemaVersion,
			Stage:         flowv1.IngestionStage_INGESTION_STAGE_PARSER,
			Source:        validSource(),
			FailedAt:      timestamppb.Now(),
			Error:         &flowv1.ErrorInfo{ErrorCode: "ERR"},
			RawPayloadDebug: &flowv1.RawPayloadDebug{
				Masked:   true,
				Encoding: flowv1.PayloadEncoding_PAYLOAD_ENCODING_TEXT,
			},
		}
	}

	// invalid dead_letter_id
	dl := validDL()
	dl.DeadLetterId = "invalid-uuid"
	if err := ValidateDeadLetterEvent(dl); err == nil {
		t.Error("expected error for invalid dead_letter_id")
	}

	// invalid schema version
	dl = validDL()
	dl.SchemaVersion = "bad"
	if err := ValidateDeadLetterEvent(dl); err == nil {
		t.Error("expected error for invalid schema version")
	}

	// stage unspecified
	dl = validDL()
	dl.Stage = flowv1.IngestionStage_INGESTION_STAGE_UNSPECIFIED
	if err := ValidateDeadLetterEvent(dl); err == nil {
		t.Error("expected error for unspecified stage")
	}

	// invalid source
	dl = validDL()
	dl.Source = &flowv1.SourceIdentity{CollectorId: ""}
	if err := ValidateDeadLetterEvent(dl); err == nil {
		t.Error("expected error for invalid source in DL")
	}

	// nil failed_at
	dl = validDL()
	dl.FailedAt = nil
	if err := ValidateDeadLetterEvent(dl); err == nil {
		t.Error("expected error for nil failed_at")
	}

	// invalid failed_at
	dl = validDL()
	dl.FailedAt = &timestamppb.Timestamp{Nanos: -1}
	if err := ValidateDeadLetterEvent(dl); err == nil {
		t.Error("expected error for invalid failed_at")
	}

	// nil error
	dl = validDL()
	dl.Error = nil
	if err := ValidateDeadLetterEvent(dl); err == nil {
		t.Error("expected error for nil error info")
	}

	// blank error code
	dl = validDL()
	dl.Error = &flowv1.ErrorInfo{ErrorCode: "  "}
	if err := ValidateDeadLetterEvent(dl); err == nil {
		t.Error("expected error for blank error code")
	}

	// neither raw_event nor raw_payload_debug set
	dl = validDL()
	dl.RawPayloadDebug = nil
	dl.RawEvent = nil
	if err := ValidateDeadLetterEvent(dl); err == nil {
		t.Error("expected error for missing both raw_event and raw_payload_debug")
	}

	// raw_event set but invalid
	dl = validDL()
	dl.RawEvent = &flowv1.RawFlowEventEnvelope{EventId: "bad"}
	if err := ValidateDeadLetterEvent(dl); err == nil {
		t.Error("expected error for invalid nested raw_event")
	}

	// raw_payload_debug unspecified encoding
	dl = validDL()
	dl.RawPayloadDebug.Encoding = flowv1.PayloadEncoding_PAYLOAD_ENCODING_UNSPECIFIED
	if err := ValidateDeadLetterEvent(dl); err == nil {
		t.Error("expected error for unspecified payload encoding")
	}
}
