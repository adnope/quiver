package netflowv9

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/validation"
)

func mapDecodedField(f DecodedField) *flowv1.NetFlowV9DecodedField {
	pb := &flowv1.NetFlowV9DecodedField{
		FieldId:     uint32(f.ID),
		FieldLength: uint32(f.Length),
	}
	if f.Name != "" {
		pb.Name = new(string)
		*pb.Name = f.Name
	}
	switch f.Value.Kind {
	case ValueKindUnsigned:
		pb.Value = &flowv1.NetFlowV9DecodedField_UnsignedValue{UnsignedValue: f.Value.Unsigned}
	case ValueKindString:
		pb.Value = &flowv1.NetFlowV9DecodedField_StringValue{StringValue: f.Value.String}
	case ValueKindBytes, ValueKindUnknown:
		pb.Value = &flowv1.NetFlowV9DecodedField_BytesValue{BytesValue: f.Value.Bytes}
	default:
		pb.Value = &flowv1.NetFlowV9DecodedField_BytesValue{BytesValue: f.Value.Bytes}
	}
	return pb
}

func mapCompatibilityFields(fields []DecodedField) (*structpb.Struct, error) {
	m := make(map[string]any, len(fields))
	for _, f := range fields {
		name := f.Name
		if name == "" {
			name = "field_" + strconv.Itoa(int(f.ID))
		}
		switch f.Value.Kind {
		case ValueKindUnsigned:
			m[name] = strconv.FormatUint(f.Value.Unsigned, 10)
		case ValueKindString:
			m[name] = f.Value.String
		case ValueKindBytes, ValueKindUnknown:
			m[name] = base64.StdEncoding.EncodeToString(f.Value.Bytes)
		default:
			m[name] = base64.StdEncoding.EncodeToString(f.Value.Bytes)
		}
	}
	return structpb.NewStruct(m)
}

func buildRawEventEnvelope(
	packetContext PacketContext,
	header Header,
	flowSet FlowSet,
	record Record,
	now time.Time,
) (*flowv1.RawFlowEventEnvelope, error) {
	eventID, err := domain.NewUUIDv7(now)
	if err != nil {
		return nil, fmt.Errorf("generate event id: %w", err)
	}

	decodedFields := make([]*flowv1.NetFlowV9DecodedField, 0, len(record.Fields))
	for _, f := range record.Fields {
		decodedFields = append(decodedFields, mapDecodedField(f))
	}

	compatFields, err := mapCompatibilityFields(record.Fields)
	if err != nil {
		return nil, fmt.Errorf("map compatibility fields: %w", err)
	}

	sourceIPText := packetContext.SourceIP.String()
	source := &flowv1.SourceIdentity{
		CollectorId: packetContext.CollectorID,
		SourceType:  flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9,
		SourceHost:  packetContext.SourceHost,
		SourceIp:    &sourceIPText,
	}

	receivedAt := packetContext.ReceivedAt.UTC()
	if receivedAt.IsZero() {
		receivedAt = now.UTC()
	}

	flow := &flowv1.NetFlowV9Flow{
		SourceId:         header.SourceID,
		TemplateId:       uint32(record.TemplateID),
		RecordIndex:      record.Index,
		Fields:           compatFields,
		PacketSequence:   header.SequenceNumber,
		ExporterUptimeMs: header.SystemUptime,
		ExporterUnixTime: &timestamppb.Timestamp{Seconds: int64(header.UnixSeconds)},
		FlowsetId:        uint32(flowSet.ID),
		FlowsetIndex:     flowSet.Index,
		DecodedFields:    decodedFields,
	}

	envelope := &flowv1.RawFlowEventEnvelope{
		EventId:       eventID,
		SchemaVersion: domain.RawSchemaVersion,
		Source:        source,
		ReceivedAt:    timestamppb.New(receivedAt),
		PartitionKey:  packetContext.CollectorID + ":" + packetContext.SourceHost,
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_NetflowV9{NetflowV9: flow},
		},
	}

	if packetContext.ProxyReceivedAt != nil {
		metadata, metadataErr := structpb.NewStruct(map[string]any{
			"proxy_received_at": packetContext.ProxyReceivedAt.UTC().Format(time.RFC3339Nano),
		})
		if metadataErr != nil {
			return nil, fmt.Errorf("encode proxy metadata: %w", metadataErr)
		}
		envelope.Metadata = metadata
	}

	if err := validation.ValidateRawEventEnvelope(envelope); err != nil {
		return nil, fmt.Errorf("validate raw event: %w", err)
	}

	return envelope, nil
}
