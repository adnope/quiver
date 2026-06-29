package validation

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

var ErrInvalidProtobufEvent = errors.New("validation: invalid protobuf event")

func PartitionKey(source *flowv1.SourceIdentity) string {
	if source == nil {
		return ""
	}
	return source.GetCollectorId() + ":" + source.GetSourceHost()
}

func ValidateRawEventEnvelope(event *flowv1.RawFlowEventEnvelope) error {
	if event == nil {
		return fmt.Errorf("%w: raw event is nil", ErrInvalidProtobufEvent)
	}
	if !domain.IsUUIDv7(event.GetEventId()) {
		return fmt.Errorf("%w: event_id must be uuidv7", ErrInvalidProtobufEvent)
	}
	if event.GetSchemaVersion() != domain.RawSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidProtobufEvent, domain.RawSchemaVersion)
	}
	if err := validateSource(event.GetSource(), true); err != nil {
		return err
	}
	if event.GetReceivedAt() == nil || !event.GetReceivedAt().IsValid() {
		return fmt.Errorf("%w: received_at is required", ErrInvalidProtobufEvent)
	}
	if event.GetPartitionKey() != PartitionKey(event.GetSource()) {
		return fmt.Errorf("%w: partition_key must equal collector_id + ':' + source_host", ErrInvalidProtobufEvent)
	}
	if event.GetPayload() == nil || event.GetPayload().GetPayload() == nil {
		return fmt.Errorf("%w: exactly one raw payload is required", ErrInvalidProtobufEvent)
	}
	if err := validatePayloadMatchesSource(event.GetSource().GetSourceType(), event.GetPayload()); err != nil {
		return err
	}
	if flow := event.GetPayload().GetNetflowV9(); flow != nil {
		if err := validateNetFlowV9(flow); err != nil {
			return err
		}
	}
	return nil
}

func validateNetFlowV9(flow *flowv1.NetFlowV9Flow) error {
	for index, field := range flow.GetDecodedFields() {
		if field == nil {
			return fmt.Errorf("%w: netflow_v9.decoded_fields[%d] is nil", ErrInvalidProtobufEvent, index)
		}
		if field.GetFieldId() == 0 || field.GetFieldId() > 65535 {
			return fmt.Errorf("%w: netflow_v9.decoded_fields[%d].field_id must be within 1..65535", ErrInvalidProtobufEvent, index)
		}
		length := field.GetFieldLength()
		if length == 0 || length > 65535 {
			return fmt.Errorf("%w: netflow_v9.decoded_fields[%d].field_length must be within 1..65535", ErrInvalidProtobufEvent, index)
		}
		if field.Name != nil && strings.TrimSpace(field.GetName()) == "" {
			return fmt.Errorf("%w: netflow_v9.decoded_fields[%d].name must not be blank", ErrInvalidProtobufEvent, index)
		}

		switch value := field.GetValue().(type) {
		case *flowv1.NetFlowV9DecodedField_UnsignedValue:
			if length > 8 {
				return fmt.Errorf("%w: netflow_v9.decoded_fields[%d] unsigned field length exceeds 8", ErrInvalidProtobufEvent, index)
			}
			if length < 8 && value.UnsignedValue >= uint64(1)<<(length*8) {
				return fmt.Errorf("%w: netflow_v9.decoded_fields[%d] unsigned value exceeds field length", ErrInvalidProtobufEvent, index)
			}
		case *flowv1.NetFlowV9DecodedField_StringValue:
			if !utf8.ValidString(value.StringValue) {
				return fmt.Errorf("%w: netflow_v9.decoded_fields[%d] string value is not valid utf-8", ErrInvalidProtobufEvent, index)
			}
			if err := validateNetFlowV9StringField(field.GetFieldId(), length, value.StringValue); err != nil {
				return fmt.Errorf("%w: netflow_v9.decoded_fields[%d]: %w", ErrInvalidProtobufEvent, index, err)
			}
		case *flowv1.NetFlowV9DecodedField_BytesValue:
			if len(value.BytesValue) != int(length) {
				return fmt.Errorf("%w: netflow_v9.decoded_fields[%d] bytes value length mismatch", ErrInvalidProtobufEvent, index)
			}
		case nil:
			return fmt.Errorf("%w: netflow_v9.decoded_fields[%d] has unknown or missing value", ErrInvalidProtobufEvent, index)
		default:
			return fmt.Errorf("%w: netflow_v9.decoded_fields[%d] has unsupported value", ErrInvalidProtobufEvent, index)
		}
	}
	return nil
}

func validateNetFlowV9StringField(fieldID uint32, length uint32, value string) error {
	switch fieldID {
	case 8, 12, 15, 18, 44, 45, 47:
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || length != 4 {
			return fmt.Errorf("ipv4 value requires a four-byte field")
		}
	case 27, 28, 62, 63:
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is6() || length != 16 {
			return fmt.Errorf("ipv6 value requires a sixteen-byte field")
		}
	default:
		if len(value) > int(length) {
			return fmt.Errorf("string value exceeds field length")
		}
	}
	return nil
}

func ValidateDeadLetterEvent(event *flowv1.DeadLetterEvent) error {
	if event == nil {
		return fmt.Errorf("%w: dead-letter event is nil", ErrInvalidProtobufEvent)
	}
	if !domain.IsUUIDv7(event.GetDeadLetterId()) {
		return fmt.Errorf("%w: dead_letter_id must be uuidv7", ErrInvalidProtobufEvent)
	}
	if event.GetSchemaVersion() != domain.RawSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidProtobufEvent, domain.RawSchemaVersion)
	}
	if event.GetStage() == flowv1.IngestionStage_INGESTION_STAGE_UNSPECIFIED {
		return fmt.Errorf("%w: stage is required", ErrInvalidProtobufEvent)
	}
	if event.GetSource() != nil {
		if err := validateSource(event.GetSource(), false); err != nil {
			return err
		}
	}
	if event.GetFailedAt() == nil || !event.GetFailedAt().IsValid() {
		return fmt.Errorf("%w: failed_at is required", ErrInvalidProtobufEvent)
	}
	if event.GetError() == nil || strings.TrimSpace(event.GetError().GetErrorCode()) == "" {
		return fmt.Errorf("%w: error.error_code is required", ErrInvalidProtobufEvent)
	}
	if event.GetRawEvent() != nil {
		if err := ValidateRawEventEnvelope(event.GetRawEvent()); err != nil {
			return fmt.Errorf("%w: invalid raw_event: %w", ErrInvalidProtobufEvent, err)
		}
	}
	if event.GetRawEvent() == nil && event.GetRawPayloadDebug() == nil {
		return fmt.Errorf("%w: raw_event or raw_payload_debug is required", ErrInvalidProtobufEvent)
	}
	if debug := event.GetRawPayloadDebug(); debug != nil {
		if debug.GetEncoding() == flowv1.PayloadEncoding_PAYLOAD_ENCODING_UNSPECIFIED {
			return fmt.Errorf("%w: raw_payload_debug.encoding is required", ErrInvalidProtobufEvent)
		}
		if !debug.GetMasked() {
			return fmt.Errorf("%w: raw_payload_debug must be masked", ErrInvalidProtobufEvent)
		}
	}
	return nil
}

func validateSource(source *flowv1.SourceIdentity, strict bool) error {
	if source == nil {
		return fmt.Errorf("%w: source is required", ErrInvalidProtobufEvent)
	}
	if strings.TrimSpace(source.GetCollectorId()) == "" {
		return fmt.Errorf("%w: source.collector_id is required", ErrInvalidProtobufEvent)
	}
	if source.GetSourceType() == flowv1.SourceType_SOURCE_TYPE_UNSPECIFIED {
		return fmt.Errorf("%w: source.source_type is required", ErrInvalidProtobufEvent)
	}
	if strings.TrimSpace(source.GetSourceHost()) == "" {
		return fmt.Errorf("%w: source.source_host is required", ErrInvalidProtobufEvent)
	}
	if strict {
		return validateGeneratedSourceType(source.GetSourceType())
	}
	return nil
}

func validateGeneratedSourceType(sourceType flowv1.SourceType) error {
	switch sourceType {
	case flowv1.SourceType_SOURCE_TYPE_UNSPECIFIED:
		return fmt.Errorf("%w: unknown source.source_type %d", ErrInvalidProtobufEvent, sourceType)
	case flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5,
		flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON,
		flowv1.SourceType_SOURCE_TYPE_REST_JSON,
		flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9,
		flowv1.SourceType_SOURCE_TYPE_SYSLOG_CEF,
		flowv1.SourceType_SOURCE_TYPE_SYSLOG_LEEF,
		flowv1.SourceType_SOURCE_TYPE_SURICATA_EVE_JSON:
		return nil
	default:
		return fmt.Errorf("%w: unknown source.source_type %d", ErrInvalidProtobufEvent, sourceType)
	}
}

func validatePayloadMatchesSource(sourceType flowv1.SourceType, payload *flowv1.RawEventPayload) error {
	switch sourceType {
	case flowv1.SourceType_SOURCE_TYPE_UNSPECIFIED:
		return fmt.Errorf("%w: source.payload does not match source.source_type %d", ErrInvalidProtobufEvent, sourceType)
	case flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5:
		if payload.GetNetflowV5() != nil {
			return nil
		}
	case flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON:
		if payload.GetZeekConn() != nil {
			return nil
		}
	case flowv1.SourceType_SOURCE_TYPE_REST_JSON:
		if payload.GetRestFlow() != nil {
			return nil
		}
	case flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9:
		if payload.GetNetflowV9() != nil {
			return nil
		}
	case flowv1.SourceType_SOURCE_TYPE_SYSLOG_CEF, flowv1.SourceType_SOURCE_TYPE_SYSLOG_LEEF:
		if payload.GetSyslog() != nil {
			return nil
		}
	case flowv1.SourceType_SOURCE_TYPE_SURICATA_EVE_JSON:
		return fmt.Errorf("%w: suricata payload is not defined in raw.v1", ErrInvalidProtobufEvent)
	default:
		return fmt.Errorf("%w: unsupported source.source_type %d", ErrInvalidProtobufEvent, sourceType)
	}
	return fmt.Errorf("%w: payload variant does not match source.source_type", ErrInvalidProtobufEvent)
}
