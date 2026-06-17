package validation

import (
	"errors"
	"fmt"
	"strings"

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
			return fmt.Errorf("%w: invalid raw_event: %v", ErrInvalidProtobufEvent, err)
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
