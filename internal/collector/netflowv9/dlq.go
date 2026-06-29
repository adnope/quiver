package netflowv9

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/validation"
)

func publishDLQEvent(
	ctx context.Context,
	publisher kafka.RawEventPublisher,
	packetContext PacketContext,
	packet []byte,
	code string,
	message string,
	deadLetterMaxBytes int,
	now time.Time,
) error {
	deadLetterID, err := domain.NewUUIDv7(now)
	if err != nil {
		return fmt.Errorf("generate dead-letter id: %w", err)
	}
	sourceIPText := packetContext.SourceIP.String()
	source := &flowv1.SourceIdentity{
		CollectorId: packetContext.CollectorID,
		SourceType:  flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9,
		SourceHost:  packetContext.SourceHost,
		SourceIp:    &sourceIPText,
	}
	payload, truncated := truncatePacket(packet, deadLetterMaxBytes)
	encoding := flowv1.PayloadEncoding_PAYLOAD_ENCODING_RAW_BYTES
	if truncated {
		encoding = flowv1.PayloadEncoding_PAYLOAD_ENCODING_TRUNCATED_RAW_BYTES
	}
	event := &flowv1.DeadLetterEvent{
		DeadLetterId:  deadLetterID,
		SchemaVersion: domain.RawSchemaVersion,
		Stage:         flowv1.IngestionStage_INGESTION_STAGE_PARSER,
		Source:        source,
		FailedAt:      timestamppb.New(now.UTC()),
		Error:         &flowv1.ErrorInfo{ErrorCode: code, ErrorMessage: message},
		RawPayloadDebug: &flowv1.RawPayloadDebug{
			Masked:            true,
			Encoding:          encoding,
			Data:              payload,
			Sha256:            sha256Hex(packet),
			OriginalSizeBytes: uint64(len(packet)),
			Truncated:         truncated,
		},
	}
	if err := validation.ValidateDeadLetterEvent(event); err != nil {
		return fmt.Errorf("validate dead-letter: %w", err)
	}
	if err := publisher.PublishDeadLetter(ctx, event); err != nil {
		return fmt.Errorf("publish dead-letter: %w", err)
	}
	return nil
}

func truncatePacket(packet []byte, maxBytes int) ([]byte, bool) {
	if maxBytes <= 0 || maxBytes > 1500 {
		maxBytes = 1500
	}
	if len(packet) <= maxBytes {
		return append([]byte(nil), packet...), false
	}
	return append([]byte(nil), packet[:maxBytes]...), true
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
