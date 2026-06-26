package normalize

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/validation"
)

const normalizationFailureCode = "normalization_failed"

func NewDeadLetterEvent(event *flowv1.RawFlowEventEnvelope, cause error, now time.Time) (*flowv1.DeadLetterEvent, error) {
	if event == nil {
		return nil, fmt.Errorf("%w: raw event is nil", ErrNormalize)
	}
	if cause == nil {
		return nil, fmt.Errorf("%w: cause is required", ErrNormalize)
	}
	if now.IsZero() {
		now = time.Now()
	}
	deadLetterID, err := domain.NewUUIDv7(now)
	if err != nil {
		return nil, fmt.Errorf("%w: generate dead-letter id: %w", ErrNormalize, err)
	}
	deadLetter := &flowv1.DeadLetterEvent{
		DeadLetterId:  deadLetterID,
		SchemaVersion: domain.RawSchemaVersion,
		Stage:         flowv1.IngestionStage_INGESTION_STAGE_NORMALIZER,
		Source:        event.GetSource(),
		ReceivedAt:    event.GetReceivedAt(),
		FailedAt:      timestamppb.New(now.UTC()),
		Error: &flowv1.ErrorInfo{
			ErrorCode:    normalizationFailureCode,
			ErrorMessage: cause.Error(),
			Retryable:    false,
		},
		RawEvent: event,
	}
	if err := validation.ValidateDeadLetterEvent(deadLetter); err != nil {
		return nil, fmt.Errorf("%w: invalid dead-letter event: %w", ErrNormalize, err)
	}
	return deadLetter, nil
}
