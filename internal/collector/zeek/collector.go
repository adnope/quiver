package zeek

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"syscall"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/observability"
	"github.com/adnope/quiver/internal/storage/postgres"
	"github.com/adnope/quiver/internal/validation"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ErrCollector = errors.New("zeek: collector failed")

type Collector struct {
	cfg          config.ZeekCollectorConfig
	state        postgres.CollectorStateStore
	publisher    kafka.RawEventPublisher
	metrics      *observability.Registry
	logger       *slog.Logger
	now          func() time.Time
	activeFile   *os.File
	activeDevice uint64
	activeInode  uint64
	activeOffset int64
}

func NewCollector(
	cfg config.ZeekCollectorConfig,
	state postgres.CollectorStateStore,
	publisher kafka.RawEventPublisher,
	metrics *observability.Registry,
	logger *slog.Logger,
) (*Collector, error) {
	if state == nil {
		return nil, fmt.Errorf("%w: state store is nil", ErrCollector)
	}
	if publisher == nil {
		return nil, fmt.Errorf("%w: publisher is nil", ErrCollector)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{cfg: cfg, state: state, publisher: publisher, metrics: metrics, logger: logger, now: time.Now}, nil
}

func (c *Collector) Stop() {
	if c.activeFile != nil {
		_ = c.activeFile.Close()
		c.activeFile = nil
	}
}

func (c *Collector) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.cfg.PollInterval.Std())
	defer ticker.Stop()
	defer c.Stop()
	for {
		if err := c.ProcessOnce(ctx); err != nil && !errors.Is(err, kafka.ErrQueueFull) {
			c.logger.WarnContext(ctx, "zeek poll failed", slog.String("component", "zeek_collector"), slog.Any("error", err))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *Collector) ProcessOnce(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("process zeek file: %w", err)
	}
	info, err := os.Stat(c.cfg.FilePath)
	if err != nil {
		return fmt.Errorf("%w: stat file: %v", ErrCollector, err)
	}
	deviceID, inode := fileIdentity(info)

	if c.activeFile == nil {
		offset, err := c.startOffset(ctx, info.Size(), deviceID, inode)
		if err != nil {
			return err
		}
		file, err := os.Open(c.cfg.FilePath)
		if err != nil {
			return fmt.Errorf("%w: open file: %v", ErrCollector, err)
		}
		c.activeFile = file
		c.activeDevice = deviceID
		c.activeInode = inode
		c.activeOffset = offset
	} else if c.activeInode != inode || c.activeDevice != deviceID {
		c.logger.Info("zeek file rotation detected, processing remaining tail of old file",
			slog.Uint64("old_inode", c.activeInode), slog.Uint64("new_inode", inode))

		if err := c.readToEOF(ctx); err != nil {
			return fmt.Errorf("read tail of old file: %w", err)
		}
		_ = c.activeFile.Close()

		file, err := os.Open(c.cfg.FilePath)
		if err != nil {
			c.activeFile = nil
			return fmt.Errorf("%w: open new rotated file: %v", ErrCollector, err)
		}
		c.activeFile = file
		c.activeDevice = deviceID
		c.activeInode = inode
		c.activeOffset = 0
	} else {
		if info.Size() < c.activeOffset {
			c.logger.Warn("zeek file size smaller than offset, treating as truncate",
				slog.Int64("offset", c.activeOffset), slog.Int64("size", info.Size()))
			c.activeOffset = 0
		}
	}

	if _, err := c.activeFile.Seek(c.activeOffset, io.SeekStart); err != nil {
		return fmt.Errorf("%w: seek file to %d: %v", ErrCollector, c.activeOffset, err)
	}

	return c.readToEOF(ctx)
}

func (c *Collector) readToEOF(ctx context.Context) error {
	reader := bufio.NewReaderSize(c.activeFile, max(4096, c.cfg.MaxLineBytes))
	info, err := c.activeFile.Stat()
	if err != nil {
		return fmt.Errorf("%w: stat active file: %v", ErrCollector, err)
	}

	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > c.cfg.MaxLineBytes {
			if err := c.publishLineDLQ(ctx, line, "line_too_large"); err != nil {
				return err
			}
			c.activeOffset += int64(len(line))
			if err := c.saveOffset(ctx, c.activeOffset, info.Size(), c.activeDevice, c.activeInode); err != nil {
				return err
			}
			continue
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return fmt.Errorf("%w: read line: %v", ErrCollector, readErr)
		}
		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) == 0 {
			c.activeOffset += int64(len(line))
			if err := c.saveOffset(ctx, c.activeOffset, info.Size(), c.activeDevice, c.activeInode); err != nil {
				return err
			}
			continue
		}
		flow, err := ParseConnLine(trimmed)
		if err != nil {
			if err := c.publishLineDLQ(ctx, trimmed, "invalid_json"); err != nil {
				return err
			}
			c.metric("collector_parse_errors_total", map[string]string{"error_code": "invalid_json"})
			c.activeOffset += int64(len(line))
			if err := c.saveOffset(ctx, c.activeOffset, info.Size(), c.activeDevice, c.activeInode); err != nil {
				return err
			}
			continue
		}
		event, err := c.rawEvent(flow)
		if err != nil {
			return err
		}
		c.metric("collector_events_received_total", nil)
		if err := c.publisher.PublishRaw(ctx, event); err != nil {
			if errors.Is(err, kafka.ErrQueueFull) {
				c.metric("collector_dropped_events_total", map[string]string{"reason": "queue_full"})
				return err
			}
			return fmt.Errorf("%w: publish raw: %v", ErrCollector, err)
		}
		c.metric("collector_events_published_total", nil)
		c.activeOffset += int64(len(line))
		if err := c.saveOffset(ctx, c.activeOffset, info.Size(), c.activeDevice, c.activeInode); err != nil {
			return err
		}
	}
}

func (c *Collector) startOffset(ctx context.Context, size int64, deviceID uint64, inode uint64) (int64, error) {
	state, found, err := c.state.Load(ctx, c.cfg.StateKey)
	if err != nil {
		return 0, fmt.Errorf("%w: load state: %v", ErrCollector, err)
	}
	if found {
		var zeekState postgres.ZeekState
		if err := jsonUnmarshal(state.State, &zeekState); err != nil {
			return 0, fmt.Errorf("%w: decode state: %v", ErrCollector, err)
		}
		if zeekState.DeviceID == deviceID && zeekState.Inode == inode && zeekState.Offset <= size {
			return zeekState.Offset, nil
		}
		c.logger.Warn("zeek collector restarted with different file inode or size mismatch, possible missed tail",
			slog.Uint64("stored_inode", zeekState.Inode), slog.Uint64("current_inode", inode),
			slog.Int64("stored_offset", zeekState.Offset), slog.Int64("current_size", size))
		return 0, nil
	}
	if c.cfg.StartPosition == "beginning" {
		return 0, nil
	}
	return size, nil
}

func (c *Collector) rawEvent(flow *flowv1.ZeekConnFlow) (*flowv1.RawFlowEventEnvelope, error) {
	eventID, err := domain.NewUUIDv7(c.now())
	if err != nil {
		return nil, fmt.Errorf("%w: generate event id: %v", ErrCollector, err)
	}
	source := &flowv1.SourceIdentity{
		CollectorId: c.cfg.CollectorID,
		SourceType:  flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON,
		SourceHost:  c.cfg.SourceHost,
	}
	event := &flowv1.RawFlowEventEnvelope{
		EventId:       eventID,
		SchemaVersion: domain.RawSchemaVersion,
		Source:        source,
		ReceivedAt:    timestamppb.New(c.now().UTC()),
		PartitionKey:  validation.PartitionKey(source),
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_ZeekConn{ZeekConn: flow},
		},
	}
	if err := validation.ValidateRawEventEnvelope(event); err != nil {
		return nil, fmt.Errorf("%w: validate raw event: %v", ErrCollector, err)
	}
	return event, nil
}

func (c *Collector) publishLineDLQ(ctx context.Context, line []byte, code string) error {
	deadLetterID, err := domain.NewUUIDv7(c.now())
	if err != nil {
		return fmt.Errorf("%w: generate dead-letter id: %v", ErrCollector, err)
	}
	source := &flowv1.SourceIdentity{
		CollectorId: c.cfg.CollectorID,
		SourceType:  flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON,
		SourceHost:  c.cfg.SourceHost,
	}
	payload := maskLine(line)
	event := &flowv1.DeadLetterEvent{
		DeadLetterId:  deadLetterID,
		SchemaVersion: domain.RawSchemaVersion,
		Stage:         flowv1.IngestionStage_INGESTION_STAGE_PARSER,
		Source:        source,
		FailedAt:      timestamppb.New(c.now().UTC()),
		Error:         &flowv1.ErrorInfo{ErrorCode: code, ErrorMessage: "invalid zeek json line"},
		RawPayloadDebug: &flowv1.RawPayloadDebug{
			Masked:            true,
			Encoding:          flowv1.PayloadEncoding_PAYLOAD_ENCODING_TEXT,
			Data:              payload,
			Sha256:            sha256Hex(line),
			OriginalSizeBytes: uint64(len(line)),
		},
	}
	if err := validation.ValidateDeadLetterEvent(event); err != nil {
		return fmt.Errorf("%w: validate dead-letter: %v", ErrCollector, err)
	}
	if err := c.publisher.PublishDeadLetter(ctx, event); err != nil {
		return fmt.Errorf("%w: publish dead-letter: %v", ErrCollector, err)
	}
	return nil
}

func (c *Collector) saveOffset(ctx context.Context, offset int64, size int64, deviceID uint64, inode uint64) error {
	state, err := postgres.NewZeekCollectorState(c.cfg.StateKey, c.cfg.CollectorID, c.cfg.SourceHost, postgres.ZeekState{
		FilePath:        c.cfg.FilePath,
		DeviceID:        deviceID,
		Inode:           inode,
		Offset:          offset,
		LastFileSize:    size,
		LastCommittedAt: c.now().UTC(),
	})
	if err != nil {
		return err
	}
	return c.state.Save(ctx, state)
}

func (c *Collector) metric(name string, labels map[string]string) {
	if c.metrics == nil {
		return
	}
	base := map[string]string{
		"collector_id": c.cfg.CollectorID,
		"source_type":  string(domain.SourceTypeZeekConnJSON),
		"source_host":  c.cfg.SourceHost,
	}
	for key, value := range labels {
		base[key] = value
	}
	c.metrics.Inc(name, base)
}

func fileIdentity(info os.FileInfo) (uint64, uint64) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, uint64(info.ModTime().UnixNano())
	}
	return uint64(stat.Dev), uint64(stat.Ino)
}

func maskLine(line []byte) []byte {
	return []byte(`{"masked":true}`)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func jsonUnmarshal(data []byte, target any) error {
	return json.Unmarshal(data, target)
}
