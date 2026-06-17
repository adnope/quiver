package netflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/observability"
	"github.com/adnope/quiver/internal/validation"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ErrCollector = errors.New("netflow: collector failed")

type allowedSource struct {
	sourceHost   string
	samplingRate uint32
}

type Collector struct {
	cfg                config.NetFlowV5CollectorConfig
	deadLetterMaxBytes int
	publisher          kafka.RawEventPublisher
	metrics            *observability.Registry
	logger             *slog.Logger
	now                func() time.Time
	allowed            map[netip.Addr]allowedSource
	nextSequence       map[netip.Addr]uint32
}

func NewCollector(
	cfg config.NetFlowV5CollectorConfig,
	deadLetterMaxBytes int,
	publisher kafka.RawEventPublisher,
	metrics *observability.Registry,
	logger *slog.Logger,
) (*Collector, error) {
	if publisher == nil {
		return nil, fmt.Errorf("%w: publisher is nil", ErrCollector)
	}
	if deadLetterMaxBytes <= 0 {
		deadLetterMaxBytes = 1500
	}
	if deadLetterMaxBytes > 1500 {
		deadLetterMaxBytes = 1500
	}
	if logger == nil {
		logger = slog.Default()
	}
	allowed := make(map[netip.Addr]allowedSource, len(cfg.AllowedSources))
	for _, source := range cfg.AllowedSources {
		addr, err := netip.ParseAddr(source.SourceIP)
		if err != nil {
			return nil, fmt.Errorf("%w: parse allowed source %q: %v", ErrCollector, source.SourceIP, err)
		}
		if _, exists := allowed[addr]; exists {
			return nil, fmt.Errorf("%w: duplicate allowed source %q", ErrCollector, source.SourceIP)
		}
		allowed[addr] = allowedSource{sourceHost: source.SourceHost, samplingRate: source.SamplingRate}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: at least one allowed source is required", ErrCollector)
	}
	return &Collector{
		cfg:                cfg,
		deadLetterMaxBytes: deadLetterMaxBytes,
		publisher:          publisher,
		metrics:            metrics,
		logger:             logger,
		now:                time.Now,
		allowed:            allowed,
		nextSequence:       map[netip.Addr]uint32{},
	}, nil
}

func (c *Collector) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("run netflow collector: %w", err)
	}
	packetConn, err := net.ListenPacket("udp", c.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("%w: listen udp: %v", ErrCollector, err)
	}
	defer func() {
		_ = packetConn.Close()
	}()
	if c.cfg.ReadBufferBytes > 0 {
		if udpConn, ok := packetConn.(*net.UDPConn); ok {
			if err := udpConn.SetReadBuffer(c.cfg.ReadBufferBytes); err != nil {
				c.logger.WarnContext(ctx, "netflow read buffer could not be configured", slog.Any("error", err))
			}
		}
	}

	bufferSize := c.cfg.PacketBufferBytes
	if bufferSize <= 0 || bufferSize > 1500 {
		bufferSize = 1500
	}
	buffer := make([]byte, bufferSize)
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("run netflow collector: %w", err)
		}
		deadline := time.Now().Add(time.Second)
		if err := packetConn.SetReadDeadline(deadline); err != nil {
			return fmt.Errorf("%w: set read deadline: %v", ErrCollector, err)
		}
		n, addr, err := packetConn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("%w: read packet: %v", ErrCollector, err)
		}
		source, ok := sourceAddr(addr)
		if !ok {
			c.metric("collector_dropped_packets_total", map[string]string{"reason": "invalid_source_addr", "source_host": "unknown"})
			continue
		}
		packet := append([]byte(nil), buffer[:n]...)
		if err := c.HandlePacket(ctx, source, packet); err != nil {
			c.logger.WarnContext(ctx, "netflow packet handling failed", slog.Any("error", err))
		}
	}
}

func (c *Collector) HandlePacket(ctx context.Context, sourceIP netip.Addr, data []byte) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("handle netflow packet: %w", err)
	}
	source, allowed := c.allowed[sourceIP]
	if !allowed {
		c.metric("collector_dropped_packets_total", map[string]string{"reason": "source_not_allowed", "source_host": "unknown"})
		return nil
	}
	c.metric("collector_packets_received_total", map[string]string{"source_host": source.sourceHost})
	packet, err := ParseV5Packet(data)
	if err != nil {
		code := "malformed_packet"
		if errors.Is(err, ErrUnsupportedVersion) {
			code = "unsupported_version"
		}
		c.metric("collector_parse_errors_total", map[string]string{"error_code": code, "source_host": source.sourceHost})
		if dlqErr := c.publishPacketDLQ(ctx, sourceIP, source.sourceHost, data, code, err.Error()); dlqErr != nil {
			return dlqErr
		}
		return nil
	}
	c.trackSequence(sourceIP, source.sourceHost, packet.Sequence, len(packet.Records))
	for _, record := range packet.Records {
		if source.samplingRate > 0 {
			record.SamplingRate = &source.samplingRate
		}
		event, err := c.rawEvent(sourceIP, source.sourceHost, record)
		if err != nil {
			return err
		}
		if err := c.publisher.PublishRaw(ctx, event); err != nil {
			if errors.Is(err, kafka.ErrQueueFull) {
				c.metric("collector_dropped_events_total", map[string]string{"reason": "queue_full", "source_host": source.sourceHost})
				return nil
			}
			return fmt.Errorf("%w: publish raw: %v", ErrCollector, err)
		}
		c.metric("collector_events_published_total", map[string]string{"source_host": source.sourceHost})
	}
	return nil
}

func (c *Collector) trackSequence(sourceIP netip.Addr, sourceHost string, packetSequence uint32, recordCount int) {
	next, found := c.nextSequence[sourceIP]
	if found && packetSequence != next {
		c.metric("netflow_sequence_gaps_total", map[string]string{"source_host": sourceHost})
		c.logger.Warn(
			"netflow sequence gap detected",
			slog.String("collector_id", c.cfg.CollectorID),
			slog.String("source_host", sourceHost),
			slog.Uint64("expected_sequence", uint64(next)),
			slog.Uint64("packet_sequence", uint64(packetSequence)),
		)
	}
	c.nextSequence[sourceIP] = packetSequence + boundedRecordCount(recordCount)
}

func boundedRecordCount(recordCount int) uint32 {
	if recordCount <= 0 {
		return 0
	}
	if recordCount > 30 {
		return 30
	}
	// NetFlow v5 packets are validated to contain at most 30 records.
	return uint32(recordCount) //nolint:gosec
}

func (c *Collector) rawEvent(sourceIP netip.Addr, sourceHost string, flow *flowv1.NetFlowV5Flow) (*flowv1.RawFlowEventEnvelope, error) {
	eventID, err := domain.NewUUIDv7(c.now())
	if err != nil {
		return nil, fmt.Errorf("%w: generate event id: %v", ErrCollector, err)
	}
	sourceIPText := sourceIP.String()
	source := &flowv1.SourceIdentity{
		CollectorId: c.cfg.CollectorID,
		SourceType:  flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5,
		SourceHost:  sourceHost,
		SourceIp:    &sourceIPText,
	}
	event := &flowv1.RawFlowEventEnvelope{
		EventId:       eventID,
		SchemaVersion: domain.RawSchemaVersion,
		Source:        source,
		ReceivedAt:    timestamppb.New(c.now().UTC()),
		PartitionKey:  validation.PartitionKey(source),
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_NetflowV5{NetflowV5: flow},
		},
	}
	if err := validation.ValidateRawEventEnvelope(event); err != nil {
		return nil, fmt.Errorf("%w: validate raw event: %v", ErrCollector, err)
	}
	return event, nil
}

func (c *Collector) publishPacketDLQ(
	ctx context.Context,
	sourceIP netip.Addr,
	sourceHost string,
	packet []byte,
	code string,
	message string,
) error {
	deadLetterID, err := domain.NewUUIDv7(c.now())
	if err != nil {
		return fmt.Errorf("%w: generate dead-letter id: %v", ErrCollector, err)
	}
	sourceIPText := sourceIP.String()
	source := &flowv1.SourceIdentity{
		CollectorId: c.cfg.CollectorID,
		SourceType:  flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5,
		SourceHost:  sourceHost,
		SourceIp:    &sourceIPText,
	}
	payload, truncated := truncatePacket(packet, c.deadLetterMaxBytes)
	encoding := flowv1.PayloadEncoding_PAYLOAD_ENCODING_RAW_BYTES
	if truncated {
		encoding = flowv1.PayloadEncoding_PAYLOAD_ENCODING_TRUNCATED_RAW_BYTES
	}
	event := &flowv1.DeadLetterEvent{
		DeadLetterId:  deadLetterID,
		SchemaVersion: domain.RawSchemaVersion,
		Stage:         flowv1.IngestionStage_INGESTION_STAGE_PARSER,
		Source:        source,
		FailedAt:      timestamppb.New(c.now().UTC()),
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
		return fmt.Errorf("%w: validate dead-letter: %v", ErrCollector, err)
	}
	if err := c.publisher.PublishDeadLetter(ctx, event); err != nil {
		return fmt.Errorf("%w: publish dead-letter: %v", ErrCollector, err)
	}
	return nil
}

func (c *Collector) metric(name string, labels map[string]string) {
	if c.metrics == nil {
		return
	}
	base := map[string]string{
		"collector_id": c.cfg.CollectorID,
		"source_type":  string(domain.SourceTypeNetFlowV5),
	}
	for key, value := range labels {
		base[key] = value
	}
	c.metrics.Inc(name, base)
}

func sourceAddr(addr net.Addr) (netip.Addr, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	parsed, ok := netip.AddrFromSlice(udpAddr.IP)
	return parsed.Unmap(), ok
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
