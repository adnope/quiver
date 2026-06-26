package zeekconntcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/timestamppb"

	quiverauth "github.com/adnope/quiver/internal/auth"
	"github.com/adnope/quiver/internal/collector"
	"github.com/adnope/quiver/internal/collector/zeek"
	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
	"github.com/adnope/quiver/internal/observability"
	"github.com/adnope/quiver/internal/validation"
)

var (
	ErrCollector   = errors.New("zeek_conn_tcp: collector failed")
	errLineTooLong = errors.New("zeek_conn_tcp: line exceeds max_line_bytes")
)

type CollectorConfig struct {
	CollectorID        string
	Settings           settings
	AllowedPeerCIDRs   []netip.Prefix
	DeadLetterMaxBytes int
}

type Collector struct {
	cfg           CollectorConfig
	publisher     kafka.RawEventPublisher
	authenticator quiverauth.APIKeyAuthenticator
	metrics       *observability.Registry
	logger        *slog.Logger
	now           func() time.Time

	listenerMu sync.Mutex
	listener   net.Listener

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	sourceLocksMu sync.Mutex
	sourceLocks   map[string]*sync.Mutex

	acceptSem chan struct{}
	closed    atomic.Bool

	activeConnections atomic.Int64
	acceptedRecords   atomic.Uint64
	parseErrors       atomic.Uint64
}

func NewCollector(
	cfg CollectorConfig,
	publisher kafka.RawEventPublisher,
	authenticator quiverauth.APIKeyAuthenticator,
	metrics *observability.Registry,
	logger *slog.Logger,
) (*Collector, error) {
	if strings.TrimSpace(cfg.CollectorID) == "" {
		return nil, fmt.Errorf("%w: collector_id is required", ErrCollector)
	}
	if publisher == nil {
		return nil, fmt.Errorf("%w: publisher is nil", ErrCollector)
	}
	if authenticator == nil {
		return nil, fmt.Errorf("%w: authenticator is nil", ErrCollector)
	}
	if cfg.DeadLetterMaxBytes <= 0 {
		cfg.DeadLetterMaxBytes = 1500
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{
		cfg:           cfg,
		publisher:     publisher,
		authenticator: authenticator,
		metrics:       metrics,
		logger:        logger,
		now:           time.Now,
		conns:         map[net.Conn]struct{}{},
		sourceLocks:   map[string]*sync.Mutex{},
		acceptSem:     make(chan struct{}, cfg.Settings.MaxConnections),
	}, nil
}

func (c *Collector) ID() string { return c.cfg.CollectorID }

func (c *Collector) Type() string { return PluginType }

func (c *Collector) SourceType() flowv1.SourceType {
	return flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON
}

func (c *Collector) Open(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("open zeek_conn_tcp collector: %w", err)
	}
	c.listenerMu.Lock()
	defer c.listenerMu.Unlock()
	if c.listener != nil {
		return nil
	}
	var listener net.Listener
	listenConfig := net.ListenConfig{}
	tcpListener, err := listenConfig.Listen(ctx, "tcp", c.cfg.Settings.ListenAddr)
	if err != nil {
		return fmt.Errorf("%w: listen tcp: %w", ErrCollector, err)
	}
	listener = tcpListener
	if c.cfg.Settings.TLS.Enabled {
		cert, certErr := tls.LoadX509KeyPair(c.cfg.Settings.TLS.CertFile, c.cfg.Settings.TLS.KeyFile)
		if certErr != nil {
			_ = tcpListener.Close()
			return fmt.Errorf("%w: load tls keypair: %w", ErrCollector, certErr)
		}
		listener = tls.NewListener(tcpListener, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		})
	}
	c.listener = listener
	c.closed.Store(false)
	return nil
}

func (c *Collector) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("run zeek_conn_tcp collector: %w", err)
	}
	c.listenerMu.Lock()
	listener := c.listener
	c.listenerMu.Unlock()
	if listener == nil {
		if err := c.Open(ctx); err != nil {
			return err
		}
		c.listenerMu.Lock()
		listener = c.listener
		c.listenerMu.Unlock()
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if c.closed.Load() || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return fmt.Errorf("%w: accept tcp: %w", ErrCollector, err)
		}
		if !c.allowedPeer(conn.RemoteAddr()) {
			c.metric("collector_connection_rejections_total", map[string]string{"reason": "peer_not_allowed", "source_host": "unknown"})
			_ = conn.Close()
			continue
		}
		select {
		case c.acceptSem <- struct{}{}:
		default:
			c.metric("collector_connection_rejections_total", map[string]string{"reason": "max_connections", "source_host": "unknown"})
			_ = conn.Close()
			continue
		}
		c.registerConn(conn)
		go c.handleConn(ctx, conn)
	}
}

func (c *Collector) Close(context.Context) error {
	c.closed.Store(true)
	c.listenerMu.Lock()
	listener := c.listener
	c.listener = nil
	c.listenerMu.Unlock()
	c.connMu.Lock()
	conns := make([]net.Conn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	c.connMu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	if listener == nil {
		return nil
	}
	if err := listener.Close(); err != nil {
		return fmt.Errorf("%w: close tcp listener: %w", ErrCollector, err)
	}
	return nil
}

func (c *Collector) Health(context.Context) collector.CollectorHealth {
	return collector.CollectorHealth{Details: map[string]string{
		"listen_addr":        c.cfg.Settings.ListenAddr,
		"active_connections": fmt.Sprintf("%d", c.activeConnections.Load()),
		"accepted_records":   fmt.Sprintf("%d", c.acceptedRecords.Load()),
		"parse_errors":       fmt.Sprintf("%d", c.parseErrors.Load()),
		"queue_depth":        "unavailable",
	}}
}

func (c *Collector) handleConn(ctx context.Context, conn net.Conn) {
	defer func() {
		c.unregisterConn(conn)
		<-c.acceptSem
		_ = conn.Close()
	}()
	reader := bufio.NewReaderSize(conn, min(c.cfg.Settings.MaxLineBytes, 64*1024))
	remoteIP := remoteAddrIP(conn.RemoteAddr())
	principal, err := c.authenticateConn(ctx, conn, reader)
	if err != nil {
		c.metric("collector_auth_failures_total", map[string]string{"source_host": "unknown"})
		c.logger.WarnContext(ctx, "zeek tcp auth failed", slog.String("collector_id", c.cfg.CollectorID), slog.Any("error", err))
		return
	}
	sourceHost := strings.TrimSpace(principal.SourceHost)
	if sourceHost == "" {
		c.metric("collector_auth_failures_total", map[string]string{"source_host": "unknown"})
		return
	}
	var sourceIP *string
	if c.cfg.Settings.TrustPeerIP && remoteIP.IsValid() {
		sourceIPText := remoteIP.String()
		sourceIP = &sourceIPText
	}
	limiter := newRecordLimiter(c.cfg.Settings.RateLimit)
	batch := make([]*flowv1.RawFlowEventEnvelope, 0, c.cfg.Settings.BatchSize)
	for {
		select {
		case <-ctx.Done():
			_ = c.flushBatch(ctx, sourceHost, batch)
			return
		default:
		}
		line, readErr := c.readLine(conn, reader, len(batch) > 0)
		if readErr != nil {
			if isTimeout(readErr) {
				if len(batch) > 0 {
					if err := c.flushBatch(ctx, sourceHost, batch); err != nil {
						c.logger.WarnContext(ctx, "zeek tcp batch publish failed", slog.String("collector_id", c.cfg.CollectorID), slog.Any("error", err))
						return
					}
					batch = batch[:0]
					continue
				}
				return
			}
			if errors.Is(readErr, errLineTooLong) {
				c.parseErrors.Add(1)
				c.metric("collector_parse_errors_total", map[string]string{"error_code": "line_too_long", "source_host": sourceHost})
				if err := c.publishDLQ(ctx, sourceHost, sourceIP, line, "line_too_long", "zeek conn record exceeds max_line_bytes"); err != nil {
					c.logger.WarnContext(ctx, "zeek tcp oversized-line dlq publish failed", slog.String("collector_id", c.cfg.CollectorID), slog.Any("error", err))
					return
				}
				continue
			}
			if errors.Is(readErr, io.EOF) {
				_ = c.flushBatch(ctx, sourceHost, batch)
				return
			}
			c.parseErrors.Add(1)
			c.metric("collector_parse_errors_total", map[string]string{"error_code": "read_error", "source_host": sourceHost})
			return
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if !limiter.allow() {
			if limiter.dropMode() {
				c.metric("collector_dropped_events_total", map[string]string{"reason": "rate_limited", "source_host": sourceHost})
				continue
			}
			limiter.wait(ctx)
		}
		event, recordErr := c.rawEvent(sourceHost, sourceIP, line)
		if recordErr != nil {
			c.parseErrors.Add(1)
			c.metric("collector_parse_errors_total", map[string]string{"error_code": recordErr.code, "source_host": sourceHost})
			if err := c.publishDLQ(ctx, sourceHost, sourceIP, line, recordErr.code, recordErr.message); err != nil {
				c.logger.WarnContext(ctx, "zeek tcp dlq publish failed", slog.String("collector_id", c.cfg.CollectorID), slog.Any("error", err))
				return
			}
			continue
		}
		batch = append(batch, event)
		if len(batch) >= c.cfg.Settings.BatchSize {
			if err := c.flushBatch(ctx, sourceHost, batch); err != nil {
				c.logger.WarnContext(ctx, "zeek tcp batch publish failed", slog.String("collector_id", c.cfg.CollectorID), slog.Any("error", err))
				return
			}
			batch = batch[:0]
		}
	}
}

func (c *Collector) authenticateConn(ctx context.Context, conn net.Conn, reader *bufio.Reader) (quiverauth.Principal, error) {
	if err := conn.SetReadDeadline(c.now().Add(c.cfg.Settings.AuthTimeout.Std())); err != nil {
		return quiverauth.Principal{}, fmt.Errorf("set auth deadline: %w", err)
	}
	line, err := readBoundedLine(reader, len(quiverauth.APIKeyHeader)+2+4096)
	if err != nil {
		return quiverauth.Principal{}, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return quiverauth.Principal{}, fmt.Errorf("clear auth deadline: %w", err)
	}
	name, value, ok := strings.Cut(strings.TrimRight(string(line), "\r\n"), ":")
	if !ok || strings.TrimSpace(name) != quiverauth.APIKeyHeader {
		return quiverauth.Principal{}, quiverauth.ErrMissingAPIKey
	}
	principal, err := c.authenticator.Authenticate(strings.TrimSpace(value))
	if err != nil {
		return quiverauth.Principal{}, err
	}
	if !principal.HasScope(quiverauth.ScopeIngest) {
		return quiverauth.Principal{}, quiverauth.ErrInsufficientScope
	}
	if strings.TrimSpace(principal.SourceHost) == "" {
		return quiverauth.Principal{}, quiverauth.ErrInsufficientScope
	}
	if err := ctx.Err(); err != nil {
		return quiverauth.Principal{}, err
	}
	return principal, nil
}

type recordError struct {
	code    string
	message string
}

func (c *Collector) rawEvent(sourceHost string, sourceIP *string, line []byte) (*flowv1.RawFlowEventEnvelope, *recordError) {
	if !utf8.Valid(line) {
		return nil, &recordError{code: "invalid_utf8", message: "zeek conn record must be valid utf-8"}
	}
	flow, err := zeek.ParseConnLine(line)
	if err != nil {
		return nil, &recordError{code: "invalid_zeek_conn", message: "invalid zeek conn record"}
	}
	eventID, err := domain.NewUUIDv7(c.now())
	if err != nil {
		return nil, &recordError{code: "id_generation_failed", message: "failed to generate event id"}
	}
	source := &flowv1.SourceIdentity{
		CollectorId: c.cfg.CollectorID,
		SourceType:  flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON,
		SourceHost:  sourceHost,
		SourceIp:    sourceIP,
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
		return nil, &recordError{code: "invalid_record", message: err.Error()}
	}
	return event, nil
}

func (c *Collector) flushBatch(ctx context.Context, sourceHost string, batch []*flowv1.RawFlowEventEnvelope) error {
	if len(batch) == 0 {
		return nil
	}
	lock := c.sourceLock(sourceHost)
	lock.Lock()
	defer lock.Unlock()
	for _, event := range batch {
		if err := c.publisher.PublishRaw(ctx, event); err != nil {
			if errors.Is(err, kafka.ErrQueueFull) {
				c.metric("collector_dropped_events_total", map[string]string{"reason": "queue_full", "source_host": sourceHost})
				return nil
			}
			return fmt.Errorf("%w: publish raw: %w", ErrCollector, err)
		}
		c.acceptedRecords.Add(1)
		c.metric("collector_events_published_total", map[string]string{"source_host": sourceHost})
	}
	return nil
}

func (c *Collector) publishDLQ(ctx context.Context, sourceHost string, sourceIP *string, line []byte, code string, message string) error {
	deadLetterID, err := domain.NewUUIDv7(c.now())
	if err != nil {
		return fmt.Errorf("%w: generate dead-letter id: %w", ErrCollector, err)
	}
	source := &flowv1.SourceIdentity{
		CollectorId: c.cfg.CollectorID,
		SourceType:  flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON,
		SourceHost:  sourceHost,
		SourceIp:    sourceIP,
	}
	payload, truncated := truncatePayload(line, c.cfg.DeadLetterMaxBytes)
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
			Sha256:            sha256Hex(line),
			OriginalSizeBytes: uint64(len(line)),
			Truncated:         truncated,
		},
	}
	if err := validation.ValidateDeadLetterEvent(event); err != nil {
		return fmt.Errorf("%w: validate dead-letter: %w", ErrCollector, err)
	}
	if err := c.publisher.PublishDeadLetter(ctx, event); err != nil {
		return fmt.Errorf("%w: publish dead-letter: %w", ErrCollector, err)
	}
	return nil
}

func (c *Collector) readLine(conn net.Conn, reader *bufio.Reader, flushPending bool) ([]byte, error) {
	deadline := c.now().Add(c.cfg.Settings.IdleTimeout.Std())
	if flushPending {
		deadline = c.now().Add(c.cfg.Settings.FlushInterval.Std())
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set idle deadline: %w", err)
	}
	line, err := readBoundedLine(reader, c.cfg.Settings.MaxLineBytes)
	if err != nil {
		return nil, err
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func readBoundedLine(reader *bufio.Reader, maxBytes int) ([]byte, error) {
	var out []byte
	for {
		part, err := reader.ReadSlice('\n')
		out = append(out, part...)
		if len(out) > maxBytes {
			for errors.Is(err, bufio.ErrBufferFull) {
				part, err = reader.ReadSlice('\n')
				out = append(out, part...)
			}
			return out[:min(len(out), maxBytes)], errLineTooLong
		}
		if err == nil {
			return out, nil
		}
		if errors.Is(err, io.EOF) && len(out) > 0 {
			return out, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

func (c *Collector) registerConn(conn net.Conn) {
	c.connMu.Lock()
	c.conns[conn] = struct{}{}
	c.connMu.Unlock()
	c.activeConnections.Add(1)
	c.metric("collector_connections_total", map[string]string{"source_host": "unknown"})
	if c.metrics != nil {
		c.metrics.Set("collector_active_connections", c.baseLabels(map[string]string{"source_host": "unknown"}), activeConnectionGauge(c.activeConnections.Load()))
	}
}

func (c *Collector) unregisterConn(conn net.Conn) {
	c.connMu.Lock()
	delete(c.conns, conn)
	c.connMu.Unlock()
	c.activeConnections.Add(-1)
	if c.metrics != nil {
		c.metrics.Set("collector_active_connections", c.baseLabels(map[string]string{"source_host": "unknown"}), activeConnectionGauge(c.activeConnections.Load()))
	}
}

func activeConnectionGauge(value int64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func (c *Collector) allowedPeer(addr net.Addr) bool {
	if len(c.cfg.AllowedPeerCIDRs) == 0 {
		return true
	}
	ip := remoteAddrIP(addr)
	if !ip.IsValid() {
		return false
	}
	for _, prefix := range c.cfg.AllowedPeerCIDRs {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *Collector) sourceLock(sourceHost string) *sync.Mutex {
	c.sourceLocksMu.Lock()
	defer c.sourceLocksMu.Unlock()
	lock := c.sourceLocks[sourceHost]
	if lock == nil {
		lock = &sync.Mutex{}
		c.sourceLocks[sourceHost] = lock
	}
	return lock
}

func (c *Collector) metric(name string, labels map[string]string) {
	if c.metrics == nil {
		return
	}
	c.metrics.Inc(name, c.baseLabels(labels))
}

func (c *Collector) baseLabels(labels map[string]string) map[string]string {
	base := map[string]string{
		"collector_id": c.cfg.CollectorID,
		"source_type":  string(domain.SourceTypeZeekConnJSON),
	}
	maps.Copy(base, labels)
	return base
}

func remoteAddrIP(addr net.Addr) netip.Addr {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}
	}
	parsed, ok := netip.AddrFromSlice(tcpAddr.IP)
	if !ok {
		return netip.Addr{}
	}
	return parsed.Unmap()
}

func truncatePayload(payload []byte, maxBytes int) ([]byte, bool) {
	if maxBytes <= 0 || maxBytes > 1500 {
		maxBytes = 1500
	}
	if len(payload) <= maxBytes {
		return append([]byte(nil), payload...), false
	}
	return append([]byte(nil), payload[:maxBytes]...), true
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
