package netflowv9

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adnope/quiver/internal/collector"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/kafka"
)

var ErrCollector = errors.New("netflow v9: collector failed")

type packetJob struct {
	ctx      context.Context
	input    collector.PacketInput
	sourceID uint32
	resultCh chan collector.PacketResult
}

type worker struct {
	jobCh chan packetJob
}

type Collector struct {
	id                 string
	settings           CollectorSettings
	deadLetterMaxBytes int
	publisher          kafka.RawEventPublisher
	metrics            *Metrics
	logger             *slog.Logger
	now                func() time.Time
	decoder            *Decoder

	workers       []worker
	startOnce     sync.Once
	wg            sync.WaitGroup
	closing       atomic.Bool
	closedCh      chan struct{}
	queuedPackets atomic.Int64
	queuedBytes   atomic.Int64
}

func NewCollector(id string, settings CollectorSettings, ctx collector.BuildContext) (*Collector, error) {
	if ctx.Publisher == nil {
		return nil, fmt.Errorf("%w: publisher is nil", ErrCollector)
	}
	workerCount := settings.WorkerCount
	if workerCount == 0 {
		procs := runtime.GOMAXPROCS(0)
		procs = max(1, procs)
		procs = min(8, procs)
		workerCount = procs
	}
	deadLetterMaxBytes := ctx.DeadLetterMaxBytes
	if deadLetterMaxBytes <= 0 || deadLetterMaxBytes > 1500 {
		deadLetterMaxBytes = 1500
	}
	if ctx.Logger == nil {
		ctx.Logger = slog.Default()
	}

	metrics := NewMetrics(id, ctx.Metrics, ctx.Logger)
	decoderConfig := Config{
		TemplateTTL:             settings.TemplateTTL,
		ExporterIdleTimeout:     settings.ExporterIdleTimeout,
		CleanupInterval:         settings.CleanupInterval,
		MaxExporters:            settings.MaxExporters,
		MaxTemplatesPerExporter: settings.MaxTemplatesPerExporter,
		MaxTemplatesTotal:       settings.MaxTemplatesTotal,
		MaxFieldsPerTemplate:    settings.MaxFieldsPerTemplate,
		MaxRecordBytes:          settings.MaxRecordBytes,
		MaxPacketBytes:          settings.MaxPacketBytes,
		PendingMaxWait:          settings.Pending.MaxWait,
		PendingBytesPerExporter: settings.Pending.MaxBytesPerExporter,
		PendingBytesTotal:       settings.Pending.MaxBytesTotal,
	}
	decoder, err := NewDecoder(decoderConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: create decoder: %w", ErrCollector, err)
	}
	decoder.WithMetrics(metrics)

	workers := make([]worker, workerCount)
	for i := range workers {
		workers[i].jobCh = make(chan packetJob, settings.QueueCapacity)
	}

	return &Collector{
		id:                 id,
		settings:           settings,
		deadLetterMaxBytes: deadLetterMaxBytes,
		publisher:          ctx.Publisher,
		metrics:            metrics,
		logger:             ctx.Logger,
		now:                time.Now,
		decoder:            decoder,
		workers:            workers,
		closedCh:           make(chan struct{}),
	}, nil
}

func (c *Collector) ID() string { return c.id }

func (c *Collector) Type() string { return PluginType }

func (c *Collector) SourceType() flowv1.SourceType { return flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9 }

func (c *Collector) Open(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("open netflow v9 collector: %w", err)
	}
	return nil
}

func (c *Collector) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("run netflow v9 collector: %w", err)
	}

	c.startOnce.Do(func() {
		for i := range c.workers {
			c.wg.Add(1)
			go c.workerLoop(&c.workers[i])
		}
	})

	ticker := time.NewTicker(c.settings.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = c.Close(context.WithoutCancel(ctx))
			return ctx.Err()
		case <-ticker.C:
			evicted := c.decoder.Cleanup(c.now())
			c.processEvicted(ctx, evicted)
			if c.metrics != nil {
				c.metrics.UpdateGauges(c.decoder.Stats())
			}
		}
	}
}

func (c *Collector) Close(ctx context.Context) error {
	if !c.closing.CompareAndSwap(false, true) {
		return nil
	}
	for _, w := range c.workers {
		close(w.jobCh)
	}
	doneCh := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		close(c.closedCh)
		return nil
	case <-ctx.Done():
		close(c.closedCh)
		return ctx.Err()
	}
}

func (c *Collector) Health(ctx context.Context) collector.CollectorHealth {
	stats := c.decoder.Stats()
	details := c.metrics.HealthDetails(len(c.workers), int(c.queuedPackets.Load()), int(c.queuedBytes.Load()), stats)
	return collector.CollectorHealth{Details: details}
}

func hashStream(sourceHost string, sourceIP netip.Addr, sourceID uint32) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(sourceHost))
	_, _ = h.Write([]byte(sourceIP.String()))
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], sourceID)
	_, _ = h.Write(buf[:])
	return h.Sum64()
}

func (c *Collector) HandlePacket(ctx context.Context, input collector.PacketInput) (collector.PacketResult, error) {
	if err := ctx.Err(); err != nil {
		return collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "context_done"}, fmt.Errorf("handle netflow v9 packet: %w", err)
	}
	if c.closing.Load() {
		return collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "collector_closed"}, nil
	}
	if len(input.Data) > c.settings.MaxPacketBytes {
		if c.metrics != nil {
			c.metrics.DroppedPacket(input.SourceHost, "packet_too_large")
			c.metrics.RecordError(fmt.Errorf("%w: packet size %d exceeds limit %d", ErrCollector, len(input.Data), c.settings.MaxPacketBytes))
		}
		pktContext := PacketContext{
			CollectorID:     c.id,
			SourceHost:      input.SourceHost,
			SourceIP:        input.SourceIP,
			ReceivedAt:      input.ReceivedAt,
			ProxyReceivedAt: input.ProxyReceivedAt,
		}
		_ = publishDLQEvent(ctx, c.publisher, pktContext, input.Data, "packet_too_large", "packet size exceeds limit", c.deadLetterMaxBytes, c.now())
		return collector.PacketResult{Status: collector.PacketRejected, ErrorCode: "packet_too_large"}, nil
	}
	if len(input.Data) < 20 {
		if c.metrics != nil {
			c.metrics.DroppedPacket(input.SourceHost, "malformed_packet")
			c.metrics.RecordError(fmt.Errorf("%w: packet size %d is too small for header", ErrCollector, len(input.Data)))
		}
		pktContext := PacketContext{
			CollectorID:     c.id,
			SourceHost:      input.SourceHost,
			SourceIP:        input.SourceIP,
			ReceivedAt:      input.ReceivedAt,
			ProxyReceivedAt: input.ProxyReceivedAt,
		}
		_ = publishDLQEvent(ctx, c.publisher, pktContext, input.Data, "malformed_packet", "packet too small for header", c.deadLetterMaxBytes, c.now())
		return collector.PacketResult{Status: collector.PacketRejected, ErrorCode: "malformed_packet"}, nil
	}

	if c.queuedPackets.Add(1) > int64(c.settings.QueueCapacity) {
		c.queuedPackets.Add(-1)
		if c.metrics != nil {
			c.metrics.DroppedPacket(input.SourceHost, "queue_full")
			c.metrics.RecordError(fmt.Errorf("%w: queue capacity exceeded", ErrCollector))
		}
		return collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "queue_full"}, nil
	}
	if c.queuedBytes.Add(int64(len(input.Data))) > int64(c.settings.MaxQueueBytes) {
		c.queuedPackets.Add(-1)
		c.queuedBytes.Add(-int64(len(input.Data)))
		if c.metrics != nil {
			c.metrics.DroppedPacket(input.SourceHost, "queue_bytes_full")
			c.metrics.RecordError(fmt.Errorf("%w: queue bytes capacity exceeded", ErrCollector))
		}
		return collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "queue_full"}, nil
	}

	sourceID := binary.BigEndian.Uint32(input.Data[16:20])
	workerIndex := hashStream(input.SourceHost, input.SourceIP, sourceID) % uint64(len(c.workers))
	job := packetJob{
		ctx:      ctx,
		input:    input,
		sourceID: sourceID,
		resultCh: make(chan collector.PacketResult, 1),
	}

	select {
	case c.workers[workerIndex].jobCh <- job:
	case <-ctx.Done():
		c.queuedPackets.Add(-1)
		c.queuedBytes.Add(-int64(len(input.Data)))
		return collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "timeout"}, ctx.Err()
	case <-c.closedCh:
		c.queuedPackets.Add(-1)
		c.queuedBytes.Add(-int64(len(input.Data)))
		return collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "collector_closed"}, nil
	}

	select {
	case res := <-job.resultCh:
		return res, nil
	case <-ctx.Done():
		return collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "timeout"}, ctx.Err()
	case <-c.closedCh:
		return collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "collector_closed"}, nil
	}
}

func (c *Collector) workerLoop(w *worker) {
	defer c.wg.Done()
	for job := range w.jobCh {
		res := c.processPacketJob(job)
		c.queuedPackets.Add(-1)
		c.queuedBytes.Add(-int64(len(job.input.Data)))
		job.resultCh <- res
	}
}

func (c *Collector) processPacketJob(job packetJob) collector.PacketResult {
	if job.input.SourceHost == "" {
		if c.metrics != nil {
			c.metrics.DroppedPacket("unknown", "auth_required")
		}
		return collector.PacketResult{Status: collector.PacketRejected, ErrorCode: "auth_required"}
	}
	if c.metrics != nil {
		c.metrics.PacketReceived(job.input.SourceHost)
	}

	pktContext := PacketContext{
		CollectorID:     c.id,
		SourceHost:      job.input.SourceHost,
		SourceIP:        job.input.SourceIP,
		ReceivedAt:      job.input.ReceivedAt,
		ProxyReceivedAt: job.input.ProxyReceivedAt,
	}

	packet, err := c.decoder.Decode(job.ctx, pktContext, job.input.Data)
	if err != nil {
		code := ErrorCode(err)
		if c.metrics != nil {
			c.metrics.ParseError(job.input.SourceHost, code)
			c.metrics.RecordError(err)
		}
		if dlqErr := publishDLQEvent(job.ctx, c.publisher, pktContext, job.input.Data, code, err.Error(), c.deadLetterMaxBytes, c.now()); dlqErr != nil {
			return collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "dlq_unavailable"}
		}
		return collector.PacketResult{Status: collector.PacketRejected, ErrorCode: code}
	}

	c.processEvicted(job.ctx, packet.EvictedPending)

	for _, flowSet := range packet.ReplayedFlowSets {
		_ = c.publishFlowSet(job.ctx, pktContext, packet.Header, flowSet)
	}

	hasPublisherError := false
	for _, flowSet := range packet.FlowSets {
		if err := c.publishFlowSet(job.ctx, pktContext, packet.Header, flowSet); err != nil {
			hasPublisherError = true
		}
	}

	if hasPublisherError {
		return collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "publisher_unavailable"}
	}

	if c.metrics != nil {
		c.metrics.RecordSuccess(c.now())
		c.metrics.UpdateGauges(c.decoder.Stats())
	}
	return collector.PacketResult{Status: collector.PacketAccepted}
}

func (c *Collector) publishFlowSet(ctx context.Context, pktContext PacketContext, header Header, flowSet FlowSet) error {
	for _, record := range flowSet.Records {
		if c.metrics != nil {
			c.metrics.RecordDecoded("ok")
		}

		envelope, err := buildRawEventEnvelope(pktContext, header, flowSet, record, c.now())
		if err != nil {
			if c.metrics != nil {
				c.metrics.DroppedEvent(pktContext.SourceHost, "build_event_failed")
				c.metrics.RecordError(err)
			}
			continue
		}

		if err := c.publisher.PublishRaw(ctx, envelope); err != nil {
			if errors.Is(err, kafka.ErrQueueFull) {
				if c.metrics != nil {
					c.metrics.DroppedEvent(pktContext.SourceHost, "queue_full")
					c.metrics.RecordError(err)
				}
				return err
			}
			if c.metrics != nil {
				c.metrics.RecordError(err)
			}
			return fmt.Errorf("publish raw: %w", err)
		}
		if c.metrics != nil {
			c.metrics.EventPublished(pktContext.SourceHost)
		}
	}
	return nil
}

func (c *Collector) processEvicted(ctx context.Context, evicted []PendingFlowSet) {
	for _, p := range evicted {
		if c.metrics != nil {
			c.metrics.RecordError(fmt.Errorf("%w: %s", ErrCollector, p.Reason))
		}
		pktContext := PacketContext{
			CollectorID:     c.id,
			SourceHost:      p.Exporter.SourceHost,
			SourceIP:        p.Exporter.SourceIP,
			ReceivedAt:      p.ReceivedAt,
			ProxyReceivedAt: p.ProxyReceivedAt,
		}
		_ = publishDLQEvent(ctx, c.publisher, pktContext, p.Data, p.Reason, "pending flowset evicted: "+p.Reason, c.deadLetterMaxBytes, c.now())
	}
}
