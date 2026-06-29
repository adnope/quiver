package netflowv9

import (
	"log/slog"
	"maps"
	"strconv"
	"sync"
	"time"

	"github.com/adnope/quiver/internal/observability"
)

type Metrics struct {
	collectorID string
	registry    *observability.Registry
	logger      *slog.Logger

	mu                 sync.Mutex
	lastSuccessTime    time.Time
	lastSanitizedError string
}

func NewMetrics(collectorID string, registry *observability.Registry, logger *slog.Logger) *Metrics {
	if logger == nil {
		logger = slog.Default()
	}
	return &Metrics{
		collectorID: collectorID,
		registry:    registry,
		logger:      logger,
	}
}

func (m *Metrics) inc(name string, labels map[string]string) {
	if m == nil || m.registry == nil {
		return
	}
	base := map[string]string{
		"collector_id": m.collectorID,
		"source_type":  "netflow_v9",
	}
	maps.Copy(base, labels)
	m.registry.Inc(name, base)
}

func (m *Metrics) set(name string, labels map[string]string, value uint64) {
	if m == nil || m.registry == nil {
		return
	}
	base := map[string]string{
		"collector_id": m.collectorID,
		"source_type":  "netflow_v9",
	}
	maps.Copy(base, labels)
	m.registry.Set(name, base, value)
}

func (m *Metrics) PacketReceived(sourceHost string) {
	m.inc("collector_packets_received_total", map[string]string{"source_host": sourceHost})
}

func (m *Metrics) EventPublished(sourceHost string) {
	m.inc("collector_events_published_total", map[string]string{"source_host": sourceHost})
}

func (m *Metrics) ParseError(sourceHost, errorCode string) {
	m.inc("collector_parse_errors_total", map[string]string{"source_host": sourceHost, "error_code": errorCode})
}

func (m *Metrics) DroppedPacket(sourceHost, reason string) {
	m.inc("collector_dropped_packets_total", map[string]string{"source_host": sourceHost, "reason": reason})
}

func (m *Metrics) DroppedEvent(sourceHost, reason string) {
	m.inc("collector_dropped_events_total", map[string]string{"source_host": sourceHost, "reason": reason})
}

func (m *Metrics) TemplateAction(action string, kind TemplateKind) {
	kindStr := "data"
	if kind == TemplateKindOptions {
		kindStr = "options"
	}
	m.inc("netflow_v9_templates_total", map[string]string{"action": action, "kind": kindStr})
}

func (m *Metrics) MissingTemplate(outcome string) {
	m.inc("netflow_v9_missing_templates_total", map[string]string{"outcome": outcome})
}

func (m *Metrics) RecordDecoded(result string) {
	m.inc("netflow_v9_records_decoded_total", map[string]string{"result": result})
}

func (m *Metrics) SequenceGap() {
	m.inc("netflow_v9_sequence_gaps_total", nil)
}

func (m *Metrics) ExporterRestart() {
	m.inc("netflow_v9_exporter_restarts_total", nil)
}

func (m *Metrics) NonZeroPadding() {
	m.inc("netflow_v9_nonzero_padding_total", nil)
}

func (m *Metrics) CachePressure(reason string) {
	m.inc("netflow_v9_cache_pressure_total", map[string]string{"reason": reason})
}

func (m *Metrics) PendingEviction(reason string) {
	m.inc("netflow_v9_pending_eviction_total", map[string]string{"reason": reason})
}

func (m *Metrics) UpdateGauges(stats StateStats) {
	m.set("netflow_v9_template_cache_entries", map[string]string{"kind": "data"}, uint64(stats.DataTemplates))       // #nosec G115 -- non-negative
	m.set("netflow_v9_template_cache_entries", map[string]string{"kind": "options"}, uint64(stats.OptionsTemplates)) // #nosec G115 -- non-negative
	m.set("netflow_v9_pending_flowsets", map[string]string{"state": "count"}, uint64(stats.PendingFlowSets))         // #nosec G115 -- non-negative
	m.set("netflow_v9_pending_flowsets", map[string]string{"state": "bytes"}, uint64(stats.PendingBytes))            // #nosec G115 -- non-negative
}

func (m *Metrics) RecordSuccess(now time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.lastSuccessTime = now
	m.mu.Unlock()
}

func (m *Metrics) RecordError(err error) {
	if m == nil || err == nil {
		return
	}
	m.mu.Lock()
	m.lastSanitizedError = ErrorCode(err)
	m.mu.Unlock()
}

func (m *Metrics) HealthDetails(workerCount, queueDepth, queueBytes int, stats StateStats) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	m.mu.Lock()
	lastSuccess := m.lastSuccessTime
	lastErr := m.lastSanitizedError
	m.mu.Unlock()

	lastSuccessStr := "never"
	if !lastSuccess.IsZero() {
		lastSuccessStr = lastSuccess.UTC().Format(time.RFC3339)
	}
	if lastErr == "" {
		lastErr = "none"
	}

	return map[string]string{
		"worker_count":           strconv.Itoa(workerCount),
		"queue_depth":            strconv.Itoa(queueDepth),
		"queue_bytes":            strconv.Itoa(queueBytes),
		"exporter_count":         strconv.Itoa(stats.Exporters),
		"data_template_count":    strconv.Itoa(stats.DataTemplates),
		"options_template_count": strconv.Itoa(stats.OptionsTemplates),
		"pending_count":          strconv.Itoa(stats.PendingFlowSets),
		"pending_bytes":          strconv.Itoa(stats.PendingBytes),
		"last_successful_packet": lastSuccessStr,
		"last_sanitized_error":   lastErr,
	}
}
