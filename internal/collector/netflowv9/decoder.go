package netflowv9

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	netFlowV9HeaderBytes = 20
	modularHalfRange     = uint32(1 << 31)
)

type Decoder struct {
	mu           sync.Mutex
	cfg          Config
	exporters    map[ExporterKey]*exporterState
	pendingBytes int
	stats        StateStats
	now          func() time.Time
	metrics      *Metrics
}

func (d *Decoder) WithMetrics(m *Metrics) *Decoder {
	d.mu.Lock()
	d.metrics = m
	d.mu.Unlock()
	return d
}

type framedFlowSet struct {
	id      uint16
	index   uint32
	payload []byte
}

func NewDecoder(cfg Config) (*Decoder, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Decoder{
		cfg:       cfg,
		exporters: map[ExporterKey]*exporterState{},
		now:       time.Now,
	}, nil
}

func (d *Decoder) Decode(ctx context.Context, packetContext PacketContext, data []byte) (Packet, error) {
	if err := ctx.Err(); err != nil {
		return Packet{}, fmt.Errorf("decode netflow v9 packet: %w", err)
	}
	if err := validatePacketContext(packetContext); err != nil {
		return Packet{}, err
	}
	if len(data) < netFlowV9HeaderBytes {
		return Packet{}, decodeError("malformed_packet", "packet is shorter than the 20-byte header")
	}
	if len(data) > d.cfg.MaxPacketBytes {
		return Packet{}, decodeError("packet_limit", "packet size %d exceeds limit %d", len(data), d.cfg.MaxPacketBytes)
	}
	header := decodeHeader(data[:netFlowV9HeaderBytes])
	if header.Version != 9 {
		return Packet{}, decodeError("unsupported_version", "packet version is %d", header.Version)
	}
	flowSets, err := frameFlowSets(data[netFlowV9HeaderBytes:])
	if err != nil {
		return Packet{}, err
	}

	now := packetContext.ReceivedAt.UTC()
	if now.IsZero() {
		now = d.now().UTC()
	}
	key := ExporterKey{
		CollectorID: strings.TrimSpace(packetContext.CollectorID),
		SourceHost:  strings.TrimSpace(packetContext.SourceHost),
		SourceIP:    packetContext.SourceIP.Unmap(),
		SourceID:    header.SourceID,
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	result := Packet{
		Header:           header,
		FlowSets:         make([]FlowSet, 0, len(flowSets)),
		ReplayedFlowSets: []FlowSet{},
		EvictedPending:   d.cleanupLocked(now),
	}
	exporter, evicted := d.getOrCreateExporterLocked(key, now)
	result.EvictedPending = append(result.EvictedPending, evicted...)
	if d.detectRestartLocked(exporter, header) {
		result.ExporterRestart = true
		d.stats.ExporterRestarts++
		if d.metrics != nil {
			d.metrics.ExporterRestart()
		}
		result.EvictedPending = append(result.EvictedPending, d.removeExporterLocked(key, "exporter_restart")...)
		exporter, evicted = d.getOrCreateExporterLocked(key, now)
		result.EvictedPending = append(result.EvictedPending, evicted...)
	} else if exporter.hasLastHeader && header.SequenceNumber != exporter.lastHeader.SequenceNumber+1 {
		result.SequenceGap = true
		d.stats.SequenceGaps++
		if d.metrics != nil {
			d.metrics.SequenceGap()
		}
	}

	parsedRecordCount := 0
	hasPending := false
	for _, framed := range flowSets {
		flowSet, recordCount, pending, replayed, dropped, nonZeroPadding, err := d.decodeFlowSetLocked(
			exporter,
			packetContext,
			header,
			framed,
			now,
		)
		if err != nil {
			return Packet{}, err
		}
		result.FlowSets = append(result.FlowSets, flowSet)
		result.ReplayedFlowSets = append(result.ReplayedFlowSets, replayed...)
		result.EvictedPending = append(result.EvictedPending, dropped...)
		parsedRecordCount += recordCount
		hasPending = hasPending || pending
		if nonZeroPadding {
			result.NonZeroPaddingFlowSets++
			if d.metrics != nil {
				d.metrics.NonZeroPadding()
			}
		}
	}
	if parsedRecordCount > int(header.Count) {
		return Packet{}, decodeError("invalid_record_count", "decoded record count %d exceeds header count %d", parsedRecordCount, header.Count)
	}
	if !hasPending && parsedRecordCount != int(header.Count) {
		return Packet{}, decodeError("invalid_record_count", "decoded record count %d does not match header count %d", parsedRecordCount, header.Count)
	}
	if hasPending && parsedRecordCount >= int(header.Count) {
		return Packet{}, decodeError("invalid_record_count", "missing-template flowsets cannot fit header count %d", header.Count)
	}

	exporter.lastHeader = header
	exporter.hasLastHeader = true
	exporter.lastSeen = now
	return result, nil
}

func (d *Decoder) decodeFlowSetLocked(
	exporter *exporterState,
	packetContext PacketContext,
	header Header,
	framed framedFlowSet,
	now time.Time,
) (FlowSet, int, bool, []FlowSet, []PendingFlowSet, bool, error) {
	switch framed.id {
	case 0:
		templates, padding, nonZeroPadding, err := decodeTemplateFlowSet(framed.payload, d.cfg.MaxFieldsPerTemplate)
		if err != nil {
			return FlowSet{}, 0, false, nil, nil, false, err
		}
		replayed := []FlowSet{}
		dropped := []PendingFlowSet{}
		for _, template := range templates {
			entry, _, capacityDropped, err := d.installTemplateLocked(exporter, TemplateKindData, template, now)
			if err != nil {
				return FlowSet{}, 0, false, nil, nil, false, err
			}
			dropped = append(dropped, capacityDropped...)
			decoded, replayDropped := d.replayPendingLocked(exporter, entry, now)
			replayed = append(replayed, decoded...)
			dropped = append(dropped, replayDropped...)
		}
		return FlowSet{ID: framed.id, Index: framed.index, PaddingBytes: padding}, len(templates), false, replayed, dropped, nonZeroPadding, nil
	case 1:
		templates, padding, nonZeroPadding, err := decodeOptionsTemplateFlowSet(framed.payload, d.cfg.MaxFieldsPerTemplate)
		if err != nil {
			return FlowSet{}, 0, false, nil, nil, false, err
		}
		replayed := []FlowSet{}
		dropped := []PendingFlowSet{}
		for _, template := range templates {
			entry, _, capacityDropped, err := d.installTemplateLocked(exporter, TemplateKindOptions, template, now)
			if err != nil {
				return FlowSet{}, 0, false, nil, nil, false, err
			}
			dropped = append(dropped, capacityDropped...)
			decoded, replayDropped := d.replayPendingLocked(exporter, entry, now)
			replayed = append(replayed, decoded...)
			dropped = append(dropped, replayDropped...)
		}
		return FlowSet{ID: framed.id, Index: framed.index, PaddingBytes: padding}, len(templates), false, replayed, dropped, nonZeroPadding, nil
	default:
		entry, expiredKind, expiredSignature := d.lookupTemplateLocked(exporter, framed.id, now)
		if entry == nil {
			dropped, err := d.addPendingLocked(
				exporter,
				packetContext,
				header,
				framed.id,
				framed.index,
				framed.payload,
				now,
				expiredKind,
				expiredSignature,
			)
			if err != nil {
				return FlowSet{}, 0, false, nil, nil, false, err
			}
			return FlowSet{ID: framed.id, Index: framed.index, TemplateID: framed.id, Pending: true}, 0, true, nil, dropped, false, nil
		}
		flowSet, count, nonZeroPadding, err := d.decodeKnownFlowSetLocked(exporter, entry, framed.payload, framed.index)
		return flowSet, count, false, nil, nil, nonZeroPadding, err
	}
}

func (d *Decoder) decodeKnownFlowSetLocked(
	exporter *exporterState,
	entry *templateEntry,
	payload []byte,
	flowSetIndex uint32,
) (FlowSet, int, bool, error) {
	if entry.recordWidth <= 0 || entry.recordWidth > d.cfg.MaxRecordBytes {
		return FlowSet{}, 0, false, decodeError("record_limit", "template %d record width is invalid", entry.id)
	}
	recordCount := len(payload) / entry.recordWidth
	padding := len(payload) % entry.recordWidth
	if recordCount == 0 || padding > 3 {
		return FlowSet{}, 0, false, decodeError("invalid_flowset_length", "flowset %d does not contain whole records with bounded padding", entry.id)
	}
	paddingData := payload[len(payload)-padding:]
	flowSet := FlowSet{
		ID:             entry.id,
		Index:          flowSetIndex,
		TemplateID:     entry.id,
		Records:        []Record{},
		OptionsRecords: []OptionsRecord{},
		PaddingBytes:   padding,
	}
	for index := range recordCount {
		start := index * entry.recordWidth
		recordData := payload[start : start+entry.recordWidth]
		if entry.kind == TemplateKindData {
			fields, err := decodeDataFields(entry.fields, recordData, false)
			if err != nil {
				return FlowSet{}, 0, false, err
			}
			flowSet.Records = append(flowSet.Records, Record{
				TemplateID: entry.id,
				Index:      uint32(index),
				Fields:     fields,
			})
			continue
		}
		scopeWidth, err := recordWidth(entry.scopes, d.cfg.MaxRecordBytes)
		if err != nil {
			return FlowSet{}, 0, false, err
		}
		scopes, err := decodeDataFields(entry.scopes, recordData[:scopeWidth], true)
		if err != nil {
			return FlowSet{}, 0, false, err
		}
		options, err := decodeDataFields(entry.options, recordData[scopeWidth:], false)
		if err != nil {
			return FlowSet{}, 0, false, err
		}
		optionsRecord := OptionsRecord{
			TemplateID: entry.id,
			Index:      uint32(index),
			Scopes:     scopes,
			Options:    options,
		}
		flowSet.OptionsRecords = append(flowSet.OptionsRecords, optionsRecord)
		d.updateSamplingLocked(exporter, optionsRecord)
	}
	return flowSet, recordCount, hasNonZeroByte(paddingData), nil
}

func (d *Decoder) replayPendingLocked(
	exporter *exporterState,
	entry *templateEntry,
	now time.Time,
) ([]FlowSet, []PendingFlowSet) {
	pending, dropped := d.pendingForTemplateLocked(exporter, entry, now)
	replayed := make([]FlowSet, 0, len(pending))
	for _, item := range pending {
		flowSet, _, _, err := d.decodeKnownFlowSetLocked(exporter, entry, item.data, item.flowSetIndex)
		if err != nil {
			dropped = append(dropped, item.public("replay_failed"))
			continue
		}
		if d.metrics != nil {
			d.metrics.MissingTemplate("replayed")
		}
		replayed = append(replayed, flowSet)
	}
	return replayed, dropped
}

func (d *Decoder) Cleanup(now time.Time) []PendingFlowSet {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cleanupLocked(now.UTC())
}

func (d *Decoder) RunCleanup(ctx context.Context) error {
	ticker := time.NewTicker(d.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-ticker.C:
			d.Cleanup(now)
		}
	}
}

func (d *Decoder) Stats() StateStats {
	d.mu.Lock()
	defer d.mu.Unlock()

	stats := d.stats
	stats.Exporters = len(d.exporters)
	stats.PendingBytes = d.pendingBytes
	for _, exporter := range d.exporters {
		stats.PendingFlowSets += len(exporter.pending)
		for key := range exporter.templates {
			switch key.kind {
			case TemplateKindData:
				stats.DataTemplates++
			case TemplateKindOptions:
				stats.OptionsTemplates++
			case TemplateKindUnknown:
				// Unknown is never stored; retain an exhaustive defensive switch.
			}
		}
	}
	return stats
}

func decodeHeader(data []byte) Header {
	return Header{
		Version:        binary.BigEndian.Uint16(data[0:2]),
		Count:          binary.BigEndian.Uint16(data[2:4]),
		SystemUptime:   binary.BigEndian.Uint32(data[4:8]),
		UnixSeconds:    binary.BigEndian.Uint32(data[8:12]),
		SequenceNumber: binary.BigEndian.Uint32(data[12:16]),
		SourceID:       binary.BigEndian.Uint32(data[16:20]),
	}
}

func frameFlowSets(data []byte) ([]framedFlowSet, error) {
	flowSets := []framedFlowSet{}
	var flowSetIndex uint32
	for offset := 0; offset < len(data); {
		if len(data)-offset < 4 {
			return nil, decodeError("invalid_flowset_boundary", "trailing flowset header is truncated")
		}
		flowSetID := binary.BigEndian.Uint16(data[offset : offset+2])
		flowSetLength := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if flowSetLength < 4 || flowSetLength > len(data)-offset {
			return nil, decodeError("invalid_flowset_boundary", "flowset %d length %d exceeds packet boundary", flowSetID, flowSetLength)
		}
		if flowSetID >= 2 && flowSetID < 256 {
			return nil, decodeError("invalid_flowset_id", "flowset id %d is reserved", flowSetID)
		}
		flowSets = append(flowSets, framedFlowSet{
			id:      flowSetID,
			index:   flowSetIndex,
			payload: data[offset+4 : offset+flowSetLength],
		})
		flowSetIndex++
		offset += flowSetLength
	}
	return flowSets, nil
}

func validatePacketContext(packetContext PacketContext) error {
	if strings.TrimSpace(packetContext.CollectorID) == "" {
		return decodeError("invalid_context", "collector id is required")
	}
	if strings.TrimSpace(packetContext.SourceHost) == "" {
		return decodeError("invalid_context", "source host is required")
	}
	if !packetContext.SourceIP.IsValid() {
		return decodeError("invalid_context", "source ip is required")
	}
	return nil
}

func (d *Decoder) detectRestartLocked(exporter *exporterState, header Header) bool {
	if !exporter.hasLastHeader {
		return false
	}
	previous := exporter.lastHeader
	uptimeRegression := modularRegression(previous.SystemUptime, header.SystemUptime)
	sequenceRegression := modularRegression(previous.SequenceNumber, header.SequenceNumber)
	exportTimeForward := !modularRegression(previous.UnixSeconds, header.UnixSeconds)
	return uptimeRegression && sequenceRegression && exportTimeForward
}

func modularRegression(previous uint32, current uint32) bool {
	if current >= previous {
		return false
	}
	forwardDelta := current - previous
	return forwardDelta >= modularHalfRange
}
