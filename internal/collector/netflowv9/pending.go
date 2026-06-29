package netflowv9

import (
	"bytes"
	"time"
)

type pendingEntry struct {
	exporter          ExporterKey
	header            Header
	flowSetID         uint16
	flowSetIndex      uint32
	data              []byte
	receivedAt        time.Time
	proxyReceivedAt   *time.Time
	expiresAt         time.Time
	expectedKind      TemplateKind
	expectedSignature string
}

func (p *pendingEntry) public(reason string) PendingFlowSet {
	return PendingFlowSet{
		Exporter:        p.exporter,
		Header:          p.header,
		FlowSetID:       p.flowSetID,
		FlowSetIndex:    p.flowSetIndex,
		Data:            bytes.Clone(p.data),
		ReceivedAt:      p.receivedAt,
		ProxyReceivedAt: cloneTimePointer(p.proxyReceivedAt),
		ExpiresAt:       p.expiresAt,
		Reason:          reason,
		ExpectedKind:    p.expectedKind,
	}
}

func (d *Decoder) addPendingLocked(
	exporter *exporterState,
	packetContext PacketContext,
	header Header,
	flowSetID uint16,
	flowSetIndex uint32,
	payload []byte,
	now time.Time,
	expectedKind TemplateKind,
	expectedSignature string,
) ([]PendingFlowSet, error) {
	if len(payload) > d.cfg.PendingBytesPerExporter || len(payload) > d.cfg.PendingBytesTotal {
		return nil, decodeError("pending_limit", "flowset size %d exceeds pending byte limits", len(payload))
	}
	entry := &pendingEntry{
		exporter:          exporter.key,
		header:            header,
		flowSetID:         flowSetID,
		flowSetIndex:      flowSetIndex,
		data:              bytes.Clone(payload),
		receivedAt:        now,
		proxyReceivedAt:   cloneTimePointer(packetContext.ProxyReceivedAt),
		expiresAt:         now.Add(d.cfg.PendingMaxWait),
		expectedKind:      expectedKind,
		expectedSignature: expectedSignature,
	}
	exporter.pending = append(exporter.pending, entry)
	exporter.pendingBytes += len(entry.data)
	d.pendingBytes += len(entry.data)

	if d.metrics != nil {
		d.metrics.MissingTemplate("buffered")
	}
	evicted := []PendingFlowSet{}
	for exporter.pendingBytes > d.cfg.PendingBytesPerExporter && len(exporter.pending) > 0 {
		evicted = append(evicted, d.removePendingLocked(exporter, 0, "pending_evicted"))
		if d.metrics != nil {
			d.metrics.MissingTemplate("evicted")
			d.metrics.PendingEviction("per_exporter_limit")
		}
	}
	for d.pendingBytes > d.cfg.PendingBytesTotal {
		oldestExporter, oldestIndex, found := d.oldestPendingLocked()
		if !found {
			break
		}
		evicted = append(evicted, d.removePendingLocked(oldestExporter, oldestIndex, "pending_evicted"))
		if d.metrics != nil {
			d.metrics.MissingTemplate("evicted")
			d.metrics.PendingEviction("global_limit")
		}
	}
	return evicted, nil
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func (d *Decoder) expirePendingLocked(exporter *exporterState, now time.Time) []PendingFlowSet {
	evicted := []PendingFlowSet{}
	for index := 0; index < len(exporter.pending); {
		if now.Before(exporter.pending[index].expiresAt) {
			index++
			continue
		}
		evicted = append(evicted, d.removePendingLocked(exporter, index, "pending_expired"))
		if d.metrics != nil {
			d.metrics.MissingTemplate("expired")
		}
	}
	return evicted
}

func (d *Decoder) pendingForTemplateLocked(
	exporter *exporterState,
	entry *templateEntry,
	now time.Time,
) ([]*pendingEntry, []PendingFlowSet) {
	replay := []*pendingEntry{}
	dropped := d.expirePendingLocked(exporter, now)
	for index := 0; index < len(exporter.pending); {
		pending := exporter.pending[index]
		if pending.flowSetID != entry.id {
			index++
			continue
		}
		if pending.expectedKind != TemplateKindUnknown && pending.expectedKind != entry.kind {
			index++
			continue
		}
		if pending.expectedSignature != "" && pending.expectedSignature != entry.signature {
			dropped = append(dropped, d.removePendingLocked(exporter, index, "template_redefined"))
			continue
		}
		replay = append(replay, pending)
		d.removePendingWithoutResultLocked(exporter, index)
	}
	return replay, dropped
}

func (d *Decoder) dropIncompatiblePendingLocked(
	exporter *exporterState,
	templateID uint16,
	kind TemplateKind,
	signature string,
) []PendingFlowSet {
	dropped := []PendingFlowSet{}
	for index := 0; index < len(exporter.pending); {
		pending := exporter.pending[index]
		matchesTemplate := pending.flowSetID == templateID
		matchesKind := pending.expectedKind == TemplateKindUnknown || pending.expectedKind == kind
		isIncompatible := pending.expectedSignature != "" && pending.expectedSignature != signature
		if matchesTemplate && matchesKind && isIncompatible {
			dropped = append(dropped, d.removePendingLocked(exporter, index, "template_redefined"))
			continue
		}
		index++
	}
	return dropped
}

func (d *Decoder) removePendingLocked(exporter *exporterState, index int, reason string) PendingFlowSet {
	entry := exporter.pending[index]
	result := entry.public(reason)
	d.removePendingWithoutResultLocked(exporter, index)
	return result
}

func (d *Decoder) removePendingWithoutResultLocked(exporter *exporterState, index int) {
	entry := exporter.pending[index]
	exporter.pendingBytes -= len(entry.data)
	d.pendingBytes -= len(entry.data)
	copy(exporter.pending[index:], exporter.pending[index+1:])
	exporter.pending[len(exporter.pending)-1] = nil
	exporter.pending = exporter.pending[:len(exporter.pending)-1]
}

func (d *Decoder) oldestPendingLocked() (*exporterState, int, bool) {
	var oldestExporter *exporterState
	oldestIndex := 0
	var oldestTime time.Time
	found := false
	for _, exporter := range d.exporters {
		for index, pending := range exporter.pending {
			if !found || pending.receivedAt.Before(oldestTime) {
				oldestExporter = exporter
				oldestIndex = index
				oldestTime = pending.receivedAt
				found = true
			}
		}
	}
	return oldestExporter, oldestIndex, found
}
