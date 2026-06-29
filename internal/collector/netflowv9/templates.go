package netflowv9

import (
	"slices"
	"time"
)

type templateLookupKey struct {
	kind TemplateKind
	id   uint16
}

type templateEntry struct {
	kind                   TemplateKind
	id                     uint16
	fields                 []FieldDefinition
	scopes                 []FieldDefinition
	options                []FieldDefinition
	recordWidth            int
	signature              string
	generation             uint64
	lastTemplateReceivedAt time.Time
}

type exporterState struct {
	key               ExporterKey
	templates         map[templateLookupKey]*templateEntry
	nextGeneration    map[templateLookupKey]uint64
	expiredSignatures map[templateLookupKey]string
	pending           []*pendingEntry
	pendingBytes      int
	sampling          SamplingState
	lastSeen          time.Time
	lastHeader        Header
	hasLastHeader     bool
}

func newExporterState(key ExporterKey, now time.Time) *exporterState {
	return &exporterState{
		key:               key,
		templates:         map[templateLookupKey]*templateEntry{},
		nextGeneration:    map[templateLookupKey]uint64{},
		expiredSignatures: map[templateLookupKey]string{},
		pending:           []*pendingEntry{},
		sampling:          newSamplingState(),
		lastSeen:          now,
	}
}

func (d *Decoder) getOrCreateExporterLocked(key ExporterKey, now time.Time) (*exporterState, []PendingFlowSet) {
	if exporter, ok := d.exporters[key]; ok {
		exporter.lastSeen = now
		return exporter, []PendingFlowSet{}
	}

	evicted := []PendingFlowSet{}
	if len(d.exporters) >= d.cfg.MaxExporters {
		oldestKey, found := d.oldestExporterLocked()
		if found {
			evicted = append(evicted, d.removeExporterLocked(oldestKey, "exporter_evicted")...)
		}
	}
	exporter := newExporterState(key, now)
	d.exporters[key] = exporter
	return exporter, evicted
}

func (d *Decoder) installTemplateLocked(
	exporter *exporterState,
	kind TemplateKind,
	template decodedTemplate,
	now time.Time,
) (*templateEntry, bool, []PendingFlowSet, error) {
	var fields []FieldDefinition
	if kind == TemplateKindData {
		fields = template.fields
	} else {
		fields = append(slices.Clone(template.scopes), template.options...)
	}
	width, err := recordWidth(fields, d.cfg.MaxRecordBytes)
	if err != nil {
		return nil, false, nil, err
	}

	key := templateLookupKey{kind: kind, id: template.id}
	signature := templateSignature(kind, template.fields, template.scopes, template.options)
	if current, ok := exporter.templates[key]; ok {
		if current.signature == signature {
			current.lastTemplateReceivedAt = now
			if d.metrics != nil {
				d.metrics.TemplateAction("refreshed", kind)
			}
			return current, false, []PendingFlowSet{}, nil
		}
		d.stats.TemplateRedefinitions++
		if d.metrics != nil {
			d.metrics.TemplateAction("redefined", kind)
		}
		generation := current.generation + 1
		exporter.nextGeneration[key] = generation
		entry := newTemplateEntry(kind, template, width, signature, generation, now)
		exporter.templates[key] = entry
		dropped := d.dropIncompatiblePendingLocked(exporter, template.id, kind, signature)
		return entry, true, dropped, nil
	}

	evicted := d.ensureTemplateCapacityLocked(exporter)
	generation := exporter.nextGeneration[key] + 1
	exporter.nextGeneration[key] = generation
	entry := newTemplateEntry(kind, template, width, signature, generation, now)
	exporter.templates[key] = entry
	delete(exporter.expiredSignatures, key)
	if d.metrics != nil {
		d.metrics.TemplateAction("learned", kind)
	}
	return entry, false, evicted, nil
}

func newTemplateEntry(
	kind TemplateKind,
	template decodedTemplate,
	width int,
	signature string,
	generation uint64,
	now time.Time,
) *templateEntry {
	return &templateEntry{
		kind:                   kind,
		id:                     template.id,
		fields:                 slices.Clone(template.fields),
		scopes:                 slices.Clone(template.scopes),
		options:                slices.Clone(template.options),
		recordWidth:            width,
		signature:              signature,
		generation:             generation,
		lastTemplateReceivedAt: now,
	}
}

func (d *Decoder) lookupTemplateLocked(
	exporter *exporterState,
	templateID uint16,
	now time.Time,
) (*templateEntry, TemplateKind, string) {
	var expiredKind TemplateKind
	var expiredSignature string
	for _, kind := range []TemplateKind{TemplateKindData, TemplateKindOptions} {
		key := templateLookupKey{kind: kind, id: templateID}
		entry, ok := exporter.templates[key]
		if !ok {
			continue
		}
		if !now.Before(entry.lastTemplateReceivedAt.Add(d.cfg.TemplateTTL)) {
			d.rememberExpiredSignatureLocked(exporter, key, entry.signature)
			delete(exporter.templates, key)
			expiredKind = kind
			expiredSignature = entry.signature
			continue
		}
		return entry, TemplateKindUnknown, ""
	}
	for _, kind := range []TemplateKind{TemplateKindData, TemplateKindOptions} {
		key := templateLookupKey{kind: kind, id: templateID}
		if signature, ok := exporter.expiredSignatures[key]; ok {
			return nil, kind, signature
		}
	}
	return nil, expiredKind, expiredSignature
}

func (d *Decoder) ensureTemplateCapacityLocked(exporter *exporterState) []PendingFlowSet {
	evicted := []PendingFlowSet{}
	for len(exporter.templates) >= d.cfg.MaxTemplatesPerExporter {
		key, found := oldestTemplate(exporter.templates)
		if !found {
			break
		}
		d.rememberExpiredSignatureLocked(exporter, key, exporter.templates[key].signature)
		delete(exporter.templates, key)
		if d.metrics != nil {
			d.metrics.TemplateAction("evicted", key.kind)
			d.metrics.CachePressure("per_exporter_limit")
		}
	}
	for d.templateCountLocked() >= d.cfg.MaxTemplatesTotal {
		exporterKey, templateKey, found := d.oldestTemplateLocked()
		if !found {
			break
		}
		target := d.exporters[exporterKey]
		d.rememberExpiredSignatureLocked(target, templateKey, target.templates[templateKey].signature)
		delete(target.templates, templateKey)
		if d.metrics != nil {
			d.metrics.TemplateAction("evicted", templateKey.kind)
			d.metrics.CachePressure("global_limit")
		}
	}
	return evicted
}

func (d *Decoder) cleanupLocked(now time.Time) []PendingFlowSet {
	evicted := []PendingFlowSet{}
	for key, exporter := range d.exporters {
		if !now.Before(exporter.lastSeen.Add(d.cfg.ExporterIdleTimeout)) {
			evicted = append(evicted, d.removeExporterLocked(key, "exporter_idle")...)
			continue
		}
		for templateKey, entry := range exporter.templates {
			if !now.Before(entry.lastTemplateReceivedAt.Add(d.cfg.TemplateTTL)) {
				d.rememberExpiredSignatureLocked(exporter, templateKey, entry.signature)
				delete(exporter.templates, templateKey)
				if d.metrics != nil {
					d.metrics.TemplateAction("expired", templateKey.kind)
				}
			}
		}
		evicted = append(evicted, d.expirePendingLocked(exporter, now)...)
	}
	return evicted
}

func (d *Decoder) removeExporterLocked(key ExporterKey, reason string) []PendingFlowSet {
	exporter, ok := d.exporters[key]
	if !ok {
		return []PendingFlowSet{}
	}
	evicted := make([]PendingFlowSet, 0, len(exporter.pending))
	for _, pending := range exporter.pending {
		evicted = append(evicted, pending.public(reason))
		d.pendingBytes -= len(pending.data)
	}
	delete(d.exporters, key)
	return evicted
}

func (d *Decoder) oldestExporterLocked() (ExporterKey, bool) {
	var oldestKey ExporterKey
	var oldestTime time.Time
	found := false
	for key, exporter := range d.exporters {
		if !found || exporter.lastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = exporter.lastSeen
			found = true
		}
	}
	return oldestKey, found
}

func oldestTemplate(templates map[templateLookupKey]*templateEntry) (templateLookupKey, bool) {
	var oldestKey templateLookupKey
	var oldestTime time.Time
	found := false
	for key, entry := range templates {
		if !found || entry.lastTemplateReceivedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.lastTemplateReceivedAt
			found = true
		}
	}
	return oldestKey, found
}

func (d *Decoder) oldestTemplateLocked() (ExporterKey, templateLookupKey, bool) {
	var oldestExporter ExporterKey
	var oldestTemplateKey templateLookupKey
	var oldestTime time.Time
	found := false
	for exporterKey, exporter := range d.exporters {
		for templateKey, entry := range exporter.templates {
			if !found || entry.lastTemplateReceivedAt.Before(oldestTime) {
				oldestExporter = exporterKey
				oldestTemplateKey = templateKey
				oldestTime = entry.lastTemplateReceivedAt
				found = true
			}
		}
	}
	return oldestExporter, oldestTemplateKey, found
}

func (d *Decoder) templateCountLocked() int {
	count := 0
	for _, exporter := range d.exporters {
		count += len(exporter.templates)
	}
	return count
}

func (d *Decoder) rememberExpiredSignatureLocked(
	exporter *exporterState,
	key templateLookupKey,
	signature string,
) {
	if _, exists := exporter.expiredSignatures[key]; !exists && len(exporter.expiredSignatures) >= d.cfg.MaxTemplatesPerExporter {
		for candidate := range exporter.expiredSignatures {
			delete(exporter.expiredSignatures, candidate)
			break
		}
	}
	if _, exists := exporter.expiredSignatures[key]; !exists && d.expiredSignatureCountLocked() >= d.cfg.MaxTemplatesTotal {
		for _, candidateExporter := range d.exporters {
			for candidate := range candidateExporter.expiredSignatures {
				delete(candidateExporter.expiredSignatures, candidate)
				break
			}
			if d.expiredSignatureCountLocked() < d.cfg.MaxTemplatesTotal {
				break
			}
		}
	}
	exporter.expiredSignatures[key] = signature
}

func (d *Decoder) expiredSignatureCountLocked() int {
	count := 0
	for _, exporter := range d.exporters {
		count += len(exporter.expiredSignatures)
	}
	return count
}
