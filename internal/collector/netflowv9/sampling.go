package netflowv9

import "maps"

type SamplingState struct {
	Interval       uint64
	Algorithm      uint64
	SamplerID      uint64
	InterfaceID    uint64
	InterfaceNames map[uint64]string
}

func newSamplingState() SamplingState {
	return SamplingState{InterfaceNames: map[uint64]string{}}
}

func (s SamplingState) clone() SamplingState {
	s.InterfaceNames = maps.Clone(s.InterfaceNames)
	return s
}

func (d *Decoder) updateSamplingLocked(exporter *exporterState, record OptionsRecord) {
	for _, scope := range record.Scopes {
		if scope.Value.Kind != ValueKindUnsigned {
			continue
		}
		switch scope.ID {
		case 2:
			exporter.sampling.InterfaceID = scope.Value.Unsigned
		case 5:
			exporter.sampling.SamplerID = scope.Value.Unsigned
		}
	}
	for _, option := range record.Options {
		switch option.ID {
		case 34:
			if option.Value.Kind == ValueKindUnsigned {
				exporter.sampling.Interval = option.Value.Unsigned
			}
		case 35, 49:
			if option.Value.Kind == ValueKindUnsigned {
				exporter.sampling.Algorithm = option.Value.Unsigned
			}
		case 48:
			if option.Value.Kind == ValueKindUnsigned {
				exporter.sampling.SamplerID = option.Value.Unsigned
			}
		case 50:
			if option.Value.Kind == ValueKindUnsigned && exporter.sampling.Interval == 0 {
				exporter.sampling.Interval = option.Value.Unsigned
			}
		case 82:
			if option.Value.Kind == ValueKindString && exporter.sampling.InterfaceID != 0 {
				if _, exists := exporter.sampling.InterfaceNames[exporter.sampling.InterfaceID]; !exists && len(exporter.sampling.InterfaceNames) >= d.cfg.MaxTemplatesPerExporter {
					for interfaceID := range exporter.sampling.InterfaceNames {
						delete(exporter.sampling.InterfaceNames, interfaceID)
						break
					}
				}
				exporter.sampling.InterfaceNames[exporter.sampling.InterfaceID] = option.Value.String
			}
		}
	}
}

func (d *Decoder) Sampling(key ExporterKey) (SamplingState, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	exporter, ok := d.exporters[key]
	if !ok {
		return SamplingState{}, false
	}
	return exporter.sampling.clone(), true
}
