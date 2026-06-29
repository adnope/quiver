package normalize

import (
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

func getV9String(flow *flowv1.NetFlowV9Flow, name string, fieldID uint32) (string, bool) {
	for _, f := range flow.GetDecodedFields() {
		if (f.GetName() == name && name != "") || f.GetFieldId() == fieldID {
			if s, ok := f.GetValue().(*flowv1.NetFlowV9DecodedField_StringValue); ok {
				return s.StringValue, true
			}
		}
	}
	if flow.GetFields() != nil {
		if v, ok := flow.GetFields().GetFields()[name]; ok {
			return v.GetStringValue(), true
		}
		if v, ok := flow.GetFields().GetFields()["field_"+strconv.FormatUint(uint64(fieldID), 10)]; ok {
			return v.GetStringValue(), true
		}
	}
	return "", false
}

func getV9Uint64(flow *flowv1.NetFlowV9Flow, name string, fieldID uint32) (uint64, bool) {
	for _, f := range flow.GetDecodedFields() {
		if (f.GetName() == name && name != "") || f.GetFieldId() == fieldID {
			if u, ok := f.GetValue().(*flowv1.NetFlowV9DecodedField_UnsignedValue); ok {
				return u.UnsignedValue, true
			}
		}
	}
	if flow.GetFields() != nil {
		if v, ok := flow.GetFields().GetFields()[name]; ok {
			s := v.GetStringValue()
			if u, err := strconv.ParseUint(s, 10, 64); err == nil {
				return u, true
			}
		}
		if v, ok := flow.GetFields().GetFields()["field_"+strconv.FormatUint(uint64(fieldID), 10)]; ok {
			s := v.GetStringValue()
			if u, err := strconv.ParseUint(s, 10, 64); err == nil {
				return u, true
			}
		}
	}
	return 0, false
}

func (n normalizer) applyNetFlowV9(record *domain.NormalizedFlowRecord, event *flowv1.RawFlowEventEnvelope, flow *flowv1.NetFlowV9Flow) (string, error) {
	if flow == nil {
		return "", fmt.Errorf("%w: netflow_v9 payload is nil", ErrNormalize)
	}

	srcStr, hasSrc := getV9String(flow, "sourceIPv4Address", 8)
	if !hasSrc || srcStr == "" {
		return "", fmt.Errorf("%w: netflow v9 sourceIPv4Address missing", ErrNormalize)
	}
	src, err := netip.ParseAddr(srcStr)
	if err != nil {
		return "", fmt.Errorf("%w: netflow v9 src_addr invalid: %w", ErrNormalize, err)
	}
	dstStr, hasDst := getV9String(flow, "destinationIPv4Address", 12)
	if !hasDst || dstStr == "" {
		return "", fmt.Errorf("%w: netflow v9 destinationIPv4Address missing", ErrNormalize)
	}
	dst, err := netip.ParseAddr(dstStr)
	if err != nil {
		return "", fmt.Errorf("%w: netflow v9 dst_addr invalid: %w", ErrNormalize, err)
	}
	record.SrcIP = src
	record.DstIP = dst
	if version, ok := domain.IPVersion(src); ok {
		record.IPVersion = version
	} else {
		record.IPVersion = 4
	}

	if sport, ok := getV9Uint64(flow, "sourceTransportPort", 7); ok {
		port, err := uint16FromUint32("netflow v9 sourceTransportPort", uint32(sport)) // #nosec G115 -- bounded
		if err != nil {
			return "", err
		}
		record.SrcPort = &port
	}
	if dport, ok := getV9Uint64(flow, "destinationTransportPort", 11); ok {
		port, err := uint16FromUint32("netflow v9 destinationTransportPort", uint32(dport)) // #nosec G115 -- bounded
		if err != nil {
			return "", err
		}
		record.DstPort = &port
	}

	firstSwitched, hasStart := getV9Uint64(flow, "flowStartSysUpTime", 22)
	lastSwitched, hasEnd := getV9Uint64(flow, "flowEndSysUpTime", 21)
	if hasStart && hasEnd && flow.GetExporterUnixTime() != nil && flow.GetExporterUptimeMs() > 0 &&
		firstSwitched <= uint64(flow.GetExporterUptimeMs()) && lastSwitched <= uint64(flow.GetExporterUptimeMs()) {
		exporterTime := flow.GetExporterUnixTime().AsTime().UTC()
		start := exporterTime.Add(-time.Duration(uint64(flow.GetExporterUptimeMs())-firstSwitched) * time.Millisecond) // #nosec G115 -- bounded
		end := exporterTime.Add(-time.Duration(uint64(flow.GetExporterUptimeMs())-lastSwitched) * time.Millisecond)    // #nosec G115 -- bounded
		if !end.Before(start) {
			record.EventStartTime = start
			record.EventEndTime = &end
			durationMS := end.Sub(start).Milliseconds()
			record.DurationMS = &durationMS
		} else {
			record.EventStartTime = event.GetReceivedAt().AsTime().UTC()
			markPartialWithAttr(record, "timestamp_fallback", "received_at", "netflow v9 timestamp end before start fallback to received_at")
		}
	} else {
		record.EventStartTime = event.GetReceivedAt().AsTime().UTC()
		markPartialWithAttr(record, "timestamp_fallback", "received_at", "netflow v9 timestamp fallback to received_at")
	}

	if proto, ok := getV9Uint64(flow, "protocolIdentifier", 4); ok {
		protocolNumber, err := uint8FromUint32("netflow v9 protocolIdentifier", uint32(proto)) // #nosec G115 -- bounded
		if err != nil {
			return "", err
		}
		protocol := domain.ProtocolFromNumber(protocolNumber)
		if protocol == domain.TransportProtocolUnknown && protocolNumber != 0 {
			record.ProtocolNumber = 0
			record.TransportProtocol = domain.TransportProtocolUnknown
		} else {
			record.ProtocolNumber = protocolNumber
			record.TransportProtocol = protocol
		}
	} else {
		record.ProtocolNumber = 0
		record.TransportProtocol = domain.TransportProtocolUnknown
	}

	if octets, ok := getV9Uint64(flow, "octetDeltaCount", 1); ok {
		record.Bytes = &octets
	} else {
		zero := uint64(0)
		record.Bytes = &zero
	}
	if pkts, ok := getV9Uint64(flow, "packetDeltaCount", 2); ok {
		record.Packets = &pkts
	} else {
		zero := uint64(0)
		record.Packets = &zero
	}

	if tcpFlagsVal, ok := getV9Uint64(flow, "tcpControlBits", 6); ok && tcpFlagsVal != 0 {
		tcpFlags, err := uint16FromUint32("netflow v9 tcpControlBits", uint32(tcpFlagsVal)) // #nosec G115 -- bounded
		if err != nil {
			return "", err
		}
		record.TCPFlags = &tcpFlags
	}

	if inIf, ok := getV9Uint64(flow, "ingressInterface", 10); ok {
		val := uint32(inIf) // #nosec G115 -- bounded
		record.InputInterface = &val
	}
	if outIf, ok := getV9Uint64(flow, "egressInterface", 14); ok {
		val := uint32(outIf) // #nosec G115 -- bounded
		record.OutputInterface = &val
	}

	mergeStructAttributes(record.Attributes, flow.GetFields())
	if tosVal, ok := getV9Uint64(flow, "ipClassOfService", 5); ok {
		tosUint32 := uint32(tosVal) // #nosec G115 -- bounded
		addOptionalAttr(record.Attributes, "tos", &tosUint32)
	}
	sourceID := flow.GetSourceId()
	templateID := flow.GetTemplateId()
	recordIndex := flow.GetRecordIndex()
	addOptionalAttr(record.Attributes, "source_id", &sourceID)
	addOptionalAttr(record.Attributes, "template_id", &templateID)
	addOptionalAttr(record.Attributes, "record_index", &recordIndex)

	sourceIP := ""
	if record.SourceIP != nil {
		sourceIP = record.SourceIP.String()
	}
	return sourceIP + ":" + strconv.FormatUint(uint64(flow.GetPacketSequence()), 10) + ":" +
		strconv.FormatUint(uint64(flow.GetRecordIndex()), 10), nil
}
