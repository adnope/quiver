package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/validation"
)

var ErrNormalize = errors.New("normalize: failed")

type Options struct {
	Now           func() time.Time
	LocalNetworks []netip.Prefix
}

func NormalizeRawEvent(event *flowv1.RawFlowEventEnvelope, opts Options) (domain.NormalizedFlowRecord, error) {
	if err := validation.ValidateRawEventEnvelope(event); err != nil {
		return domain.NormalizedFlowRecord{}, fmt.Errorf("%w: %w", ErrNormalize, err)
	}
	normalizer := normalizer{
		now:           opts.Now,
		localNetworks: opts.LocalNetworks,
	}
	if normalizer.now == nil {
		normalizer.now = time.Now
	}
	if len(normalizer.localNetworks) == 0 {
		normalizer.localNetworks = domain.DefaultLocalNetworks()
	}
	return normalizer.normalize(event)
}

type normalizer struct {
	now           func() time.Time
	localNetworks []netip.Prefix
}

func (n normalizer) normalize(event *flowv1.RawFlowEventEnvelope) (domain.NormalizedFlowRecord, error) {
	record, err := n.baseRecord(event)
	if err != nil {
		return domain.NormalizedFlowRecord{}, err
	}

	var nativeIdentity string
	switch payload := event.GetPayload().GetPayload().(type) {
	case *flowv1.RawEventPayload_RestFlow:
		nativeIdentity, err = n.applyREST(&record, payload.RestFlow)
	case *flowv1.RawEventPayload_ZeekConn:
		nativeIdentity, err = n.applyZeek(&record, payload.ZeekConn)
	case *flowv1.RawEventPayload_NetflowV5:
		nativeIdentity, err = n.applyNetFlowV5(&record, event, payload.NetflowV5)
	case *flowv1.RawEventPayload_NetflowV9:
		nativeIdentity, err = n.applyNetFlowV9(&record, event, payload.NetflowV9)
	default:
		err = fmt.Errorf("%w: unsupported raw payload", ErrNormalize)
	}
	if err != nil {
		return domain.NormalizedFlowRecord{}, err
	}

	record.Direction = domain.InferDirection(record.SrcIP, record.DstIP, n.localNetworks)
	record.IdempotencyKey = domain.BuildIdempotencyKey(record, nativeIdentity)
	record.Attributes = domain.MaskSensitiveAttributes(record.Attributes)
	if err := domain.ValidateNormalizedFlowRecord(record); err != nil {
		return domain.NormalizedFlowRecord{}, fmt.Errorf("%w: %w", ErrNormalize, err)
	}
	return record, nil
}

func (n normalizer) baseRecord(event *flowv1.RawFlowEventEnvelope) (domain.NormalizedFlowRecord, error) {
	id, err := domain.NewUUIDv7(n.now())
	if err != nil {
		return domain.NormalizedFlowRecord{}, fmt.Errorf("%w: generate normalized id: %w", ErrNormalize, err)
	}
	source := event.GetSource()
	sourceType, err := domainSourceType(source.GetSourceType())
	if err != nil {
		return domain.NormalizedFlowRecord{}, err
	}

	var sourceIP *netip.Addr
	if source.GetSourceIp() != "" {
		addr, err := netip.ParseAddr(source.GetSourceIp())
		if err != nil {
			return domain.NormalizedFlowRecord{}, fmt.Errorf("%w: invalid source_ip: %w", ErrNormalize, err)
		}
		sourceIP = &addr
	}

	return domain.NormalizedFlowRecord{
		ID:                  id,
		SchemaVersion:       domain.FlowSchemaVersion,
		RawEventID:          event.GetEventId(),
		SourceType:          sourceType,
		CollectorID:         source.GetCollectorId(),
		SourceHost:          source.GetSourceHost(),
		SourceIP:            sourceIP,
		IngestedAt:          event.GetReceivedAt().AsTime().UTC(),
		NormalizedAt:        n.now().UTC(),
		Direction:           domain.DirectionUnknown,
		NormalizationStatus: domain.NormalizationStatusOK,
		Attributes:          map[string]json.RawMessage{},
	}, nil
}

func (n normalizer) applyREST(record *domain.NormalizedFlowRecord, input *flowv1.RestFlowInput) (string, error) {
	if input == nil {
		return "", fmt.Errorf("%w: rest payload is nil", ErrNormalize)
	}
	if input.GetEventStartTime() == nil || !input.GetEventStartTime().IsValid() {
		return "", fmt.Errorf("%w: rest event_start_time is required", ErrNormalize)
	}
	record.EventStartTime = input.GetEventStartTime().AsTime().UTC()
	if input.GetEventEndTime() != nil {
		end := input.GetEventEndTime().AsTime().UTC()
		record.EventEndTime = &end
		duration := end.Sub(record.EventStartTime).Milliseconds()
		record.DurationMS = &duration
	}
	if err := applyTuple(record, input.GetTuple()); err != nil {
		return "", err
	}
	applyCounters(record, input.GetCounters())
	if input.ApplicationProtocol != nil {
		record.ApplicationProtocol = new(input.GetApplicationProtocol())
	}
	if input.TcpFlags != nil {
		tcpFlags, err := uint16FromUint32("rest tcp_flags", input.GetTcpFlags())
		if err != nil {
			return "", err
		}
		record.TCPFlags = new(tcpFlags)
	}
	if input.SamplingRate != nil {
		record.SamplingRate = new(input.GetSamplingRate())
	}
	mergeStructAttributes(record.Attributes, input.GetAttributes())
	return restNativeIdentity(input, record), nil
}

func (n normalizer) applyZeek(record *domain.NormalizedFlowRecord, flow *flowv1.ZeekConnFlow) (string, error) {
	if flow == nil {
		return "", fmt.Errorf("%w: zeek payload is nil", ErrNormalize)
	}
	if flow.GetTs() <= 0 {
		return "", fmt.Errorf("%w: zeek ts is required", ErrNormalize)
	}
	totalMicros := int64(math.Round(flow.GetTs() * 1e6))
	record.EventStartTime = time.Unix(totalMicros/1e6, (totalMicros%1e6)*1e3).UTC()
	if flow.Duration != nil {
		durationMS := int64(math.Round(flow.GetDuration() * 1000))
		record.DurationMS = &durationMS
		end := record.EventStartTime.Add(time.Duration(durationMS) * time.Millisecond)
		record.EventEndTime = &end
	}
	src, err := netip.ParseAddr(flow.GetIdOrigH())
	if err != nil {
		return "", fmt.Errorf("%w: zeek id.orig_h invalid: %w", ErrNormalize, err)
	}
	dst, err := netip.ParseAddr(flow.GetIdRespH())
	if err != nil {
		return "", fmt.Errorf("%w: zeek id.resp_h invalid: %w", ErrNormalize, err)
	}
	record.SrcIP = src
	record.DstIP = dst
	if version, ok := domain.IPVersion(src); ok {
		record.IPVersion = version
	}
	if flow.IdOrigP != nil {
		port, err := uint16FromUint32("zeek id.orig_p", flow.GetIdOrigP())
		if err != nil {
			return "", err
		}
		record.SrcPort = new(port)
	}
	if flow.IdRespP != nil {
		port, err := uint16FromUint32("zeek id.resp_p", flow.GetIdRespP())
		if err != nil {
			return "", err
		}
		record.DstPort = new(port)
	}
	protocol, ok := domain.ParseTransportProtocol(flow.GetProto())
	if !ok {
		protocol = domain.TransportProtocolOther
	}
	record.TransportProtocol = protocol
	record.ProtocolNumber, _ = domain.ProtocolNumberFromName(protocol)
	if protocol == domain.TransportProtocolOther {
		record.ProtocolNumber = 0
	}
	if flow.OrigBytes != nil && flow.RespBytes != nil {
		record.Bytes = new(flow.GetOrigBytes() + flow.GetRespBytes())
	} else if flow.OrigBytes != nil || flow.RespBytes != nil {
		markPartialWithAttr(record, "bytes_partial", true, "one-sided zeek byte counter")
	}
	if flow.OrigPkts != nil && flow.RespPkts != nil {
		record.Packets = new(flow.GetOrigPkts() + flow.GetRespPkts())
	} else if flow.OrigPkts != nil || flow.RespPkts != nil {
		markPartialWithAttr(record, "packets_partial", true, "one-sided zeek packet counter")
	}
	if flow.ConnState != nil {
		record.FlowState = new(flow.GetConnState())
	}
	if flow.Service != nil {
		record.ApplicationProtocol = new(flow.GetService())
	}
	mergeStructAttributes(record.Attributes, flow.GetExtra())
	addOptionalAttr(record.Attributes, "local_orig", flow.LocalOrig)
	addOptionalAttr(record.Attributes, "local_resp", flow.LocalResp)
	addOptionalAttr(record.Attributes, "history", flow.History)
	if flow.GetUid() != "" {
		return flow.GetUid(), nil
	}
	return "zeek:" + record.SourceHost + ":" + record.EventStartTime.Format(time.RFC3339Nano), nil
}

func (n normalizer) applyNetFlowV5(record *domain.NormalizedFlowRecord, event *flowv1.RawFlowEventEnvelope, flow *flowv1.NetFlowV5Flow) (string, error) {
	if flow == nil {
		return "", fmt.Errorf("%w: netflow_v5 payload is nil", ErrNormalize)
	}
	src, err := netip.ParseAddr(flow.GetSrcAddr())
	if err != nil {
		return "", fmt.Errorf("%w: netflow src_addr invalid: %w", ErrNormalize, err)
	}
	dst, err := netip.ParseAddr(flow.GetDstAddr())
	if err != nil {
		return "", fmt.Errorf("%w: netflow dst_addr invalid: %w", ErrNormalize, err)
	}
	record.SrcIP = src
	record.DstIP = dst
	record.IPVersion = 4
	if flow.SrcPort != nil {
		port, err := uint16FromUint32("netflow src_port", flow.GetSrcPort())
		if err != nil {
			return "", err
		}
		record.SrcPort = new(port)
	}
	if flow.DstPort != nil {
		port, err := uint16FromUint32("netflow dst_port", flow.GetDstPort())
		if err != nil {
			return "", err
		}
		record.DstPort = new(port)
	}
	durationMS := int64(flow.GetLastSwitchedMs()) - int64(flow.GetFirstSwitchedMs())
	if durationMS >= 0 {
		record.DurationMS = &durationMS
	}
	if flow.GetExporterUnixTime() != nil && flow.ExporterUptimeMs != nil &&
		flow.GetFirstSwitchedMs() <= flow.GetExporterUptimeMs() &&
		flow.GetLastSwitchedMs() <= flow.GetExporterUptimeMs() {
		exporterTime := flow.GetExporterUnixTime().AsTime().UTC()
		start := exporterTime.Add(-time.Duration(flow.GetExporterUptimeMs()-flow.GetFirstSwitchedMs()) * time.Millisecond)
		end := exporterTime.Add(-time.Duration(flow.GetExporterUptimeMs()-flow.GetLastSwitchedMs()) * time.Millisecond)
		record.EventStartTime = start
		record.EventEndTime = &end
	} else {
		record.EventStartTime = event.GetReceivedAt().AsTime().UTC()
		markPartialWithAttr(record, "timestamp_fallback", "received_at", "netflow timestamp fallback to received_at")
	}
	protocolNumber, err := uint8FromUint32("netflow protocol_number", flow.GetProtocolNumber())
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
	record.Bytes = new(flow.GetBytes())
	record.Packets = new(flow.GetPackets())
	if flow.TcpFlags != 0 {
		tcpFlags, err := uint16FromUint32("netflow tcp_flags", flow.GetTcpFlags())
		if err != nil {
			return "", err
		}
		record.TCPFlags = new(tcpFlags)
	}
	addOptionalUint32(&record.InputInterface, flow.InputInterface)
	addOptionalUint32(&record.OutputInterface, flow.OutputInterface)
	if flow.NextHop != nil && flow.GetNextHop() != "" && flow.GetNextHop() != "0.0.0.0" {
		nextHop, err := netip.ParseAddr(flow.GetNextHop())
		if err != nil {
			return "", fmt.Errorf("%w: netflow next_hop invalid: %w", ErrNormalize, err)
		}
		record.NextHopIP = &nextHop
	}
	addOptionalAttr(record.Attributes, "src_as", flow.SrcAs)
	addOptionalAttr(record.Attributes, "dst_as", flow.DstAs)
	addOptionalAttr(record.Attributes, "src_mask", flow.SrcMask)
	addOptionalAttr(record.Attributes, "dst_mask", flow.DstMask)
	if flow.SamplingRate != nil {
		record.SamplingRate = new(flow.GetSamplingRate())
	}
	sourceIP := ""
	if record.SourceIP != nil {
		sourceIP = record.SourceIP.String()
	}
	return sourceIP + ":" + strconv.FormatUint(uint64(flow.GetPacketSequence()), 10) + ":" +
		strconv.FormatUint(uint64(flow.GetRecordIndex()), 10), nil
}

func applyTuple(record *domain.NormalizedFlowRecord, tuple *flowv1.NetworkTuple) error {
	if tuple == nil {
		return fmt.Errorf("%w: network tuple is required", ErrNormalize)
	}
	src, err := netip.ParseAddr(tuple.GetSrcIp())
	if err != nil {
		return fmt.Errorf("%w: src_ip invalid: %w", ErrNormalize, err)
	}
	dst, err := netip.ParseAddr(tuple.GetDstIp())
	if err != nil {
		return fmt.Errorf("%w: dst_ip invalid: %w", ErrNormalize, err)
	}
	record.SrcIP = src
	record.DstIP = dst
	version, ok := domain.IPVersion(src)
	if !ok {
		return fmt.Errorf("%w: src_ip invalid", ErrNormalize)
	}
	record.IPVersion = version
	if tuple.SrcPort != nil {
		port, err := uint16FromUint32("src_port", tuple.GetSrcPort())
		if err != nil {
			return err
		}
		record.SrcPort = new(port)
	}
	if tuple.DstPort != nil {
		port, err := uint16FromUint32("dst_port", tuple.GetDstPort())
		if err != nil {
			return err
		}
		record.DstPort = new(port)
	}
	protocolNumber, err := uint8FromUint32("protocol_number", tuple.GetProtocolNumber())
	if err != nil {
		return err
	}
	record.ProtocolNumber = protocolNumber
	record.TransportProtocol = domain.ProtocolFromNumber(record.ProtocolNumber)
	if tuple.GetTransportProtocol() != flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED {
		record.TransportProtocol = domainTransportProtocol(tuple.GetTransportProtocol())
	}
	return nil
}

func applyCounters(record *domain.NormalizedFlowRecord, counters *flowv1.CounterFields) {
	if counters == nil {
		return
	}
	if counters.GetBytesPartial() {
		markPartialWithAttr(record, "bytes_partial", true, "rest byte counter marked partial")
	} else if counters.Bytes != nil {
		record.Bytes = new(counters.GetBytes())
	}
	if counters.GetPacketsPartial() {
		markPartialWithAttr(record, "packets_partial", true, "rest packet counter marked partial")
	} else if counters.Packets != nil {
		record.Packets = new(counters.GetPackets())
	}
}

func restNativeIdentity(input *flowv1.RestFlowInput, record *domain.NormalizedFlowRecord) string {
	if input.GetExternalId() != "" {
		return input.GetExternalId()
	}
	sum := sha256.Sum256([]byte(record.EventStartTime.Format(time.RFC3339Nano) + "|" +
		record.SrcIP.String() + "|" + record.DstIP.String() + "|" +
		strconv.Itoa(int(record.ProtocolNumber))))
	return "tuple:" + hex.EncodeToString(sum[:])
}

func domainSourceType(sourceType flowv1.SourceType) (domain.SourceType, error) {
	switch sourceType {
	case flowv1.SourceType_SOURCE_TYPE_UNSPECIFIED:
		return "", fmt.Errorf("%w: unsupported source type %s", ErrNormalize, sourceType)
	case flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5:
		return domain.SourceTypeNetFlowV5, nil
	case flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON:
		return domain.SourceTypeZeekConnJSON, nil
	case flowv1.SourceType_SOURCE_TYPE_REST_JSON:
		return domain.SourceTypeRESTJSON, nil
	case flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9:
		return domain.SourceTypeNetFlowV9, nil
	case flowv1.SourceType_SOURCE_TYPE_SYSLOG_CEF:
		return domain.SourceTypeSyslogCEF, nil
	case flowv1.SourceType_SOURCE_TYPE_SYSLOG_LEEF:
		return domain.SourceTypeSyslogLEEF, nil
	case flowv1.SourceType_SOURCE_TYPE_SURICATA_EVE_JSON:
		return domain.SourceTypeSuricataEVE, nil
	default:
		return "", fmt.Errorf("%w: unsupported source type %s", ErrNormalize, sourceType)
	}
}

func domainTransportProtocol(protocol flowv1.TransportProtocol) domain.TransportProtocol {
	switch protocol {
	case flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED:
		return domain.TransportProtocolUnknown
	case flowv1.TransportProtocol_TRANSPORT_PROTOCOL_TCP:
		return domain.TransportProtocolTCP
	case flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UDP:
		return domain.TransportProtocolUDP
	case flowv1.TransportProtocol_TRANSPORT_PROTOCOL_ICMP:
		return domain.TransportProtocolICMP
	case flowv1.TransportProtocol_TRANSPORT_PROTOCOL_GRE:
		return domain.TransportProtocolGRE
	case flowv1.TransportProtocol_TRANSPORT_PROTOCOL_ESP:
		return domain.TransportProtocolESP
	case flowv1.TransportProtocol_TRANSPORT_PROTOCOL_OTHER:
		return domain.TransportProtocolOther
	case flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UNKNOWN:
		return domain.TransportProtocolUnknown
	default:
		return domain.TransportProtocolUnknown
	}
}

func mergeStructAttributes(dst map[string]json.RawMessage, src *structpb.Struct) {
	if src == nil {
		return
	}
	for key, value := range src.GetFields() {
		data, err := protojson.Marshal(value)
		if err == nil {
			dst[key] = data
		}
	}
}

func addOptionalAttr[T uint32 | string | bool](attrs map[string]json.RawMessage, key string, value *T) {
	if value == nil {
		return
	}
	data, err := json.Marshal(*value)
	if err == nil {
		attrs[key] = data
	}
}

func addOptionalUint32(target **uint32, value *uint32) {
	if value != nil {
		*target = new(*value)
	}
}

func markPartialWithAttr(record *domain.NormalizedFlowRecord, key string, value any, reason string) {
	record.NormalizationStatus = domain.NormalizationStatusPartial
	record.NormalizationError = new(reason)
	data, _ := json.Marshal(value)
	record.Attributes[key] = data
}

func uint16FromUint32(field string, value uint32) (uint16, error) {
	if value > math.MaxUint16 {
		return 0, fmt.Errorf("%w: %s out of range", ErrNormalize, field)
	}
	return uint16(value), nil
}

func uint8FromUint32(field string, value uint32) (uint8, error) {
	if value > math.MaxUint8 {
		return 0, fmt.Errorf("%w: %s out of range", ErrNormalize, field)
	}
	return uint8(value), nil
}
