package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	RawSchemaVersion  = "raw.v1"
	FlowSchemaVersion = "flow.v1"
)

type SourceType string

const (
	SourceTypeUnknown      SourceType = ""
	SourceTypeNetFlowV5    SourceType = "netflow_v5"
	SourceTypeNetFlowV9    SourceType = "netflow_v9"
	SourceTypeZeekConnJSON SourceType = "zeek_conn_json"
	SourceTypeSuricataEVE  SourceType = "suricata_eve_json"
	SourceTypeRESTJSON     SourceType = "rest_json"
	SourceTypeSyslogCEF    SourceType = "syslog_cef"
	SourceTypeSyslogLEEF   SourceType = "syslog_leef"
)

type TransportProtocol string

const (
	TransportProtocolUnknown TransportProtocol = "unknown"
	TransportProtocolTCP     TransportProtocol = "tcp"
	TransportProtocolUDP     TransportProtocol = "udp"
	TransportProtocolICMP    TransportProtocol = "icmp"
	TransportProtocolGRE     TransportProtocol = "gre"
	TransportProtocolESP     TransportProtocol = "esp"
	TransportProtocolOther   TransportProtocol = "other"
)

type Direction string

const (
	DirectionUnknown  Direction = "unknown"
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
	DirectionInternal Direction = "internal"
	DirectionExternal Direction = "external"
)

type NormalizationStatus string

const (
	NormalizationStatusOK      NormalizationStatus = "ok"
	NormalizationStatusPartial NormalizationStatus = "partial"
)

type NormalizedFlowRecord struct {
	ID                  string
	SchemaVersion       string
	IdempotencyKey      string
	RawEventID          string
	SourceType          SourceType
	CollectorID         string
	SourceHost          string
	SourceIP            *netip.Addr
	IngestedAt          time.Time
	NormalizedAt        time.Time
	EventStartTime      time.Time
	EventEndTime        *time.Time
	DurationMS          *int64
	SrcIP               netip.Addr
	DstIP               netip.Addr
	SrcPort             *uint16
	DstPort             *uint16
	IPVersion           int
	TransportProtocol   TransportProtocol
	ProtocolNumber      uint8
	Bytes               *uint64
	Packets             *uint64
	TCPFlags            *uint16
	FlowState           *string
	Direction           Direction
	InputInterface      *uint32
	OutputInterface     *uint32
	NextHopIP           *netip.Addr
	ApplicationProtocol *string
	SamplingRate        *uint32
	NormalizationStatus NormalizationStatus
	NormalizationError  *string
	Attributes          map[string]json.RawMessage
}

var ErrInvalidRecord = errors.New("domain: invalid normalized flow record")

func IsUUIDv7(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !isHex(r) {
				return false
			}
		}
	}
	return value[14] == '7' && strings.ContainsRune("89abAB", rune(value[19]))
}

func ValidSourceType(sourceType SourceType) bool {
	switch sourceType {
	case SourceTypeNetFlowV5,
		SourceTypeNetFlowV9,
		SourceTypeZeekConnJSON,
		SourceTypeSuricataEVE,
		SourceTypeRESTJSON,
		SourceTypeSyslogCEF,
		SourceTypeSyslogLEEF:
		return true
	default:
		return false
	}
}

func ValidTransportProtocol(protocol TransportProtocol) bool {
	switch protocol {
	case TransportProtocolTCP,
		TransportProtocolUDP,
		TransportProtocolICMP,
		TransportProtocolGRE,
		TransportProtocolESP,
		TransportProtocolOther,
		TransportProtocolUnknown:
		return true
	default:
		return false
	}
}

func ProtocolFromNumber(number uint8) TransportProtocol {
	switch number {
	case 0:
		return TransportProtocolUnknown
	case 1:
		return TransportProtocolICMP
	case 6:
		return TransportProtocolTCP
	case 17:
		return TransportProtocolUDP
	case 47:
		return TransportProtocolGRE
	case 50:
		return TransportProtocolESP
	default:
		return TransportProtocolUnknown
	}
}

func ParseTransportProtocol(value string) (TransportProtocol, bool) {
	protocol := TransportProtocol(strings.ToLower(strings.TrimSpace(value)))
	if ValidTransportProtocol(protocol) {
		return protocol, true
	}
	return TransportProtocolUnknown, false
}

func ProtocolNumberFromName(protocol TransportProtocol) (uint8, bool) {
	switch protocol {
	case TransportProtocolUnknown:
		return 0, true
	case TransportProtocolICMP:
		return 1, true
	case TransportProtocolTCP:
		return 6, true
	case TransportProtocolUDP:
		return 17, true
	case TransportProtocolGRE:
		return 47, true
	case TransportProtocolESP:
		return 50, true
	case TransportProtocolOther:
		return 0, true
	default:
		return 0, false
	}
}

func DefaultLocalNetworks() []netip.Prefix {
	cidrs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefixes = append(prefixes, netip.MustParsePrefix(cidr))
	}
	return prefixes
}

func ParseLocalNetworks(cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse local network %q: %w", cidr, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func IPVersion(addr netip.Addr) (int, bool) {
	switch {
	case !addr.IsValid():
		return 0, false
	case addr.Is4() || addr.Is4In6():
		return 4, true
	default:
		return 6, true
	}
}

func InferDirection(src netip.Addr, dst netip.Addr, localNetworks []netip.Prefix) Direction {
	if !src.IsValid() || !dst.IsValid() {
		return DirectionUnknown
	}

	srcLocal := containsAddr(localNetworks, src)
	dstLocal := containsAddr(localNetworks, dst)
	switch {
	case srcLocal && dstLocal:
		return DirectionInternal
	case srcLocal && !dstLocal:
		return DirectionOutbound
	case !srcLocal && dstLocal:
		return DirectionInbound
	default:
		return DirectionExternal
	}
}

func ValidateNormalizedFlowRecord(record NormalizedFlowRecord) error {
	if record.SchemaVersion != FlowSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %q", ErrInvalidRecord, FlowSchemaVersion)
	}
	if !IsUUIDv7(record.ID) {
		return fmt.Errorf("%w: id must be uuidv7", ErrInvalidRecord)
	}
	if strings.TrimSpace(record.IdempotencyKey) == "" {
		return fmt.Errorf("%w: idempotency_key is required", ErrInvalidRecord)
	}
	if !IsUUIDv7(record.RawEventID) {
		return fmt.Errorf("%w: raw_event_id must be uuidv7", ErrInvalidRecord)
	}
	if !ValidSourceType(record.SourceType) {
		return fmt.Errorf("%w: invalid source_type", ErrInvalidRecord)
	}
	if strings.TrimSpace(record.CollectorID) == "" {
		return fmt.Errorf("%w: collector_id is required", ErrInvalidRecord)
	}
	if strings.TrimSpace(record.SourceHost) == "" {
		return fmt.Errorf("%w: source_host is required", ErrInvalidRecord)
	}
	if record.IngestedAt.IsZero() {
		return fmt.Errorf("%w: ingested_at is required", ErrInvalidRecord)
	}
	if record.NormalizedAt.IsZero() {
		return fmt.Errorf("%w: normalized_at is required", ErrInvalidRecord)
	}
	if record.EventStartTime.IsZero() {
		return fmt.Errorf("%w: event_start_time is required", ErrInvalidRecord)
	}
	if record.EventEndTime != nil && record.EventEndTime.Before(record.EventStartTime) {
		return fmt.Errorf("%w: event_end_time before event_start_time", ErrInvalidRecord)
	}
	if !record.SrcIP.IsValid() || !record.DstIP.IsValid() {
		return fmt.Errorf("%w: src_ip and dst_ip must be valid", ErrInvalidRecord)
	}
	if record.IPVersion != 4 && record.IPVersion != 6 {
		return fmt.Errorf("%w: ip_version must be 4 or 6", ErrInvalidRecord)
	}
	if srcVersion, ok := IPVersion(record.SrcIP); !ok || srcVersion != record.IPVersion {
		return fmt.Errorf("%w: ip_version must match src_ip", ErrInvalidRecord)
	}
	if dstVersion, ok := IPVersion(record.DstIP); !ok || dstVersion != record.IPVersion {
		return fmt.Errorf("%w: ip_version must match dst_ip", ErrInvalidRecord)
	}
	if !ValidTransportProtocol(record.TransportProtocol) {
		return fmt.Errorf("%w: invalid transport_protocol", ErrInvalidRecord)
	}
	if record.Direction == "" {
		return fmt.Errorf("%w: direction is required", ErrInvalidRecord)
	}
	if record.NormalizationStatus != NormalizationStatusOK &&
		record.NormalizationStatus != NormalizationStatusPartial {
		return fmt.Errorf("%w: invalid normalization_status", ErrInvalidRecord)
	}
	if record.Attributes == nil {
		return fmt.Errorf("%w: attributes must be initialized", ErrInvalidRecord)
	}
	if requiresPorts(record.TransportProtocol) && (record.SrcPort == nil || record.DstPort == nil) &&
		record.NormalizationStatus != NormalizationStatusPartial {
		return fmt.Errorf("%w: tcp/udp records missing ports must be partial", ErrInvalidRecord)
	}
	return nil
}

func BuildIdempotencyKey(record NormalizedFlowRecord, nativeIdentity string) string {
	parts := []string{
		record.SchemaVersion,
		string(record.SourceType),
		record.CollectorID,
		record.SourceHost,
		nativeIdentity,
		record.EventStartTime.UTC().Format(time.RFC3339Nano),
		formatOptionalTime(record.EventEndTime),
		record.SrcIP.String(),
		record.DstIP.String(),
		formatOptionalUint16(record.SrcPort),
		formatOptionalUint16(record.DstPort),
		fmt.Sprintf("%d", record.ProtocolNumber),
		formatOptionalUint64(record.Bytes),
		formatOptionalUint64(record.Packets),
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func MaskSensitiveAttributes(attrs map[string]json.RawMessage) map[string]json.RawMessage {
	masked := make(map[string]json.RawMessage, len(attrs))
	for key, value := range attrs {
		if IsSensitiveKey(key) {
			masked[key] = json.RawMessage(`"***MASKED***"`)
			continue
		}
		masked[key] = maskJSONValue(value)
	}
	return masked
}

func IsSensitiveKey(key string) bool {
	normalized := normalizeKey(key)
	sensitiveKeys := []string{
		"password",
		"passwd",
		"secret",
		"token",
		"api_key",
		"apikey",
		"authorization",
		"auth",
		"cookie",
		"session",
		"credential",
	}
	for _, sensitiveKey := range sensitiveKeys {
		if normalized == sensitiveKey || strings.Contains(normalized, "_"+sensitiveKey) ||
			strings.Contains(normalized, sensitiveKey+"_") {
			return true
		}
	}
	return false
}

func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func requiresPorts(protocol TransportProtocol) bool {
	return protocol == TransportProtocolTCP || protocol == TransportProtocolUDP
}

func formatOptionalTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func formatOptionalUint16(value *uint16) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}

func formatOptionalUint64(value *uint64) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}

func maskJSONValue(raw json.RawMessage) json.RawMessage {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err == nil {
		return mustMarshalRaw(MaskSensitiveAttributes(object))
	}

	var array []json.RawMessage
	if err := json.Unmarshal(raw, &array); err == nil {
		masked := make([]json.RawMessage, 0, len(array))
		for _, item := range array {
			masked = append(masked, maskJSONValue(item))
		}
		return mustMarshalRaw(masked)
	}

	return slices.Clone(raw)
}

func mustMarshalRaw[T map[string]json.RawMessage | []json.RawMessage](value T) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return data
}

func isHex(r rune) bool {
	return unicode.IsDigit(r) || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

func normalizeKey(key string) string {
	replacer := strings.NewReplacer("-", "_", " ", "_", ".", "_")
	return replacer.Replace(strings.ToLower(key))
}
