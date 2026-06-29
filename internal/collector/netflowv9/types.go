package netflowv9

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

var ErrDecode = errors.New("netflow v9 decode")

type DecodeError struct {
	Code string
	Err  error
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("%s: %v", ErrDecode, e.Err)
}

func (e *DecodeError) Unwrap() error {
	return e.Err
}

func decodeError(code string, format string, args ...any) error {
	return &DecodeError{Code: code, Err: fmt.Errorf(format, args...)}
}

func ErrorCode(err error) string {
	var decodeErr *DecodeError
	if errors.As(err, &decodeErr) {
		return decodeErr.Code
	}
	return "internal_error"
}

type Header struct {
	Version        uint16
	Count          uint16
	SystemUptime   uint32
	UnixSeconds    uint32
	SequenceNumber uint32
	SourceID       uint32
}

type PacketContext struct {
	CollectorID     string
	SourceHost      string
	SourceIP        netip.Addr
	ReceivedAt      time.Time
	ProxyReceivedAt *time.Time
}

type TemplateKind uint8

const (
	TemplateKindUnknown TemplateKind = iota
	TemplateKindData
	TemplateKindOptions
)

type FieldDefinition struct {
	ID     uint16
	Length uint16
}

type ValueKind uint8

const (
	ValueKindUnknown ValueKind = iota
	ValueKindUnsigned
	ValueKindString
	ValueKindBytes
)

type FieldValue struct {
	Kind     ValueKind
	Unsigned uint64
	String   string
	Bytes    []byte
}

type DecodedField struct {
	ID     uint16
	Length uint16
	Name   string
	Value  FieldValue
}

type Record struct {
	TemplateID uint16
	Index      uint32
	Fields     []DecodedField
}

type OptionsRecord struct {
	TemplateID uint16
	Index      uint32
	Scopes     []DecodedField
	Options    []DecodedField
}

type FlowSet struct {
	ID             uint16
	Index          uint32
	TemplateID     uint16
	Records        []Record
	OptionsRecords []OptionsRecord
	Pending        bool
	PaddingBytes   int
}

type Packet struct {
	Header                 Header
	FlowSets               []FlowSet
	ReplayedFlowSets       []FlowSet
	EvictedPending         []PendingFlowSet
	SequenceGap            bool
	ExporterRestart        bool
	NonZeroPaddingFlowSets int
}

type ExporterKey struct {
	CollectorID string
	SourceHost  string
	SourceIP    netip.Addr
	SourceID    uint32
}

type PendingFlowSet struct {
	Exporter        ExporterKey
	Header          Header
	FlowSetID       uint16
	FlowSetIndex    uint32
	Data            []byte
	ReceivedAt      time.Time
	ProxyReceivedAt *time.Time
	ExpiresAt       time.Time
	Reason          string
	ExpectedKind    TemplateKind
}

type StateStats struct {
	Exporters             int
	DataTemplates         int
	OptionsTemplates      int
	PendingFlowSets       int
	PendingBytes          int
	TemplateRedefinitions uint64
	SequenceGaps          uint64
	ExporterRestarts      uint64
}
