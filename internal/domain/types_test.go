package domain

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func TestInferDirection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		src      string
		dst      string
		expected Direction
	}{
		{name: "local to local", src: "192.168.1.10", dst: "10.0.0.5", expected: DirectionInternal},
		{name: "local to public", src: "192.168.1.10", dst: "8.8.8.8", expected: DirectionOutbound},
		{name: "public to local", src: "8.8.8.8", dst: "172.16.0.1", expected: DirectionInbound},
		{name: "public to public", src: "1.1.1.1", dst: "8.8.8.8", expected: DirectionExternal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := InferDirection(
				netip.MustParseAddr(tt.src),
				netip.MustParseAddr(tt.dst),
				DefaultLocalNetworks(),
			)
			if got != tt.expected {
				t.Fatalf("InferDirection() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestProtocolFromNumber(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		number   uint8
		expected TransportProtocol
	}{
		{name: "unknown zero", number: 0, expected: TransportProtocolUnknown},
		{name: "tcp", number: 6, expected: TransportProtocolTCP},
		{name: "udp", number: 17, expected: TransportProtocolUDP},
		{name: "icmp", number: 1, expected: TransportProtocolICMP},
		{name: "unrecognized valid number", number: 132, expected: TransportProtocolUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := ProtocolFromNumber(tt.number); got != tt.expected {
				t.Fatalf("ProtocolFromNumber(%d) = %q, want %q", tt.number, got, tt.expected)
			}
		})
	}
}

func TestParseTransportProtocol(t *testing.T) {
	t.Parallel()

	got, ok := ParseTransportProtocol("TCP")
	if !ok || got != TransportProtocolTCP {
		t.Fatalf("ParseTransportProtocol(TCP) = %q, %v", got, ok)
	}

	got, ok = ParseTransportProtocol("sctp")
	if ok || got != TransportProtocolUnknown {
		t.Fatalf("ParseTransportProtocol(sctp) = %q, %v", got, ok)
	}
}

func TestIsUUIDv7(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "valid uuidv7", input: "01934d7c-79b4-7000-8b69-001122334455", expected: true},
		{name: "wrong version", input: "01934d7c-79b4-6000-8b69-001122334455", expected: false},
		{name: "wrong variant", input: "01934d7c-79b4-7000-7b69-001122334455", expected: false},
		{name: "not uuid", input: "not-a-uuid", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsUUIDv7(tt.input); got != tt.expected {
				t.Fatalf("IsUUIDv7(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseLocalNetworks(t *testing.T) {
	t.Parallel()

	prefixes, err := ParseLocalNetworks([]string{"192.168.1.128/24"})
	if err != nil {
		t.Fatalf("ParseLocalNetworks() error = %v", err)
	}
	if len(prefixes) != 1 || prefixes[0].String() != "192.168.1.0/24" {
		t.Fatalf("prefixes = %v", prefixes)
	}

	if _, err := ParseLocalNetworks([]string{"bad-cidr"}); err == nil {
		t.Fatal("expected invalid cidr error")
	}
}

func TestIPVersion(t *testing.T) {
	t.Parallel()

	if got, ok := IPVersion(netip.MustParseAddr("192.168.1.10")); !ok || got != 4 {
		t.Fatalf("IPv4 version = %d, %v", got, ok)
	}
	if got, ok := IPVersion(netip.MustParseAddr("2001:db8::1")); !ok || got != 6 {
		t.Fatalf("IPv6 version = %d, %v", got, ok)
	}
}

func TestValidateNormalizedFlowRecord(t *testing.T) {
	t.Parallel()

	valid := validRecord()
	if err := ValidateNormalizedFlowRecord(valid); err != nil {
		t.Fatalf("valid record failed validation: %v", err)
	}

	t.Run("missing tcp ports requires partial", func(t *testing.T) {
		t.Parallel()

		record := validRecord()
		record.SrcPort = nil
		record.NormalizationStatus = NormalizationStatusOK
		if err := ValidateNormalizedFlowRecord(record); err == nil {
			t.Fatal("expected missing tcp port validation error")
		}
	})

	t.Run("partial tcp record can omit ports", func(t *testing.T) {
		t.Parallel()

		record := validRecord()
		record.SrcPort = nil
		record.NormalizationStatus = NormalizationStatusPartial
		if err := ValidateNormalizedFlowRecord(record); err != nil {
			t.Fatalf("partial record failed validation: %v", err)
		}
	})

	t.Run("event end before start fails", func(t *testing.T) {
		t.Parallel()

		record := validRecord()
		end := record.EventStartTime.Add(-time.Second)
		record.EventEndTime = &end
		if err := ValidateNormalizedFlowRecord(record); err == nil {
			t.Fatal("expected event time validation error")
		}
	})

	t.Run("ip version mismatch fails", func(t *testing.T) {
		t.Parallel()

		record := validRecord()
		record.IPVersion = 6
		if err := ValidateNormalizedFlowRecord(record); err == nil {
			t.Fatal("expected ip version validation error")
		}
	})
}

func TestBuildIdempotencyKey(t *testing.T) {
	t.Parallel()

	first := validRecord()
	second := validRecord()
	keyA := BuildIdempotencyKey(first, "rest-external-1")
	keyB := BuildIdempotencyKey(second, "rest-external-1")
	if keyA != keyB {
		t.Fatalf("same record produced different keys: %q != %q", keyA, keyB)
	}

	second.DstIP = netip.MustParseAddr("1.1.1.1")
	keyC := BuildIdempotencyKey(second, "rest-external-1")
	if keyA == keyC {
		t.Fatal("different record produced same idempotency key")
	}
}

func TestMaskSensitiveAttributes(t *testing.T) {
	t.Parallel()

	attrs := map[string]json.RawMessage{
		"token":       json.RawMessage(`"abc"`),
		"db_password": json.RawMessage(`"secret"`),
		"nested":      json.RawMessage(`{"authorization":"Bearer secret","safe":"value"}`),
		"safe_array":  json.RawMessage(`[{"cookie":"session=value"},{"count":1}]`),
	}

	masked := MaskSensitiveAttributes(attrs)
	assertJSON(t, masked["token"], `"***MASKED***"`)
	assertJSON(t, masked["db_password"], `"***MASKED***"`)
	assertJSON(t, masked["nested"], `{"authorization":"***MASKED***","safe":"value"}`)
	assertJSON(t, masked["safe_array"], `[{"cookie":"***MASKED***"},{"count":1}]`)
}

func validRecord() NormalizedFlowRecord {
	now := time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC)
	end := now.Add(5 * time.Second)
	srcPort := uint16(51524)
	dstPort := uint16(53)
	bytesValue := uint64(420)
	packets := uint64(3)
	return NormalizedFlowRecord{
		ID:                  "018ff4a2-7a8b-7c3d-9a10-09b37f0a2e11",
		SchemaVersion:       FlowSchemaVersion,
		IdempotencyKey:      "sha256:existing",
		RawEventID:          "018ff4a2-7a8b-7c3d-9a10-09b37f0a2e10",
		SourceType:          SourceTypeRESTJSON,
		CollectorID:         "rest-ingest-main",
		SourceHost:          "rest-demo-client",
		IngestedAt:          now,
		NormalizedAt:        now.Add(time.Millisecond),
		EventStartTime:      now,
		EventEndTime:        &end,
		SrcIP:               netip.MustParseAddr("192.168.1.10"),
		DstIP:               netip.MustParseAddr("8.8.8.8"),
		SrcPort:             &srcPort,
		DstPort:             &dstPort,
		IPVersion:           4,
		TransportProtocol:   TransportProtocolUDP,
		ProtocolNumber:      17,
		Bytes:               &bytesValue,
		Packets:             &packets,
		Direction:           DirectionOutbound,
		NormalizationStatus: NormalizationStatusOK,
		Attributes:          map[string]json.RawMessage{},
	}
}

func assertJSON(t *testing.T, raw json.RawMessage, expected string) {
	t.Helper()

	var gotValue object
	var expectedValue object
	if err := json.Unmarshal(raw, &gotValue); err != nil {
		t.Fatalf("unmarshal got json: %v", err)
	}
	if err := json.Unmarshal([]byte(expected), &expectedValue); err != nil {
		t.Fatalf("unmarshal expected json: %v", err)
	}

	got, err := json.Marshal(gotValue)
	if err != nil {
		t.Fatalf("marshal got json: %v", err)
	}
	want, err := json.Marshal(expectedValue)
	if err != nil {
		t.Fatalf("marshal expected json: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("json = %s, want %s", got, want)
	}
}

type object any
