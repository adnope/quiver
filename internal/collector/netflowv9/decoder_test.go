package netflowv9

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type testField struct {
	id     uint16
	length uint16
}

func TestDecoderDecodesTypedDataAndPreservesRepeatedFields(t *testing.T) {
	t.Parallel()

	decoder := newTestDecoder(t, Config{})
	now := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)
	fields := []testField{
		{id: 8, length: 4},
		{id: 27, length: 16},
		{id: 1, length: 8},
		{id: 82, length: 8},
		{id: 400, length: 3},
		{id: 400, length: 2},
	}
	record := bytes.Join([][]byte{
		{192, 0, 2, 10},
		netip.MustParseAddr("2001:db8::10").AsSlice(),
		uintBytes(math.MaxUint64, 8),
		{'e', 't', 'h', '0', 0, 0, 0, 0},
		{1, 2, 3},
		{4, 5},
	}, nil)
	packet := packetBytes(
		2,
		1000,
		100,
		10,
		7,
		templateFlowSet(256, fields),
		dataFlowSet(256, record, 3, true),
	)

	decoded, err := decoder.Decode(context.Background(), packetContext(now, "gateway-a", "192.0.2.1"), packet)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(decoded.FlowSets) != 2 || len(decoded.FlowSets[1].Records) != 1 {
		t.Fatalf("decoded flowsets = %+v", decoded.FlowSets)
	}
	values := decoded.FlowSets[1].Records[0].Fields
	if len(values) != len(fields) {
		t.Fatalf("decoded fields = %d, want %d", len(values), len(fields))
	}
	if values[0].Value.String != "192.0.2.10" || values[1].Value.String != "2001:db8::10" {
		t.Fatalf("decoded addresses = %q, %q", values[0].Value.String, values[1].Value.String)
	}
	if values[2].Value.Unsigned != math.MaxUint64 || values[3].Value.String != "eth0" {
		t.Fatalf("decoded uint/string values = %+v %+v", values[2], values[3])
	}
	if values[4].ID != values[5].ID || !bytes.Equal(values[4].Value.Bytes, []byte{1, 2, 3}) || !bytes.Equal(values[5].Value.Bytes, []byte{4, 5}) {
		t.Fatalf("repeated raw fields lost order: %+v", values[4:])
	}
	if decoded.NonZeroPaddingFlowSets != 1 || decoded.FlowSets[1].PaddingBytes != 3 {
		t.Fatalf("padding result = %+v", decoded)
	}
}

func TestDecoderSoftflowdStyleIPv4TCPUDPAndICMPRecords(t *testing.T) {
	t.Parallel()

	decoder := newTestDecoder(t, Config{})
	now := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)
	fields := []testField{
		{id: 1, length: 8},
		{id: 2, length: 8},
		{id: 4, length: 1},
		{id: 6, length: 1},
		{id: 7, length: 2},
		{id: 8, length: 4},
		{id: 11, length: 2},
		{id: 12, length: 4},
		{id: 32, length: 2},
		{id: 21, length: 4},
		{id: 22, length: 4},
	}
	recordDefinitions := []struct {
		protocol  uint64
		offset    uint64
		lastOctet byte
	}{
		{protocol: 6, offset: 0, lastOctet: 10},
		{protocol: 17, offset: 1, lastOctet: 11},
		{protocol: 1, offset: 2, lastOctet: 12},
	}
	records := []byte{}
	for _, definition := range recordDefinitions {
		records = append(records, uintBytes(1000+definition.offset, 8)...)
		records = append(records, uintBytes(10+definition.offset, 8)...)
		records = append(records, uintBytes(definition.protocol, 1)...)
		records = append(records, uintBytes(0x12, 1)...)
		records = append(records, uintBytes(1000+definition.offset, 2)...)
		records = append(records, []byte{192, 0, 2, definition.lastOctet}...)
		records = append(records, uintBytes(2000+definition.offset, 2)...)
		records = append(records, []byte{198, 51, 100, definition.lastOctet + 10}...)
		records = append(records, uintBytes(8, 2)...)
		records = append(records, uintBytes(900, 4)...)
		records = append(records, uintBytes(800, 4)...)
	}
	packet := packetBytes(
		4,
		1000,
		100,
		10,
		7,
		templateFlowSet(256, fields),
		dataFlowSet(256, records, 0, false),
	)
	decoded, err := decoder.Decode(context.Background(), packetContext(now, "gateway-a", "192.0.2.1"), packet)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	gotRecords := decoded.FlowSets[1].Records
	if len(gotRecords) != 3 {
		t.Fatalf("record count = %d, want 3", len(gotRecords))
	}
	for index, definition := range recordDefinitions {
		if gotRecords[index].Fields[2].Value.Unsigned != definition.protocol {
			t.Fatalf("record %d protocol = %d, want %d", index, gotRecords[index].Fields[2].Value.Unsigned, definition.protocol)
		}
	}
}

func TestDecoderOptionsTemplateAndSamplingState(t *testing.T) {
	t.Parallel()

	decoder := newTestDecoder(t, Config{})
	now := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)
	optionsTemplate := optionsTemplateFlowSet(
		300,
		[]testField{{id: 2, length: 4}},
		[]testField{{id: 34, length: 4}, {id: 35, length: 1}, {id: 82, length: 8}},
	)
	optionsData := bytes.Join([][]byte{
		uintBytes(9, 4),
		uintBytes(100, 4),
		uintBytes(1, 1),
		{'e', 't', 'h', '9', 0, 0, 0, 0},
	}, nil)
	packet := packetBytes(2, 1000, 100, 10, 7, optionsTemplate, dataFlowSet(300, optionsData, 3, false))
	ctx := packetContext(now, "gateway-a", "192.0.2.1")
	decoded, err := decoder.Decode(context.Background(), ctx, packet)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(decoded.FlowSets[1].OptionsRecords) != 1 {
		t.Fatalf("options records = %+v", decoded.FlowSets[1])
	}
	key := ExporterKey{CollectorID: ctx.CollectorID, SourceHost: ctx.SourceHost, SourceIP: ctx.SourceIP, SourceID: 7}
	sampling, ok := decoder.Sampling(key)
	if !ok {
		t.Fatal("sampling state not found")
	}
	if sampling.Interval != 100 || sampling.Algorithm != 1 || sampling.InterfaceID != 9 || sampling.InterfaceNames[9] != "eth9" {
		t.Fatalf("sampling state = %+v", sampling)
	}
}

func TestDecoderScopesTemplatesByExporterAndSourceID(t *testing.T) {
	t.Parallel()

	decoder := newTestDecoder(t, Config{})
	now := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)
	templateA := packetBytes(1, 100, 100, 1, 1, templateFlowSet(256, []testField{{id: 8, length: 4}}))
	templateB := packetBytes(1, 100, 100, 1, 2, templateFlowSet(256, []testField{{id: 1, length: 8}}))
	if _, err := decoder.Decode(context.Background(), packetContext(now, "gateway-a", "192.0.2.1"), templateA); err != nil {
		t.Fatalf("Decode(template A) error = %v", err)
	}
	if _, err := decoder.Decode(context.Background(), packetContext(now, "gateway-a", "192.0.2.1"), templateB); err != nil {
		t.Fatalf("Decode(template B) error = %v", err)
	}

	dataA := packetBytes(1, 101, 101, 2, 1, dataFlowSet(256, []byte{198, 51, 100, 1}, 0, false))
	decodedA, err := decoder.Decode(context.Background(), packetContext(now.Add(time.Second), "gateway-a", "192.0.2.1"), dataA)
	if err != nil {
		t.Fatalf("Decode(data A) error = %v", err)
	}
	dataB := packetBytes(1, 101, 101, 2, 2, dataFlowSet(256, uintBytes(99, 8), 0, false))
	decodedB, err := decoder.Decode(context.Background(), packetContext(now.Add(time.Second), "gateway-a", "192.0.2.1"), dataB)
	if err != nil {
		t.Fatalf("Decode(data B) error = %v", err)
	}
	if decodedA.FlowSets[0].Records[0].Fields[0].Value.String != "198.51.100.1" || decodedB.FlowSets[0].Records[0].Fields[0].Value.Unsigned != 99 {
		t.Fatalf("template state crossed source ids: A=%+v B=%+v", decodedA, decodedB)
	}
}

func TestDecoderLearnsMultipleDataAndOptionsTemplatesFromSingleFlowSets(t *testing.T) {
	t.Parallel()

	decoder := newTestDecoder(t, Config{})
	now := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)
	dataTemplates := append(
		templateRecord(256, []testField{{id: 8, length: 4}}),
		templateRecord(257, []testField{{id: 1, length: 8}})...,
	)
	optionsTemplates := append(
		optionsTemplateRecord(300, []testField{{id: 2, length: 4}}, []testField{{id: 34, length: 4}}),
		optionsTemplateRecord(301, []testField{{id: 5, length: 2}}, []testField{{id: 35, length: 1}})...,
	)
	packet := packetBytes(
		4,
		100,
		100,
		1,
		7,
		flowSet(0, padToFour(dataTemplates, false)),
		flowSet(1, padToFour(optionsTemplates, false)),
	)
	if _, err := decoder.Decode(context.Background(), packetContext(now, "gateway-a", "192.0.2.1"), packet); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	stats := decoder.Stats()
	if stats.DataTemplates != 2 || stats.OptionsTemplates != 2 {
		t.Fatalf("template stats = %+v", stats)
	}
}

func TestDecoderTemplateExpiryPendingReplayAndRedefinitionSafety(t *testing.T) {
	t.Parallel()

	decoder := newTestDecoder(t, Config{TemplateTTL: time.Minute, PendingMaxWait: time.Minute})
	start := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)
	ctx := packetContext(start, "gateway-a", "192.0.2.1")
	template := packetBytes(1, 100, 100, 1, 7, templateFlowSet(256, []testField{{id: 1, length: 4}}))
	if _, err := decoder.Decode(context.Background(), ctx, template); err != nil {
		t.Fatalf("Decode(template) error = %v", err)
	}

	ctx.ReceivedAt = start.Add(30 * time.Second)
	data := packetBytes(1, 101, 101, 2, 7, dataFlowSet(256, uintBytes(7, 4), 0, false))
	if _, err := decoder.Decode(context.Background(), ctx, data); err != nil {
		t.Fatalf("Decode(data before expiry) error = %v", err)
	}
	ctx.ReceivedAt = start.Add(61 * time.Second)
	pending, err := decoder.Decode(context.Background(), ctx, data)
	if err != nil {
		t.Fatalf("Decode(data after expiry) error = %v", err)
	}
	if !pending.FlowSets[0].Pending || decoder.Stats().PendingFlowSets != 1 {
		t.Fatalf("missing template was not buffered: %+v stats=%+v", pending, decoder.Stats())
	}

	ctx.ReceivedAt = start.Add(62 * time.Second)
	redefined := packetBytes(1, 102, 102, 3, 7, templateFlowSet(256, []testField{{id: 1, length: 8}}))
	result, err := decoder.Decode(context.Background(), ctx, redefined)
	if err != nil {
		t.Fatalf("Decode(redefined template) error = %v", err)
	}
	if len(result.ReplayedFlowSets) != 0 || len(result.EvictedPending) != 1 || result.EvictedPending[0].Reason != "template_redefined" {
		t.Fatalf("incompatible pending generation was not rejected: %+v", result)
	}
	if decoder.Stats().PendingFlowSets != 0 {
		t.Fatalf("pending flowsets remain: %+v", decoder.Stats())
	}
}

func TestDecoderTemplateRefreshRedefinitionAndIdleCleanup(t *testing.T) {
	t.Parallel()

	decoder := newTestDecoder(t, Config{
		TemplateTTL:         time.Minute,
		ExporterIdleTimeout: 2 * time.Minute,
	})
	start := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)
	ctx := packetContext(start, "gateway-a", "192.0.2.1")
	templateA := packetBytes(1, 100, 100, 1, 7, templateFlowSet(256, []testField{{id: 1, length: 4}}))
	if _, err := decoder.Decode(context.Background(), ctx, templateA); err != nil {
		t.Fatalf("Decode(template) error = %v", err)
	}
	ctx.ReceivedAt = start.Add(30 * time.Second)
	templateA = packetBytes(1, 101, 101, 2, 7, templateFlowSet(256, []testField{{id: 1, length: 4}}))
	if _, err := decoder.Decode(context.Background(), ctx, templateA); err != nil {
		t.Fatalf("Decode(template refresh) error = %v", err)
	}
	ctx.ReceivedAt = start.Add(80 * time.Second)
	data := packetBytes(1, 102, 102, 3, 7, dataFlowSet(256, uintBytes(5, 4), 0, false))
	decoded, err := decoder.Decode(context.Background(), ctx, data)
	if err != nil || decoded.FlowSets[0].Pending {
		t.Fatalf("refreshed template was unavailable: result=%+v err=%v", decoded, err)
	}
	ctx.ReceivedAt = start.Add(81 * time.Second)
	templateB := packetBytes(1, 103, 103, 4, 7, templateFlowSet(256, []testField{{id: 1, length: 8}}))
	if _, err := decoder.Decode(context.Background(), ctx, templateB); err != nil {
		t.Fatalf("Decode(template redefinition) error = %v", err)
	}
	if decoder.Stats().TemplateRedefinitions != 1 {
		t.Fatalf("template redefinitions = %d, want 1", decoder.Stats().TemplateRedefinitions)
	}
	decoder.Cleanup(start.Add(4 * time.Minute))
	if decoder.Stats().Exporters != 0 {
		t.Fatalf("idle exporter was not removed: %+v", decoder.Stats())
	}
}

func TestDecoderMissingTemplateReplaysInReceiveOrder(t *testing.T) {
	t.Parallel()

	decoder := newTestDecoder(t, Config{})
	start := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)
	ctx := packetContext(start, "gateway-a", "192.0.2.1")
	for index, value := range []uint64{10, 20} {
		ctx.ReceivedAt = start.Add(time.Duration(index) * time.Second)
		packet := packetBytes(1, 100+uint32(index), 100, uint32(index), 7, dataFlowSet(256, uintBytes(value, 4), 0, false))
		decoded, err := decoder.Decode(context.Background(), ctx, packet)
		if err != nil || !decoded.FlowSets[0].Pending {
			t.Fatalf("Decode(pending %d) result=%+v err=%v", index, decoded, err)
		}
	}
	ctx.ReceivedAt = start.Add(2 * time.Second)
	template := packetBytes(1, 102, 102, 2, 7, templateFlowSet(256, []testField{{id: 1, length: 4}}))
	decoded, err := decoder.Decode(context.Background(), ctx, template)
	if err != nil {
		t.Fatalf("Decode(template) error = %v", err)
	}
	if len(decoded.ReplayedFlowSets) != 2 {
		t.Fatalf("replayed flowsets = %d, want 2", len(decoded.ReplayedFlowSets))
	}
	first := decoded.ReplayedFlowSets[0].Records[0].Fields[0].Value.Unsigned
	second := decoded.ReplayedFlowSets[1].Records[0].Fields[0].Value.Unsigned
	if first != 10 || second != 20 {
		t.Fatalf("replay order = %d, %d", first, second)
	}
}

func TestDecoderPendingTimeoutAndCapacityEviction(t *testing.T) {
	t.Parallel()

	decoder := newTestDecoder(t, Config{
		PendingMaxWait:          time.Second,
		PendingBytesPerExporter: 8,
		PendingBytesTotal:       8,
	})
	start := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)
	ctx := packetContext(start, "gateway-a", "192.0.2.1")
	first := packetBytes(1, 1, 1, 1, 7, dataFlowSet(256, []byte{1, 2, 3, 4, 5, 6}, 0, false))
	if _, err := decoder.Decode(context.Background(), ctx, first); err != nil {
		t.Fatalf("Decode(first) error = %v", err)
	}
	ctx.ReceivedAt = start.Add(100 * time.Millisecond)
	second := packetBytes(1, 2, 2, 2, 7, dataFlowSet(257, []byte{7, 8, 9, 10, 11, 12}, 0, false))
	decoded, err := decoder.Decode(context.Background(), ctx, second)
	if err != nil {
		t.Fatalf("Decode(second) error = %v", err)
	}
	if len(decoded.EvictedPending) != 1 || decoded.EvictedPending[0].Reason != "pending_evicted" {
		t.Fatalf("capacity eviction = %+v", decoded.EvictedPending)
	}
	expired := decoder.Cleanup(start.Add(2 * time.Second))
	if len(expired) != 1 || expired[0].Reason != "pending_expired" || decoder.Stats().PendingBytes != 0 {
		t.Fatalf("timeout cleanup=%+v stats=%+v", expired, decoder.Stats())
	}
}

func TestDecoderTemplateAndExporterLimits(t *testing.T) {
	t.Parallel()

	decoder := newTestDecoder(t, Config{
		MaxExporters:            1,
		MaxTemplatesPerExporter: 1,
		MaxTemplatesTotal:       1,
	})
	start := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)
	packet := packetBytes(
		2,
		1,
		1,
		1,
		7,
		templateFlowSet(256, []testField{{id: 1, length: 4}}),
		templateFlowSet(257, []testField{{id: 2, length: 4}}),
	)
	if _, err := decoder.Decode(context.Background(), packetContext(start, "gateway-a", "192.0.2.1"), packet); err != nil {
		t.Fatalf("Decode(first exporter) error = %v", err)
	}
	stats := decoder.Stats()
	if stats.DataTemplates != 1 || stats.Exporters != 1 {
		t.Fatalf("stats after template eviction = %+v", stats)
	}
	if _, err := decoder.Decode(context.Background(), packetContext(start.Add(time.Second), "gateway-b", "192.0.2.2"), packetBytes(0, 1, 1, 1, 7)); err != nil {
		t.Fatalf("Decode(second exporter) error = %v", err)
	}
	stats = decoder.Stats()
	if stats.Exporters != 1 || stats.DataTemplates != 0 {
		t.Fatalf("stats after exporter eviction = %+v", stats)
	}
}

func TestDecoderRestartSequenceAndUint32Wraparound(t *testing.T) {
	t.Parallel()

	t.Run("credible restart clears state", func(t *testing.T) {
		t.Parallel()

		decoder := newTestDecoder(t, Config{})
		start := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)
		ctx := packetContext(start, "gateway-a", "192.0.2.1")
		first := packetBytes(1, 1000, 100, 100, 7, templateFlowSet(256, []testField{{id: 1, length: 4}}))
		if _, err := decoder.Decode(context.Background(), ctx, first); err != nil {
			t.Fatalf("Decode(first) error = %v", err)
		}
		ctx.ReceivedAt = start.Add(time.Second)
		restarted, err := decoder.Decode(context.Background(), ctx, packetBytes(0, 10, 101, 1, 7))
		if err != nil {
			t.Fatalf("Decode(restart) error = %v", err)
		}
		if !restarted.ExporterRestart || decoder.Stats().DataTemplates != 0 {
			t.Fatalf("restart result=%+v stats=%+v", restarted, decoder.Stats())
		}
	})

	t.Run("uptime and sequence wrap are forward progress", func(t *testing.T) {
		t.Parallel()

		decoder := newTestDecoder(t, Config{})
		start := time.Date(2026, 6, 28, 1, 0, 0, 0, time.UTC)
		ctx := packetContext(start, "gateway-a", "192.0.2.1")
		if _, err := decoder.Decode(context.Background(), ctx, packetBytes(0, math.MaxUint32-5, 100, math.MaxUint32, 7)); err != nil {
			t.Fatalf("Decode(before wrap) error = %v", err)
		}
		ctx.ReceivedAt = start.Add(time.Second)
		wrapped, err := decoder.Decode(context.Background(), ctx, packetBytes(0, 3, 101, 0, 7))
		if err != nil {
			t.Fatalf("Decode(after wrap) error = %v", err)
		}
		if wrapped.ExporterRestart || wrapped.SequenceGap {
			t.Fatalf("wrap misclassified: %+v", wrapped)
		}
		ctx.ReceivedAt = start.Add(2 * time.Second)
		gap, err := decoder.Decode(context.Background(), ctx, packetBytes(0, 4, 102, 2, 7))
		if err != nil {
			t.Fatalf("Decode(gap) error = %v", err)
		}
		if !gap.SequenceGap {
			t.Fatalf("sequence gap not detected: %+v", gap)
		}
	})
}

func TestDecoderRejectsMalformedBoundariesCountsAndFieldWidths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		packet   []byte
		expected string
	}{
		{name: "short header", packet: []byte{0, 9}, expected: "malformed_packet"},
		{name: "unsupported version", packet: packetWithVersion(10), expected: "unsupported_version"},
		{name: "reserved flowset", packet: packetBytes(0, 1, 1, 1, 1, flowSet(2, nil)), expected: "invalid_flowset_id"},
		{name: "truncated flowset", packet: append(packetBytes(0, 1, 1, 1, 1), 0, 0, 0, 20), expected: "invalid_flowset_boundary"},
		{name: "count mismatch", packet: packetBytes(2, 1, 1, 1, 1, templateFlowSet(256, []testField{{id: 1, length: 4}})), expected: "invalid_record_count"},
		{name: "zero field width", packet: packetBytes(1, 1, 1, 1, 1, templateFlowSet(256, []testField{{id: 1, length: 0}})), expected: "invalid_field_length"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decoder := newTestDecoder(t, Config{})
			_, err := decoder.Decode(
				context.Background(),
				packetContext(time.Now(), "gateway-a", "192.0.2.1"),
				tt.packet,
			)
			if err == nil || ErrorCode(err) != tt.expected {
				t.Fatalf("Decode() error = %v code=%q, want %q", err, ErrorCode(err), tt.expected)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	t.Parallel()

	if _, err := NewDecoder(Config{}); err != nil {
		t.Fatalf("NewDecoder(defaults) error = %v", err)
	}
	_, err := NewDecoder(Config{MaxPacketBytes: 65536})
	if err == nil || !strings.Contains(err.Error(), "65535") {
		t.Fatalf("NewDecoder() error = %v", err)
	}
}

func FuzzDecoderNeverPanics(f *testing.F) {
	f.Add(packetBytes(0, 1, 1, 1, 1))
	f.Add(packetBytes(1, 1, 1, 1, 1, templateFlowSet(256, []testField{{id: 1, length: 4}})))
	f.Add([]byte{0, 9})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > DefaultMaxPacketBytes {
			data = data[:DefaultMaxPacketBytes]
		}
		decoder := newTestDecoder(t, Config{
			MaxExporters:            4,
			MaxTemplatesPerExporter: 8,
			MaxTemplatesTotal:       16,
			PendingBytesPerExporter: 1024,
			PendingBytesTotal:       4096,
		})
		_, _ = decoder.Decode(
			context.Background(),
			packetContext(time.Unix(1, 0), "gateway", "192.0.2.1"),
			data,
		)
	})
}

func newTestDecoder(t *testing.T, cfg Config) *Decoder {
	t.Helper()

	decoder, err := NewDecoder(cfg)
	if err != nil {
		t.Fatalf("NewDecoder() error = %v", err)
	}
	return decoder
}

func packetContext(receivedAt time.Time, sourceHost string, sourceIP string) PacketContext {
	return PacketContext{
		CollectorID: "netflow-v9-main",
		SourceHost:  sourceHost,
		SourceIP:    netip.MustParseAddr(sourceIP),
		ReceivedAt:  receivedAt,
	}
}

func packetBytes(
	count uint16,
	uptime uint32,
	unixSeconds uint32,
	sequence uint32,
	sourceID uint32,
	flowSets ...[]byte,
) []byte {
	totalBytes := netFlowV9HeaderBytes
	for _, flowSet := range flowSets {
		totalBytes += len(flowSet)
	}
	packet := make([]byte, totalBytes)
	binary.BigEndian.PutUint16(packet[0:2], 9)
	binary.BigEndian.PutUint16(packet[2:4], count)
	binary.BigEndian.PutUint32(packet[4:8], uptime)
	binary.BigEndian.PutUint32(packet[8:12], unixSeconds)
	binary.BigEndian.PutUint32(packet[12:16], sequence)
	binary.BigEndian.PutUint32(packet[16:20], sourceID)
	offset := netFlowV9HeaderBytes
	for _, flowSet := range flowSets {
		copy(packet[offset:], flowSet)
		offset += len(flowSet)
	}
	return packet
}

func packetWithVersion(version uint16) []byte {
	packet := packetBytes(0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(packet[:2], version)
	return packet
}

func flowSet(id uint16, payload []byte) []byte {
	result := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint16(result[0:2], id)
	binary.BigEndian.PutUint16(result[2:4], checkedUint16(4+len(payload)))
	return append(result, payload...)
}

func templateFlowSet(templateID uint16, fields []testField) []byte {
	return flowSet(0, padToFour(templateRecord(templateID, fields), false))
}

func templateRecord(templateID uint16, fields []testField) []byte {
	payload := make([]byte, 4, 4+len(fields)*4)
	binary.BigEndian.PutUint16(payload[0:2], templateID)
	binary.BigEndian.PutUint16(payload[2:4], checkedUint16(len(fields)))
	for _, field := range fields {
		payload = binary.BigEndian.AppendUint16(payload, field.id)
		payload = binary.BigEndian.AppendUint16(payload, field.length)
	}
	return payload
}

func optionsTemplateFlowSet(templateID uint16, scopes []testField, options []testField) []byte {
	return flowSet(1, padToFour(optionsTemplateRecord(templateID, scopes, options), false))
}

func optionsTemplateRecord(templateID uint16, scopes []testField, options []testField) []byte {
	payload := make([]byte, 6, 6+(len(scopes)+len(options))*4)
	binary.BigEndian.PutUint16(payload[0:2], templateID)
	binary.BigEndian.PutUint16(payload[2:4], checkedUint16(len(scopes)*4))
	binary.BigEndian.PutUint16(payload[4:6], checkedUint16(len(options)*4))
	for _, field := range append(append([]testField{}, scopes...), options...) {
		payload = binary.BigEndian.AppendUint16(payload, field.id)
		payload = binary.BigEndian.AppendUint16(payload, field.length)
	}
	return payload
}

func dataFlowSet(templateID uint16, record []byte, padding int, nonZero bool) []byte {
	payload := append([]byte(nil), record...)
	for range padding {
		value := byte(0)
		if nonZero {
			value = 0xa5
		}
		payload = append(payload, value)
	}
	return flowSet(templateID, payload)
}

func padToFour(data []byte, nonZero bool) []byte {
	padding := (4 - len(data)%4) % 4
	result := append([]byte(nil), data...)
	for range padding {
		value := byte(0)
		if nonZero {
			value = 0xa5
		}
		result = append(result, value)
	}
	return result
}

func uintBytes(value uint64, width int) []byte {
	result := make([]byte, width)
	for index := width - 1; index >= 0; index-- {
		result[index] = byte(value)
		value >>= 8
	}
	return result
}

func checkedUint16(value int) uint16 {
	if value < 0 || value > math.MaxUint16 {
		panic("test fixture exceeds uint16")
	}
	return uint16(value)
}

func TestDecoder_RunCleanup(t *testing.T) {
	t.Parallel()

	decoder := newTestDecoder(t, Config{
		CleanupInterval: time.Millisecond,
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := decoder.RunCleanup(ctx)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}
