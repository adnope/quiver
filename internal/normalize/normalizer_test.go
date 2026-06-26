package normalize

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
	"github.com/adnope/quiver/internal/validation"
)

func TestNormalizeRESTFlow(t *testing.T) {
	t.Parallel()

	event := rawRESTEvent(t)
	record, err := NormalizeRawEvent(event, testOptions())
	if err != nil {
		t.Fatalf("NormalizeRawEvent(rest) error = %v", err)
	}

	if record.SourceType != domain.SourceTypeRESTJSON || record.SourceHost != "rest-client-host" {
		t.Fatalf("source metadata = %s/%s", record.SourceType, record.SourceHost)
	}
	if record.SourceIP == nil || record.SourceIP.String() != "203.0.113.10" {
		t.Fatalf("source_ip = %v", record.SourceIP)
	}
	if record.SrcIP.String() != "192.168.1.10" || record.DstIP.String() != "8.8.8.8" {
		t.Fatalf("tuple = %s -> %s", record.SrcIP, record.DstIP)
	}
	if record.TransportProtocol != domain.TransportProtocolUDP || record.ProtocolNumber != 17 {
		t.Fatalf("protocol = %s/%d", record.TransportProtocol, record.ProtocolNumber)
	}
	if record.Direction != domain.DirectionOutbound {
		t.Fatalf("direction = %q", record.Direction)
	}
	if record.Bytes == nil || *record.Bytes != 420 || record.Packets == nil || *record.Packets != 3 {
		t.Fatalf("counters = %v/%v", record.Bytes, record.Packets)
	}
	assertJSONRaw(t, record.Attributes["token"], `"***MASKED***"`)
	if record.NormalizationStatus != domain.NormalizationStatusOK {
		t.Fatalf("status = %q", record.NormalizationStatus)
	}
}

func TestNormalizeRESTIdempotency(t *testing.T) {
	t.Parallel()

	first, err := NormalizeRawEvent(rawRESTEvent(t), testOptions())
	if err != nil {
		t.Fatalf("first normalize error = %v", err)
	}
	second, err := NormalizeRawEvent(rawRESTEvent(t), testOptions())
	if err != nil {
		t.Fatalf("second normalize error = %v", err)
	}
	if first.IdempotencyKey != second.IdempotencyKey {
		t.Fatalf("idempotency keys differ: %q != %q", first.IdempotencyKey, second.IdempotencyKey)
	}

	noExternal := rawRESTEvent(t)
	noExternal.Payload.GetRestFlow().ExternalId = nil
	a, err := NormalizeRawEvent(noExternal, testOptions())
	if err != nil {
		t.Fatalf("normalize no external id error = %v", err)
	}
	b, err := NormalizeRawEvent(noExternal, testOptions())
	if err != nil {
		t.Fatalf("normalize no external id second error = %v", err)
	}
	if a.IdempotencyKey != b.IdempotencyKey {
		t.Fatalf("tuple fallback idempotency keys differ")
	}
}

func TestNormalizeZeekFlowAndPartialCounters(t *testing.T) {
	t.Parallel()

	event := rawZeekEvent(t)
	record, err := NormalizeRawEvent(event, testOptions())
	if err != nil {
		t.Fatalf("NormalizeRawEvent(zeek) error = %v", err)
	}
	if record.EventStartTime.Format(time.RFC3339Nano) != "2026-06-16T10:15:20.123Z" {
		t.Fatalf("event_start_time = %s", record.EventStartTime.Format(time.RFC3339Nano))
	}
	if record.DurationMS == nil || *record.DurationMS != 45 {
		t.Fatalf("duration_ms = %v", record.DurationMS)
	}
	if record.EventEndTime == nil || record.EventEndTime.Format(time.RFC3339Nano) != "2026-06-16T10:15:20.168Z" {
		t.Fatalf("event_end_time = %v", record.EventEndTime)
	}
	if record.Bytes == nil || *record.Bytes != 180 || record.Packets == nil || *record.Packets != 2 {
		t.Fatalf("counters = %v/%v", record.Bytes, record.Packets)
	}
	if record.ApplicationProtocol == nil || *record.ApplicationProtocol != "dns" {
		t.Fatalf("application_protocol = %v", record.ApplicationProtocol)
	}
	if record.FlowState == nil || *record.FlowState != "SF" {
		t.Fatalf("flow_state = %v", record.FlowState)
	}

	partial := rawZeekEvent(t)
	partial.Payload.GetZeekConn().RespBytes = nil
	partial.Payload.GetZeekConn().RespPkts = nil
	record, err = NormalizeRawEvent(partial, testOptions())
	if err != nil {
		t.Fatalf("NormalizeRawEvent(partial zeek) error = %v", err)
	}
	if record.Bytes != nil || record.Packets != nil {
		t.Fatalf("partial counters should be nil, got %v/%v", record.Bytes, record.Packets)
	}
	assertJSONRaw(t, record.Attributes["bytes_partial"], `true`)
	assertJSONRaw(t, record.Attributes["packets_partial"], `true`)
	if record.NormalizationStatus != domain.NormalizationStatusPartial {
		t.Fatalf("status = %q", record.NormalizationStatus)
	}
}

func TestNormalizeNetFlowV5(t *testing.T) {
	t.Parallel()

	event := rawNetFlowEvent(t)
	record, err := NormalizeRawEvent(event, testOptions())
	if err != nil {
		t.Fatalf("NormalizeRawEvent(netflow) error = %v", err)
	}
	if record.TransportProtocol != domain.TransportProtocolTCP || record.ProtocolNumber != 6 {
		t.Fatalf("protocol = %s/%d", record.TransportProtocol, record.ProtocolNumber)
	}
	if record.EventStartTime.Format(time.RFC3339) != "2026-06-16T10:15:11Z" ||
		record.EventEndTime == nil ||
		record.EventEndTime.Format(time.RFC3339) != "2026-06-16T10:15:12Z" {
		t.Fatalf("times = %s/%v", record.EventStartTime, record.EventEndTime)
	}
	if record.DurationMS == nil || *record.DurationMS != 1000 {
		t.Fatalf("duration_ms = %v", record.DurationMS)
	}
	if record.InputInterface == nil || *record.InputInterface != 2 ||
		record.OutputInterface == nil || *record.OutputInterface != 3 {
		t.Fatalf("interfaces = %v/%v", record.InputInterface, record.OutputInterface)
	}
	if record.NextHopIP == nil || record.NextHopIP.String() != "192.168.1.1" {
		t.Fatalf("next_hop = %v", record.NextHopIP)
	}
	if record.SamplingRate == nil || *record.SamplingRate != 100 {
		t.Fatalf("sampling_rate = %v", record.SamplingRate)
	}
}

func TestNormalizeNetFlowV5TimestampFallbackAndUnknownProtocol(t *testing.T) {
	t.Parallel()

	event := rawNetFlowEvent(t)
	flow := event.Payload.GetNetflowV5()
	flow.ExporterUnixTime = nil
	flow.ExporterUptimeMs = nil
	flow.ProtocolNumber = 132
	flow.SrcPort = nil
	flow.DstPort = nil

	record, err := NormalizeRawEvent(event, testOptions())
	if err != nil {
		t.Fatalf("NormalizeRawEvent(netflow fallback) error = %v", err)
	}
	if !record.EventStartTime.Equal(event.GetReceivedAt().AsTime()) {
		t.Fatalf("fallback start = %s, want received_at", record.EventStartTime)
	}
	if record.TransportProtocol != domain.TransportProtocolUnknown || record.ProtocolNumber != 0 {
		t.Fatalf("protocol = %s/%d", record.TransportProtocol, record.ProtocolNumber)
	}
	assertJSONRaw(t, record.Attributes["timestamp_fallback"], `"received_at"`)
	if record.NormalizationStatus != domain.NormalizationStatusPartial {
		t.Fatalf("status = %q", record.NormalizationStatus)
	}
}

func TestNewDeadLetterEventForNormalizationFailure(t *testing.T) {
	t.Parallel()

	event := rawZeekEvent(t)
	event.Payload.GetZeekConn().IdOrigH = "not-an-ip"
	_, err := NormalizeRawEvent(event, testOptions())
	if err == nil {
		t.Fatal("expected normalization error")
	}

	deadLetter, buildErr := NewDeadLetterEvent(
		event,
		err,
		time.Date(2026, 6, 16, 10, 15, 30, 0, time.UTC),
	)
	if buildErr != nil {
		t.Fatalf("NewDeadLetterEvent() error = %v", buildErr)
	}
	if deadLetter.GetStage() != flowv1.IngestionStage_INGESTION_STAGE_NORMALIZER {
		t.Fatalf("stage = %s", deadLetter.GetStage())
	}
	if deadLetter.GetError().GetErrorCode() != normalizationFailureCode {
		t.Fatalf("error_code = %q", deadLetter.GetError().GetErrorCode())
	}
	if !strings.Contains(deadLetter.GetError().GetErrorMessage(), "id.orig_h") {
		t.Fatalf("error_message = %q", deadLetter.GetError().GetErrorMessage())
	}
	if deadLetter.GetRawEvent().GetEventId() != event.GetEventId() {
		t.Fatalf("raw event not attached")
	}
	if err := validation.ValidateDeadLetterEvent(deadLetter); err != nil {
		t.Fatalf("dead-letter validation failed: %v", err)
	}
}

func testOptions() Options {
	return Options{
		Now: func() time.Time {
			return time.Date(2026, 6, 16, 10, 15, 30, 0, time.UTC)
		},
		LocalNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
	}
}

func rawRESTEvent(t *testing.T) *flowv1.RawFlowEventEnvelope {
	t.Helper()

	attrs, err := structpb.NewStruct(map[string]any{"token": "secret", "integration": "demo"})
	if err != nil {
		t.Fatalf("attributes: %v", err)
	}
	sourceIP := "203.0.113.10"
	externalID := "client-flow-0001"
	applicationProtocol := "dns"
	bytesValue := uint64(420)
	packets := uint64(3)
	srcPort := uint32(51524)
	dstPort := uint32(53)
	start := timestamppb.New(time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC))
	end := timestamppb.New(time.Date(2026, 6, 16, 10, 15, 25, 0, time.UTC))
	return &flowv1.RawFlowEventEnvelope{
		EventId:       "01934d7c-79b4-7000-8b69-001122334455",
		SchemaVersion: domain.RawSchemaVersion,
		Source: &flowv1.SourceIdentity{
			CollectorId: "rest-ingest-main",
			SourceType:  flowv1.SourceType_SOURCE_TYPE_REST_JSON,
			SourceHost:  "rest-client-host",
			SourceIp:    &sourceIP,
		},
		ReceivedAt:   timestamppb.New(time.Date(2026, 6, 16, 10, 15, 19, 0, time.UTC)),
		PartitionKey: "rest-ingest-main:rest-client-host",
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_RestFlow{
				RestFlow: &flowv1.RestFlowInput{
					ExternalId:          &externalID,
					EventStartTime:      start,
					EventEndTime:        end,
					ApplicationProtocol: &applicationProtocol,
					Tuple: &flowv1.NetworkTuple{
						SrcIp:             new("192.168.1.10"),
						DstIp:             new("8.8.8.8"),
						SrcPort:           &srcPort,
						DstPort:           &dstPort,
						TransportProtocol: flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UDP,
						ProtocolNumber:    17,
					},
					Counters:   &flowv1.CounterFields{Bytes: &bytesValue, Packets: &packets},
					Attributes: attrs,
				},
			},
		},
	}
}

func rawZeekEvent(t *testing.T) *flowv1.RawFlowEventEnvelope {
	t.Helper()

	service := "dns"
	duration := 0.045
	origBytes := uint64(60)
	respBytes := uint64(120)
	origPkts := uint64(1)
	respPkts := uint64(1)
	connState := "SF"
	history := "Dd"
	localOrig := true
	return &flowv1.RawFlowEventEnvelope{
		EventId:       "01934d7c-79b4-7000-8b69-001122334456",
		SchemaVersion: domain.RawSchemaVersion,
		Source: &flowv1.SourceIdentity{
			CollectorId: "zeek-conn-01",
			SourceType:  flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON,
			SourceHost:  "zeek-probe-01",
		},
		ReceivedAt:   timestamppb.New(time.Date(2026, 6, 16, 10, 15, 21, 0, time.UTC)),
		PartitionKey: "zeek-conn-01:zeek-probe-01",
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_ZeekConn{
				ZeekConn: &flowv1.ZeekConnFlow{
					Ts:        1781604920.123,
					Uid:       "CAbCdEf123",
					IdOrigH:   "192.168.1.10",
					IdOrigP:   new(uint32(51524)),
					IdRespH:   "8.8.8.8",
					IdRespP:   new(uint32(53)),
					Proto:     "udp",
					Service:   &service,
					Duration:  &duration,
					OrigBytes: &origBytes,
					RespBytes: &respBytes,
					OrigPkts:  &origPkts,
					RespPkts:  &respPkts,
					ConnState: &connState,
					History:   &history,
					LocalOrig: &localOrig,
				},
			},
		},
	}
}

func rawNetFlowEvent(t *testing.T) *flowv1.RawFlowEventEnvelope {
	t.Helper()

	sourceIP := "10.10.0.1"
	nextHop := "192.168.1.1"
	inputIface := uint32(2)
	outputIface := uint32(3)
	srcPort := uint32(51524)
	dstPort := uint32(443)
	exporterUptime := uint32(10000)
	sampling := uint32(100)
	srcAS := uint32(64512)
	return &flowv1.RawFlowEventEnvelope{
		EventId:       "01934d7c-79b4-7000-8b69-001122334457",
		SchemaVersion: domain.RawSchemaVersion,
		Source: &flowv1.SourceIdentity{
			CollectorId: "netflow-main",
			SourceType:  flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5,
			SourceHost:  "router-core-01",
			SourceIp:    &sourceIP,
		},
		ReceivedAt:   timestamppb.New(time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC)),
		PartitionKey: "netflow-main:router-core-01",
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_NetflowV5{
				NetflowV5: &flowv1.NetFlowV5Flow{
					PacketSequence:   42,
					RecordIndex:      7,
					SrcAddr:          "192.168.1.10",
					DstAddr:          "8.8.8.8",
					NextHop:          &nextHop,
					InputInterface:   &inputIface,
					OutputInterface:  &outputIface,
					Packets:          3,
					Bytes:            420,
					FirstSwitchedMs:  1000,
					LastSwitchedMs:   2000,
					ExporterUnixTime: timestamppb.New(time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC)),
					ExporterUptimeMs: &exporterUptime,
					SrcPort:          &srcPort,
					DstPort:          &dstPort,
					TcpFlags:         18,
					ProtocolNumber:   6,
					SrcAs:            &srcAS,
					SamplingRate:     &sampling,
				},
			},
		},
	}
}

func assertJSONRaw(t *testing.T, got json.RawMessage, expected string) {
	t.Helper()

	var gotValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("unmarshal got %q: %v", got, err)
	}
	var expectedValue any
	if err := json.Unmarshal([]byte(expected), &expectedValue); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}
	gotData, _ := json.Marshal(gotValue)
	expectedData, _ := json.Marshal(expectedValue)
	if string(gotData) != string(expectedData) {
		t.Fatalf("json = %s, want %s", gotData, expectedData)
	}
}

func TestNormalizerEdgeCases(t *testing.T) {
	t.Run("domainSourceType mappings", func(t *testing.T) {
		types := []struct {
			proto   flowv1.SourceType
			domain  domain.SourceType
			wantErr bool
		}{
			{flowv1.SourceType_SOURCE_TYPE_NETFLOW_V5, domain.SourceTypeNetFlowV5, false},
			{flowv1.SourceType_SOURCE_TYPE_ZEEK_CONN_JSON, domain.SourceTypeZeekConnJSON, false},
			{flowv1.SourceType_SOURCE_TYPE_REST_JSON, domain.SourceTypeRESTJSON, false},
			{flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9, domain.SourceTypeNetFlowV9, false},
			{flowv1.SourceType_SOURCE_TYPE_SYSLOG_CEF, domain.SourceTypeSyslogCEF, false},
			{flowv1.SourceType_SOURCE_TYPE_SYSLOG_LEEF, domain.SourceTypeSyslogLEEF, false},
			{flowv1.SourceType_SOURCE_TYPE_SURICATA_EVE_JSON, domain.SourceTypeSuricataEVE, false},
			{flowv1.SourceType_SOURCE_TYPE_UNSPECIFIED, "", true},
		}
		for _, tc := range types {
			res, err := domainSourceType(tc.proto)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error for proto %v", tc.proto)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for proto %v: %v", tc.proto, err)
				}
				if res != tc.domain {
					t.Errorf("got %v, want %v", res, tc.domain)
				}
			}
		}
	})

	t.Run("domainTransportProtocol mappings", func(t *testing.T) {
		protos := []struct {
			proto  flowv1.TransportProtocol
			domain domain.TransportProtocol
		}{
			{flowv1.TransportProtocol_TRANSPORT_PROTOCOL_TCP, domain.TransportProtocolTCP},
			{flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UDP, domain.TransportProtocolUDP},
			{flowv1.TransportProtocol_TRANSPORT_PROTOCOL_ICMP, domain.TransportProtocolICMP},
			{flowv1.TransportProtocol_TRANSPORT_PROTOCOL_GRE, domain.TransportProtocolGRE},
			{flowv1.TransportProtocol_TRANSPORT_PROTOCOL_ESP, domain.TransportProtocolESP},
			{flowv1.TransportProtocol_TRANSPORT_PROTOCOL_OTHER, domain.TransportProtocolOther},
			{flowv1.TransportProtocol_TRANSPORT_PROTOCOL_UNSPECIFIED, domain.TransportProtocolUnknown},
		}
		for _, tc := range protos {
			res := domainTransportProtocol(tc.proto)
			if res != tc.domain {
				t.Errorf("got %v, want %v", res, tc.domain)
			}
		}
	})

	t.Run("Option fallbacks", func(t *testing.T) {
		event := rawRESTEvent(t)
		opts := Options{} // all nil/empty
		record, err := NormalizeRawEvent(event, opts)
		if err != nil {
			t.Fatalf("NormalizeRawEvent with empty Options failed: %v", err)
		}
		if record.ID == "" {
			t.Error("Expected ID to be generated")
		}
		if len(record.Attributes) == 0 {
			t.Error("Expected attributes to be populated")
		}
	})
}
