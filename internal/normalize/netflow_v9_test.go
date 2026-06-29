package normalize

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/adnope/quiver/internal/domain"
	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

func rawNetFlowV9Event(t *testing.T) *flowv1.RawFlowEventEnvelope {
	t.Helper()

	sourceIP := "10.10.0.1"
	fields, err := structpb.NewStruct(map[string]any{
		"sourceIPv4Address":        "192.168.1.10",
		"destinationIPv4Address":   "8.8.8.8",
		"sourceTransportPort":      "51524",
		"destinationTransportPort": "443",
		"protocolIdentifier":       "6",
		"octetDeltaCount":          "420",
		"packetDeltaCount":         "3",
		"tcpControlBits":           "18",
		"flowStartSysUpTime":       "1000",
		"flowEndSysUpTime":         "2000",
		"ingressInterface":         "2",
		"egressInterface":          "3",
		"ipClassOfService":         "46",
	})
	if err != nil {
		t.Fatalf("fields structpb: %v", err)
	}

	return &flowv1.RawFlowEventEnvelope{
		EventId:       "01934d7c-79b4-7000-8b69-001122334458",
		SchemaVersion: domain.RawSchemaVersion,
		Source: &flowv1.SourceIdentity{
			CollectorId: "netflow-v9-main",
			SourceType:  flowv1.SourceType_SOURCE_TYPE_NETFLOW_V9,
			SourceHost:  "router-v9-01",
			SourceIp:    &sourceIP,
		},
		ReceivedAt:   timestamppb.New(time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC)),
		PartitionKey: "netflow-v9-main:router-v9-01",
		Payload: &flowv1.RawEventPayload{
			Payload: &flowv1.RawEventPayload_NetflowV9{
				NetflowV9: &flowv1.NetFlowV9Flow{
					PacketSequence:   42,
					RecordIndex:      7,
					SourceId:         1,
					TemplateId:       256,
					ExporterUnixTime: timestamppb.New(time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC)),
					ExporterUptimeMs: 10000,
					Fields:           fields,
				},
			},
		},
	}
}

func TestNormalizeNetFlowV9(t *testing.T) {
	t.Parallel()

	event := rawNetFlowV9Event(t)
	record, err := NormalizeRawEvent(event, testOptions())
	if err != nil {
		t.Fatalf("NormalizeRawEvent(netflow_v9) error = %v", err)
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
	if record.Bytes == nil || *record.Bytes != 420 || record.Packets == nil || *record.Packets != 3 {
		t.Fatalf("counters = %v/%v", record.Bytes, record.Packets)
	}
	if record.TCPFlags == nil || *record.TCPFlags != 18 {
		t.Fatalf("tcp_flags = %v", record.TCPFlags)
	}
	assertJSONRaw(t, record.Attributes["tos"], `46`)
	assertJSONRaw(t, record.Attributes["source_id"], `1`)
	assertJSONRaw(t, record.Attributes["template_id"], `256`)
	assertJSONRaw(t, record.Attributes["record_index"], `7`)
}

func TestNormalizeNetFlowV9TimestampFallback(t *testing.T) {
	t.Parallel()

	event := rawNetFlowV9Event(t)
	flow := event.Payload.GetNetflowV9()
	flow.ExporterUnixTime = nil
	flow.ExporterUptimeMs = 0

	record, err := NormalizeRawEvent(event, testOptions())
	if err != nil {
		t.Fatalf("NormalizeRawEvent(netflow_v9 fallback) error = %v", err)
	}
	if !record.EventStartTime.Equal(event.GetReceivedAt().AsTime()) {
		t.Fatalf("fallback start = %s, want received_at", record.EventStartTime)
	}
	assertJSONRaw(t, record.Attributes["timestamp_fallback"], `"received_at"`)
}

func TestNormalizeNetFlowV9MissingSrcDst(t *testing.T) {
	t.Parallel()

	event := rawNetFlowV9Event(t)
	event.Payload.GetNetflowV9().Fields = &structpb.Struct{} // Empty fields

	_, err := NormalizeRawEvent(event, testOptions())
	if err == nil {
		t.Fatal("expected normalization error for missing src/dst IP")
	}
}
