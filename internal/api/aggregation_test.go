package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/adnope/quiver/internal/domain"
	"github.com/adnope/quiver/internal/storage/postgres"
)

func TestAggregationEndpoints(t *testing.T) {
	t.Parallel()

	store := &fakeAggregationStore{
		talkers: []postgres.TopTalkerRow{{
			IP:        netip.MustParseAddr("192.168.1.10"),
			Metric:    postgres.AggregationMetricBytes,
			Value:     100,
			FlowCount: 2,
		}},
		ports: []postgres.TopPortRow{{
			Port:      53,
			Metric:    postgres.AggregationMetricPackets,
			Value:     7,
			FlowCount: 3,
		}},
		protocols: []postgres.ProtocolRow{{
			ProtocolNumber:    17,
			TransportProtocol: domain.TransportProtocolUDP,
			Metric:            postgres.AggregationMetricFlows,
			Value:             5,
			FlowCount:         5,
		}},
	}
	handler := newQueryTestServer(t, &fakeFlowStore{}, store)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest("/api/v1/aggregations/top-talkers?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z", "query-key"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("missing direction status = %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest(
		"/api/v1/aggregations/top-talkers?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z&direction=src&src_ip=192.168.1.10",
		"query-key",
	))
	if recorder.Code != http.StatusOK {
		t.Fatalf("top-talkers status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var talkers TopTalkersResponse
	decodeJSON(t, recorder, &talkers)
	if len(talkers.Items) != 1 || talkers.Items[0].Metric != "bytes" || talkers.Limit != 20 {
		t.Fatalf("talkers = %+v", talkers)
	}
	if store.lastTalkers.SrcIP == nil || store.lastTalkers.Metric != postgres.AggregationMetricBytes {
		t.Fatalf("last talkers query = %+v", store.lastTalkers)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest(
		"/api/v1/aggregations/top-ports?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z&direction=dst&metric=packets",
		"query-key",
	))
	if recorder.Code != http.StatusOK {
		t.Fatalf("top-ports status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var ports TopPortsResponse
	decodeJSON(t, recorder, &ports)
	if len(ports.Items) != 1 || ports.Items[0].Port != 53 {
		t.Fatalf("ports = %+v", ports)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest(
		"/api/v1/aggregations/protocols?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z&metric=flows",
		"query-key",
	))
	if recorder.Code != http.StatusOK {
		t.Fatalf("protocols status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var protocols ProtocolsResponse
	decodeJSON(t, recorder, &protocols)
	if len(protocols.Items) != 1 || protocols.Items[0].ProtocolNumber != 17 || protocols.Items[0].Metric != "flows" {
		t.Fatalf("protocols = %+v", protocols)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest(
		"/api/v1/aggregations/protocols?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z&metric=bad",
		"query-key",
	))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid metric status = %d", recorder.Code)
	}
}

type fakeAggregationStore struct {
	talkers     []postgres.TopTalkerRow
	ports       []postgres.TopPortRow
	protocols   []postgres.ProtocolRow
	lastTalkers postgres.AggregationQuery
}

func (s *fakeAggregationStore) TopTalkers(_ context.Context, query postgres.AggregationQuery) ([]postgres.TopTalkerRow, error) {
	s.lastTalkers = query
	return s.talkers, nil
}

func (s *fakeAggregationStore) TopPorts(context.Context, postgres.AggregationQuery) ([]postgres.TopPortRow, error) {
	return s.ports, nil
}

func (s *fakeAggregationStore) ProtocolDistribution(context.Context, postgres.AggregationQuery) ([]postgres.ProtocolRow, error) {
	return s.protocols, nil
}
