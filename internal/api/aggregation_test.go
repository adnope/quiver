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

func TestAggregationCursorPagination(t *testing.T) {
	t.Parallel()

	store := &fakeAggregationStore{
		talkers: []postgres.TopTalkerRow{
			{IP: netip.MustParseAddr("192.168.1.10"), Metric: postgres.AggregationMetricBytes, Value: 100, FlowCount: 2},
			{IP: netip.MustParseAddr("192.168.1.20"), Metric: postgres.AggregationMetricBytes, Value: 90, FlowCount: 1},
		},
	}
	handler := newQueryTestServer(t, nil, store)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest(
		"/api/v1/aggregations/top-talkers?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z&direction=src&limit=1",
		"query-key",
	))
	if recorder.Code != http.StatusOK {
		t.Fatalf("first page status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var firstPage TopTalkersResponse
	decodeJSON(t, recorder, &firstPage)
	if len(firstPage.Items) != 1 || firstPage.NextCursor == "" || firstPage.Limit != 1 {
		t.Fatalf("first page = %+v", firstPage)
	}
	if store.lastTalkers.Limit != 2 {
		t.Fatalf("store limit = %d, want limit+1", store.lastTalkers.Limit)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest(
		"/api/v1/aggregations/top-talkers?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z&direction=src&limit=1&cursor="+firstPage.NextCursor,
		"query-key",
	))
	if recorder.Code != http.StatusOK {
		t.Fatalf("second page status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if store.lastTalkers.Cursor == nil || store.lastTalkers.Cursor.IP == nil || store.lastTalkers.Cursor.IP.String() != "192.168.1.10" {
		t.Fatalf("decoded cursor = %+v", store.lastTalkers.Cursor)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, newQueryRequest(
		"/api/v1/aggregations/top-ports?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z&direction=src&limit=1&cursor="+firstPage.NextCursor,
		"query-key",
	))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("wrong endpoint cursor status = %d", recorder.Code)
	}
	var errResponse ErrorResponse
	decodeJSON(t, recorder, &errResponse)
	if errResponse.Error.Code != CodeInvalidCursor {
		t.Fatalf("error code = %q", errResponse.Error.Code)
	}
}

type fakeAggregationStore struct {
	talkers       []postgres.TopTalkerRow
	ports         []postgres.TopPortRow
	protocols     []postgres.ProtocolRow
	lastTalkers   postgres.AggregationQuery
	lastPorts     postgres.AggregationQuery
	lastProtocols postgres.AggregationQuery
}

func (s *fakeAggregationStore) TopTalkers(_ context.Context, query postgres.AggregationQuery) ([]postgres.TopTalkerRow, error) {
	s.lastTalkers = query
	return s.talkers, nil
}

func (s *fakeAggregationStore) TopPorts(_ context.Context, query postgres.AggregationQuery) ([]postgres.TopPortRow, error) {
	s.lastPorts = query
	return s.ports, nil
}

func (s *fakeAggregationStore) ProtocolDistribution(_ context.Context, query postgres.AggregationQuery) ([]postgres.ProtocolRow, error) {
	s.lastProtocols = query
	return s.protocols, nil
}
