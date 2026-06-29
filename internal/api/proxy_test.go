package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/collector"
	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/observability"
)

type mockCollector struct {
	mu      sync.Mutex
	packets []mockPacket
	err     error
	result  collector.PacketResult
	results []collector.PacketResult
}

type mockPacket struct {
	SourceIP   netip.Addr
	SourceHost string
	Data       []byte
	ReceivedAt time.Time
	ProxyTime  *time.Time
}

func (c *mockCollector) HandlePacket(
	_ context.Context,
	_ map[string]struct{},
	input collector.PacketInput,
) (collector.PacketResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.packets = append(c.packets, mockPacket{
		SourceIP:   input.SourceIP,
		SourceHost: input.SourceHost,
		Data:       input.Data,
		ReceivedAt: input.ReceivedAt,
		ProxyTime:  input.ProxyReceivedAt,
	})
	if c.err != nil {
		return collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "internal_error"}, c.err
	}
	if c.result.Status != "" {
		return c.result, nil
	}
	if len(c.results) >= len(c.packets) {
		return c.results[len(c.packets)-1], nil
	}
	return collector.PacketResult{Status: collector.PacketAccepted}, nil
}

func (c *mockCollector) getPackets() []mockPacket {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]mockPacket, len(c.packets))
	copy(out, c.packets)
	return out
}

func TestProxyHandlerAuthentication(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	cfg.QuiverClientGateways = []config.QuiverClientGatewayConfig{
		{
			Name:       "client-1",
			SourceHost: "gateway-host-01",
			KeyEnv:     "CLIENT_GATEWAY_KEY",
		},
	}
	cfg.API.RateLimits.Ingest.RequestsPerMinute = 60

	env := func(key string) string {
		if key == "CLIENT_GATEWAY_KEY" {
			return "valid-gateway-key"
		}
		return ""
	}

	collector := &mockCollector{}
	server, err := NewServerWithCollectors(cfg, nil, nil, nil, env, nil, StaticHealthChecker{Value: HealthOK}, collector)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	tests := []struct {
		name       string
		apiKey     string
		wantStatus int
	}{
		{
			name:       "missing api key",
			apiKey:     "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid api key",
			apiKey:     "invalid-key",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "valid api key",
			apiKey:     "valid-gateway-key",
			wantStatus: http.StatusAccepted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(ProxyRequest{
				Records: []ProxyRecord{
					{
						SourceIP:   "192.168.1.1",
						PacketData: base64.StdEncoding.EncodeToString([]byte("test")),
						ReceivedAt: time.Now(),
					},
				},
			})
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			if tt.apiKey != "" {
				req.Header.Set(APIKeyHeader, tt.apiKey)
			}

			w := httptest.NewRecorder()
			server.Handler().ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestProxyHandlerReturnsUnavailableWithoutCollector(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	cfg.QuiverClientGateways = []config.QuiverClientGatewayConfig{{
		Name:       "client-1",
		SourceHost: "gateway-host-01",
		KeyEnv:     "CLIENT_GATEWAY_KEY",
	}}
	cfg.API.RateLimits.Ingest.RequestsPerMinute = 60
	env := func(key string) string {
		if key == "CLIENT_GATEWAY_KEY" {
			return "valid-gateway-key"
		}
		return ""
	}
	server, err := NewServerWithCollectors(cfg, nil, nil, nil, env, nil, StaticHealthChecker{Value: HealthOK}, nil)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	bodyBytes, _ := json.Marshal(ProxyRequest{Records: []ProxyRecord{{SourceIP: "192.0.2.1", PacketData: "AA=="}}})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader(bodyBytes))
	req.Header.Set(APIKeyHeader, "valid-gateway-key")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestProxyHandlerGzipAndValidPayload(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	cfg.QuiverClientGateways = []config.QuiverClientGatewayConfig{
		{
			Name:       "client-1",
			SourceHost: "gateway-host-01",
			KeyEnv:     "CLIENT_GATEWAY_KEY",
		},
	}
	cfg.API.RateLimits.Ingest.RequestsPerMinute = 60

	env := func(key string) string {
		if key == "CLIENT_GATEWAY_KEY" {
			return "valid-gateway-key"
		}
		return ""
	}

	collector := &mockCollector{}
	server, err := NewServerWithCollectors(cfg, nil, nil, nil, env, nil, StaticHealthChecker{Value: HealthOK}, collector)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	payload := ProxyRequest{
		Records: []ProxyRecord{
			{
				SourceIP:   "10.0.0.5",
				PacketData: base64.StdEncoding.EncodeToString([]byte("payload-1")),
				ReceivedAt: time.Now(),
			},
			{
				SourceIP:   "172.16.0.100",
				PacketData: base64.StdEncoding.EncodeToString([]byte("payload-2")),
				ReceivedAt: time.Now(),
			},
		},
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gw).Encode(payload); err != nil {
		t.Fatalf("failed to gzip payload: %v", err)
	}
	_ = gw.Close()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/proxy-netflow", &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set(APIKeyHeader, "valid-gateway-key")

	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp map[string]int
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["accepted"] != 2 || resp["rejected"] != 0 {
		t.Errorf("expected 2 accepted, 0 rejected; got %+v", resp)
	}

	packets := collector.getPackets()
	if len(packets) != 2 {
		t.Fatalf("expected 2 packet, got %d", len(packets))
	}

	if packets[0].SourceIP != netip.MustParseAddr("10.0.0.5") || packets[0].SourceHost != "gateway-host-01" || string(packets[0].Data) != "payload-1" {
		t.Errorf("packet 0 mismatch: %+v", packets[0])
	}
	if packets[1].SourceIP != netip.MustParseAddr("172.16.0.100") || packets[1].SourceHost != "gateway-host-01" || string(packets[1].Data) != "payload-2" {
		t.Errorf("packet 1 mismatch: %+v", packets[1])
	}
}

func TestProxyHandlerValidationAndErrors(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	cfg.QuiverClientGateways = []config.QuiverClientGatewayConfig{
		{
			Name:       "client-1",
			SourceHost: "gateway-host-01",
			KeyEnv:     "CLIENT_GATEWAY_KEY",
		},
	}
	cfg.API.RateLimits.Ingest.RequestsPerMinute = 60

	env := func(key string) string {
		if key == "CLIENT_GATEWAY_KEY" {
			return "valid-gateway-key"
		}
		return ""
	}

	collector := &mockCollector{}
	server, err := NewServerWithCollectors(cfg, nil, nil, nil, env, nil, StaticHealthChecker{Value: HealthOK}, collector)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	t.Run("invalid json", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader([]byte("{invalid-json")))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(APIKeyHeader, "valid-gateway-key")

		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.Code)
		}
	})

	t.Run("invalid base64 data and invalid IP", func(t *testing.T) {
		payload := ProxyRequest{
			Records: []ProxyRecord{
				{
					SourceIP:   "10.0.0.1",
					PacketData: "!!!invalid-base64!!!",
					ReceivedAt: time.Now(),
				},
				{
					SourceIP:   "invalid-ip-address",
					PacketData: base64.StdEncoding.EncodeToString([]byte("payload-2")),
					ReceivedAt: time.Now(),
				},
				{
					SourceIP:   "10.0.0.2",
					PacketData: base64.StdEncoding.EncodeToString([]byte("payload-3")),
					ReceivedAt: time.Now(),
				},
			},
		}

		bodyBytes, _ := json.Marshal(payload)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(APIKeyHeader, "valid-gateway-key")

		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusAccepted {
			t.Fatalf("status = %d", w.Code)
		}

		var resp map[string]int
		_ = json.NewDecoder(w.Body).Decode(&resp)

		if resp["accepted"] != 1 || resp["rejected"] != 2 {
			t.Errorf("expected 1 accepted, 2 rejected; got %+v", resp)
		}
	})

	t.Run("collector failure", func(t *testing.T) {
		collector.err = errors.New("pipeline error")
		defer func() { collector.err = nil }()

		payload := ProxyRequest{
			Records: []ProxyRecord{
				{
					SourceIP:   "10.0.0.3",
					PacketData: base64.StdEncoding.EncodeToString([]byte("payload-err")),
					ReceivedAt: time.Now(),
				},
			},
		}

		bodyBytes, _ := json.Marshal(payload)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(APIKeyHeader, "valid-gateway-key")

		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusAccepted {
			t.Fatalf("status = %d", w.Code)
		}

		var resp map[string]int
		_ = json.NewDecoder(w.Body).Decode(&resp)

		if resp["accepted"] != 0 || resp["rejected"] != 1 {
			t.Errorf("expected 0 accepted, 1 rejected; got %+v", resp)
		}
	})
}

func TestProxyHandlerEnforcesBodyAndBatchLimits(t *testing.T) {
	t.Parallel()

	cfg := config.Config{}
	cfg.API.MaxRequestBodyBytes = 64
	cfg.API.RateLimits.Ingest.RequestsPerMinute = 60
	cfg.QuiverClientGateways = []config.QuiverClientGatewayConfig{{
		Name:       "client-1",
		SourceHost: "gateway-host-01",
		KeyEnv:     "CLIENT_GATEWAY_KEY",
	}}
	env := func(key string) string {
		if key == "CLIENT_GATEWAY_KEY" {
			return "valid-gateway-key"
		}
		return ""
	}
	server, err := NewServerWithCollectors(
		cfg,
		nil,
		nil,
		nil,
		env,
		nil,
		StaticHealthChecker{Value: HealthOK},
		&mockCollector{},
	)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodPost,
		"/api/v1/ingest/proxy-netflow",
		bytes.NewReader([]byte(`{"records":[{"source_ip":"192.0.2.1","packet_data":"`+strings.Repeat("A", 80)+`"}]}`)),
	)
	req.Header.Set(APIKeyHeader, "valid-gateway-key")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}

	cfg.API.MaxRequestBodyBytes = config.DefaultMaxRequestBodyBytes
	server, err = NewServerWithCollectors(
		cfg,
		nil,
		nil,
		nil,
		env,
		nil,
		StaticHealthChecker{Value: HealthOK},
		&mockCollector{},
	)
	if err != nil {
		t.Fatalf("create batch-limit server: %v", err)
	}
	records := make([]ProxyRecord, config.DefaultMaxBatchSize+1)
	for i := range records {
		records[i] = ProxyRecord{SourceIP: "192.0.2.1", PacketData: "AA=="}
	}
	body, err := json.Marshal(ProxyRequest{Records: records})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader(body))
	req.Header.Set(APIKeyHeader, "valid-gateway-key")
	w = httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized batch status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestProxyHandlerV2ReturnsOrderedPerRecordResults(t *testing.T) {
	t.Parallel()

	router := &mockCollector{results: []collector.PacketResult{
		{Status: collector.PacketAccepted},
		{Status: collector.PacketRetryable, ErrorCode: "queue_full"},
	}}
	server := newProxyTestServer(t, router, nil)
	body, err := json.Marshal(ProxyRequest{Records: []ProxyRecord{
		{SourceIP: "192.0.2.1", PacketData: base64.StdEncoding.EncodeToString([]byte("accepted"))},
		{SourceIP: "192.0.2.2", PacketData: "invalid-base64"},
		{SourceIP: "192.0.2.3", PacketData: base64.StdEncoding.EncodeToString([]byte("retryable"))},
	}})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader(body))
	req.Header.Set(APIKeyHeader, "valid-gateway-key")
	req.Header.Set(ProxyProtocolHeader, ProxyProtocolV2)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	var response ProxyV2Response
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("json.Decode() error = %v", err)
	}
	if response.Accepted != 1 || response.Retryable != 1 || response.Rejected != 1 || len(response.Results) != 3 {
		t.Fatalf("response = %+v", response)
	}
	wantStatuses := []collector.PacketStatus{collector.PacketAccepted, collector.PacketRejected, collector.PacketRetryable}
	for index, result := range response.Results {
		if result.Index != index || result.Status != wantStatuses[index] {
			t.Fatalf("result[%d] = %+v", index, result)
		}
	}
	if response.Results[1].ErrorCode != "invalid_base64" || response.Results[2].ErrorCode != "queue_full" {
		t.Fatalf("unexpected error codes: %+v", response.Results)
	}
}

func TestProxyHandlerLegacyResponseCountsRetryableAsRejected(t *testing.T) {
	t.Parallel()

	router := &mockCollector{result: collector.PacketResult{Status: collector.PacketRetryable, ErrorCode: "queue_full"}}
	server := newProxyTestServer(t, router, nil)
	body := []byte(`{"records":[{"source_ip":"192.0.2.1","packet_data":"AAU="}]}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader(body))
	req.Header.Set(APIKeyHeader, "valid-gateway-key")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	var response map[string]json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("json.Decode() error = %v", err)
	}
	if string(response["accepted"]) != "0" || string(response["rejected"]) != "1" {
		t.Fatalf("legacy response = %s", w.Body.String())
	}
	if _, exists := response["retryable"]; exists {
		t.Fatalf("legacy response unexpectedly contains retryable: %s", w.Body.String())
	}
	if _, exists := response["results"]; exists {
		t.Fatalf("legacy response unexpectedly contains results: %s", w.Body.String())
	}
}

func TestProxyHandlerValidatesGatewayTimestampsWithoutRejectingPackets(t *testing.T) {
	t.Parallel()

	metrics := observability.NewRegistry()
	router := &mockCollector{}
	server := newProxyTestServer(t, router, metrics)
	now := time.Now().UTC()
	validTime := now.Add(-time.Minute).Format(time.RFC3339Nano)
	futureTime := now.Add(10 * time.Minute).Format(time.RFC3339Nano)
	body := []byte(`{"records":[` +
		`{"source_ip":"192.0.2.1","packet_data":"AAU=","received_at":"` + validTime + `"},` +
		`{"source_ip":"192.0.2.2","packet_data":"AAU=","received_at":"` + futureTime + `"},` +
		`{"source_ip":"192.0.2.3","packet_data":"AAU=","received_at":"not-a-time"}` +
		`]}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader(body))
	req.Header.Set(APIKeyHeader, "valid-gateway-key")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}

	packets := router.getPackets()
	if len(packets) != 3 {
		t.Fatalf("packet count = %d, want 3", len(packets))
	}
	if packets[0].ProxyTime == nil || !packets[0].ProxyTime.Equal(now.Add(-time.Minute)) {
		t.Fatalf("valid proxy timestamp = %v", packets[0].ProxyTime)
	}
	if packets[1].ProxyTime != nil || packets[2].ProxyTime != nil {
		t.Fatalf("invalid proxy timestamps were retained: %+v", packets)
	}
	metricsBody := string(metrics.WritePrometheus())
	if !strings.Contains(metricsBody, `proxy_netflow_invalid_timestamps_total{reason="future"} 1`) ||
		!strings.Contains(metricsBody, `proxy_netflow_invalid_timestamps_total{reason="invalid"} 1`) {
		t.Fatalf("timestamp metrics missing:\n%s", metricsBody)
	}
}

func newProxyTestServer(t *testing.T, router PacketRouter, metrics *observability.Registry) *Server {
	t.Helper()

	cfg := config.Config{
		API: config.APIConfig{RateLimits: config.RateLimitsConfig{
			Ingest: config.RateLimitConfig{RequestsPerMinute: 60},
		}},
		ProxyNetFlow: config.ProxyNetFlowConfig{CollectorID: "netflow-main"},
		QuiverClientGateways: []config.QuiverClientGatewayConfig{{
			Name:       "client-1",
			SourceHost: "gateway-host-01",
			KeyEnv:     "CLIENT_GATEWAY_KEY",
		}},
	}
	server, err := NewServerWithCollectors(
		cfg,
		nil,
		nil,
		nil,
		func(key string) string {
			if key == "CLIENT_GATEWAY_KEY" {
				return "valid-gateway-key"
			}
			return ""
		},
		metrics,
		StaticHealthChecker{Value: HealthOK},
		router,
	)
	if err != nil {
		t.Fatalf("NewServerWithCollectors() error = %v", err)
	}
	return server
}
