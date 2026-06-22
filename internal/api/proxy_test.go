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

	"github.com/adnope/quiver/internal/config"
)

type mockCollector struct {
	mu      sync.Mutex
	packets []mockPacket
	err     error
}

type mockPacket struct {
	SourceIP   netip.Addr
	SourceHost string
	Data       []byte
}

func (c *mockCollector) HandlePacket(ctx context.Context, sourceIP netip.Addr, sourceHost string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.packets = append(c.packets, mockPacket{
		SourceIP:   sourceIP,
		SourceHost: sourceHost,
		Data:       data,
	})
	return c.err
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
	server, err := NewServerWithCollectors(cfg, nil, nil, nil, env, nil, StaticHealthChecker{Value: HealthOK}, []InjectableCollector{collector})
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
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader(bodyBytes))
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
	server, err := NewServerWithCollectors(cfg, nil, nil, nil, env, nil, StaticHealthChecker{Value: HealthOK}, []InjectableCollector{collector})
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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/proxy-netflow", &buf)
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
	server, err := NewServerWithCollectors(cfg, nil, nil, nil, env, nil, StaticHealthChecker{Value: HealthOK}, []InjectableCollector{collector})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	t.Run("invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader([]byte("{invalid-json")))
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
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader(bodyBytes))
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
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader(bodyBytes))
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
		[]InjectableCollector{&mockCollector{}},
	)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	req := httptest.NewRequest(
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
		[]InjectableCollector{&mockCollector{}},
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
	req = httptest.NewRequest(http.MethodPost, "/api/v1/ingest/proxy-netflow", bytes.NewReader(body))
	req.Header.Set(APIKeyHeader, "valid-gateway-key")
	w = httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized batch status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
