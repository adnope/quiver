package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSendBatchWithRetrySuccess(t *testing.T) {
	t.Parallel()

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Errorf("expected gzip encoding, got %s", r.Header.Get("Content-Encoding"))
		}
		if r.Header.Get("X-API-Key") != "test-api-key" {
			t.Errorf("expected api key test-api-key, got %s", r.Header.Get("X-API-Key"))
		}
		if r.Header.Get("X-Quiver-Proxy-Protocol") != "2" {
			t.Errorf("expected proxy protocol 2, got %s", r.Header.Get("X-Quiver-Proxy-Protocol"))
		}

		gzipReader, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("failed to create gzip reader: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer func() { _ = gzipReader.Close() }()

		var req ProxyRequest
		if err := json.NewDecoder(gzipReader).Decode(&req); err != nil {
			t.Errorf("failed to decode JSON: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if len(req.Records) != 1 {
			t.Errorf("expected 1 record, got %d", len(req.Records))
		}
		if req.Records[0].SourceIP != "10.0.0.1" {
			t.Errorf("expected SourceIP 10.0.0.1, got %s", req.Records[0].SourceIP)
		}
		data, _ := base64.StdEncoding.DecodeString(req.Records[0].PacketData)
		if string(data) != "test-data" {
			t.Errorf("expected PacketData test-data, got %s", string(data))
		}

		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":1,"retryable":0,"rejected":0,"results":[{"index":0,"status":"accepted"}]}`))
	}))
	defer server.Close()

	cfg := ClientConfig{
		BackendURL:         server.URL,
		APIKey:             "test-api-key",
		ListenAddr:         "127.0.0.1:0",
		BatchIntervalMS:    1000,
		MaxBatchSize:       10,
		InsecureSkipVerify: true,
	}

	items := []QueueItem{
		{
			sourceIP:   "10.0.0.1",
			packetData: []byte("test-data"),
			receivedAt: time.Now().UTC(),
		},
	}

	ctx := context.Background()
	sendBatchWithRetry(ctx, server.Client(), cfg, items)

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected 1 request, got %d", requestCount)
	}
}

func TestSendBatchWithRetryRetriesAndFails(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	cfg := ClientConfig{
		BackendURL:         server.URL,
		APIKey:             "test-api-key",
		ListenAddr:         "127.0.0.1:0",
		BatchIntervalMS:    1000,
		MaxBatchSize:       10,
		InsecureSkipVerify: true,
	}

	items := []QueueItem{
		{
			sourceIP:   "10.0.0.2",
			packetData: []byte("test-data-retry"),
			receivedAt: time.Now().UTC(),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use a short timeout or cancel so the test doesn't hang on 5 retries with backoff.
	// Wait, the client code uses hardcoded backoff: backoff := 100 * time.Millisecond,
	// and sleeps. We want the test to run quickly, so we can pass a cancelled context or a timeout,
	// or let it run since max 5 retries with 100ms, 200ms, 400ms, 800ms backoff takes ~1.5s total.
	start := time.Now()
	sendBatchWithRetry(ctx, server.Client(), cfg, items)
	duration := time.Since(start)

	count := requestCount.Load()
	if count < 2 {
		t.Errorf("expected at least 2 retries, got %d in %v", count, duration)
	}
}

func TestSendBatchWithRetryHaltedOnClientError(t *testing.T) {
	t.Parallel()

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad_request","message":"invalid JSON body"}`))
	}))
	defer server.Close()

	cfg := ClientConfig{
		BackendURL:         server.URL,
		APIKey:             "test-api-key",
		ListenAddr:         "127.0.0.1:0",
		BatchIntervalMS:    1000,
		MaxBatchSize:       10,
		InsecureSkipVerify: true,
	}

	items := []QueueItem{
		{
			sourceIP:   "10.0.0.3",
			packetData: []byte("test-data-fatal"),
			receivedAt: time.Now().UTC(),
		},
	}

	ctx := context.Background()
	sendBatchWithRetry(ctx, server.Client(), cfg, items)

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Errorf("expected exactly 1 request (no retries for 400 Bad Request), got %d", requestCount)
	}
}

func TestSendBatchWithRetryContextCancelled(t *testing.T) {
	t.Parallel()

	cfg := ClientConfig{
		BackendURL: "http://invalid-localhost-url-nonexistent",
		APIKey:     "test-api-key",
	}

	items := []QueueItem{
		{
			sourceIP:   "10.0.0.4",
			packetData: []byte("test-data-cancelled"),
			receivedAt: time.Now().UTC(),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Should exit immediately without executing requests
	client := &http.Client{
		Transport: http.DefaultTransport,
	}
	sendBatchWithRetry(ctx, client, cfg, items)
}

func TestClientConfigParsing(t *testing.T) {
	// Simple validation of the structures
	cfg := ClientConfig{
		BackendURL: "http://localhost:8080",
		APIKey:     "secret-key",
	}
	if cfg.BackendURL != "http://localhost:8080" || cfg.APIKey != "secret-key" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestSendBatchWithRetryRetriesOnlyRetryableRecords(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	var secondRequestRecords atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := requestCount.Add(1)
		gzipReader, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("gzip.NewReader() error = %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer func() { _ = gzipReader.Close() }()
		var request ProxyRequest
		if err := json.NewDecoder(gzipReader).Decode(&request); err != nil {
			t.Errorf("json.Decode() error = %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if attempt == 1 {
			_, _ = w.Write([]byte(`{"accepted":1,"retryable":1,"rejected":1,"results":[{"index":0,"status":"accepted"},{"index":1,"status":"retryable","error_code":"queue_full"},{"index":2,"status":"rejected","error_code":"malformed_packet"}]}`))
			return
		}
		secondRequestRecords.Store(int64(len(request.Records)))
		_, _ = w.Write([]byte(`{"accepted":1,"retryable":0,"rejected":0,"results":[{"index":0,"status":"accepted"}]}`))
	}))
	defer server.Close()

	cfg := ClientConfig{BackendURL: server.URL, APIKey: "key"}
	items := []QueueItem{
		{sourceIP: "192.0.2.1", packetData: []byte("accepted"), receivedAt: time.Now()},
		{sourceIP: "192.0.2.2", packetData: []byte("retryable"), receivedAt: time.Now()},
		{sourceIP: "192.0.2.3", packetData: []byte("rejected"), receivedAt: time.Now()},
	}
	sendBatchWithRetry(context.Background(), server.Client(), cfg, items)
	if requestCount.Load() != 2 || secondRequestRecords.Load() != 1 {
		t.Fatalf("requests=%d second_records=%d, want 2 and 1", requestCount.Load(), secondRequestRecords.Load())
	}
}

func TestClientConfigValidatePacketSize(t *testing.T) {
	t.Parallel()

	cfg := ClientConfig{
		BackendURL:      "https://quiver.example",
		APIKey:          "secret",
		ListenAddr:      "127.0.0.1:2055",
		BatchIntervalMS: 1000,
		MaxBatchSize:    100,
		MaxPacketBytes:  65535,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	cfg.MaxPacketBytes = 65536
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected max_packet_bytes validation error")
	}
}

func TestPostBatchForwardsMaximumSizePacket(t *testing.T) {
	t.Parallel()

	packet := bytes.Repeat([]byte{0xa5}, 65535)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gzipReader, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("gzip.NewReader() error = %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer func() { _ = gzipReader.Close() }()
		var request ProxyRequest
		if err := json.NewDecoder(gzipReader).Decode(&request); err != nil {
			t.Errorf("json.Decode() error = %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		decoded, err := base64.StdEncoding.DecodeString(request.Records[0].PacketData)
		if err != nil || !bytes.Equal(decoded, packet) {
			t.Errorf("maximum packet changed: len=%d err=%v", len(decoded), err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":1,"retryable":0,"rejected":0,"results":[{"index":0,"status":"accepted"}]}`))
	}))
	defer server.Close()

	response, status, err := postBatch(context.Background(), server.Client(), ClientConfig{
		BackendURL: server.URL,
		APIKey:     "key",
	}, []QueueItem{{
		sourceIP:   "192.0.2.1",
		packetData: packet,
		receivedAt: time.Now(),
	}})
	if err != nil || status != http.StatusAccepted || response.Accepted != 1 {
		t.Fatalf("postBatch() response=%+v status=%d err=%v", response, status, err)
	}
}

func TestClientMainStartsAndStops(t *testing.T) {
	if os.Getenv("QUIVER_CLIENT_TEST_MAIN") == "1" {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		os.Args = []string{os.Args[0], "-config", os.Getenv("QUIVER_CLIENT_TEST_CONFIG")}
		go func() {
			time.Sleep(100 * time.Millisecond)
			proc, err := os.FindProcess(os.Getpid())
			if err == nil {
				_ = proc.Signal(os.Interrupt)
			}
		}()
		main()
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":0,"retryable":0,"rejected":0,"results":[]}`))
	}))
	defer server.Close()

	configPath := filepath.Join(t.TempDir(), "client.yaml")
	config := `backend_url: "` + server.URL + `"
api_key: "client-key"
listen_addr: "127.0.0.1:0"
batch_interval_ms: 10
max_batch_size: 2
max_packet_bytes: 65535
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestClientMainStartsAndStops$") //nolint:gosec // test intentionally re-execs the current test binary.
	cmd.Env = append(os.Environ(), "QUIVER_CLIENT_TEST_MAIN=1", "QUIVER_CLIENT_TEST_CONFIG="+configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("main subprocess failed: %v output=%s", err, output)
	}
	if ctx.Err() != nil {
		t.Fatalf("main subprocess timed out: %v output=%s", ctx.Err(), output)
	}
	if !strings.Contains(string(output), "quiver-client stopped cleanly") {
		t.Fatalf("output = %s, want clean shutdown", output)
	}
}

func TestClientConfigValidateRejectsInvalidFields(t *testing.T) {
	t.Parallel()

	valid := ClientConfig{
		BackendURL:      "https://quiver.example",
		APIKey:          "secret",
		ListenAddr:      "127.0.0.1:2055",
		BatchIntervalMS: 1000,
		MaxBatchSize:    100,
		MaxPacketBytes:  65535,
	}
	tests := []struct {
		name string
		edit func(*ClientConfig)
		want string
	}{
		{name: "relative backend", edit: func(c *ClientConfig) { c.BackendURL = "/relative" }, want: "backend_url"},
		{name: "unsupported scheme", edit: func(c *ClientConfig) { c.BackendURL = "ftp://example.com" }, want: "backend_url"},
		{name: "credentials", edit: func(c *ClientConfig) { c.BackendURL = "https://user:pass@example.com" }, want: "credentials"},
		{name: "blank api key", edit: func(c *ClientConfig) { c.APIKey = " \t" }, want: "api_key"},
		{name: "bad listen addr", edit: func(c *ClientConfig) { c.ListenAddr = "127.0.0.1" }, want: "listen_addr"},
		{name: "zero interval", edit: func(c *ClientConfig) { c.BatchIntervalMS = 0 }, want: "batch_interval_ms"},
		{name: "large interval", edit: func(c *ClientConfig) { c.BatchIntervalMS = 60001 }, want: "batch_interval_ms"},
		{name: "zero batch", edit: func(c *ClientConfig) { c.MaxBatchSize = 0 }, want: "max_batch_size"},
		{name: "large batch", edit: func(c *ClientConfig) { c.MaxBatchSize = 1001 }, want: "max_batch_size"},
		{name: "zero packet", edit: func(c *ClientConfig) { c.MaxPacketBytes = 0 }, want: "max_packet_bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid
			tt.edit(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestRetryableSubsetValidation(t *testing.T) {
	t.Parallel()

	items := []QueueItem{
		{sourceIP: "192.0.2.1", packetData: []byte("one"), receivedAt: time.Now()},
		{sourceIP: "192.0.2.2", packetData: []byte("two"), receivedAt: time.Now()},
	}
	valid := ProxyV2Response{
		Accepted:  1,
		Retryable: 1,
		Rejected:  0,
		Results: []ProxyRecordResult{
			{Index: 0, Status: "accepted"},
			{Index: 1, Status: "retryable", ErrorCode: "queue_full"},
		},
	}
	retryable, err := retryableSubset(items, valid)
	if err != nil {
		t.Fatalf("retryableSubset(valid) error = %v", err)
	}
	if len(retryable) != 1 || string(retryable[0].packetData) != "two" {
		t.Fatalf("retryable = %+v", retryable)
	}

	tests := []struct {
		name     string
		response ProxyV2Response
		want     string
	}{
		{name: "result count mismatch", response: ProxyV2Response{Results: valid.Results[:1]}, want: "result count"},
		{name: "negative index", response: ProxyV2Response{Results: []ProxyRecordResult{{Index: -1, Status: "accepted"}, {Index: 1, Status: "accepted"}}}, want: "invalid"},
		{name: "duplicate index", response: ProxyV2Response{Results: []ProxyRecordResult{{Index: 0, Status: "accepted"}, {Index: 0, Status: "accepted"}}}, want: "duplicate"},
		{name: "accepted with error", response: ProxyV2Response{Results: []ProxyRecordResult{{Index: 0, Status: "accepted", ErrorCode: "bad"}, {Index: 1, Status: "accepted"}}}, want: "accepted"},
		{name: "retryable missing error", response: ProxyV2Response{Results: []ProxyRecordResult{{Index: 0, Status: "accepted"}, {Index: 1, Status: "retryable"}}}, want: "retryable"},
		{name: "rejected missing error", response: ProxyV2Response{Results: []ProxyRecordResult{{Index: 0, Status: "accepted"}, {Index: 1, Status: "rejected"}}}, want: "rejected"},
		{name: "unknown status", response: ProxyV2Response{Results: []ProxyRecordResult{{Index: 0, Status: "accepted"}, {Index: 1, Status: "unknown"}}}, want: "unknown"},
		{name: "count mismatch", response: ProxyV2Response{Accepted: 2, Retryable: 0, Rejected: 0, Results: valid.Results}, want: "counts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := retryableSubset(items, tt.response)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("retryableSubset() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestPostBatchResponseEdgeCases(t *testing.T) {
	t.Parallel()

	items := []QueueItem{{sourceIP: "192.0.2.1", packetData: []byte("packet"), receivedAt: time.Now()}}

	_, _, err := postBatch(context.Background(), http.DefaultClient, ClientConfig{BackendURL: "://bad-url", APIKey: "key"}, items)
	if err == nil || !strings.Contains(err.Error(), "create proxy request") {
		t.Fatalf("bad URL error = %v", err)
	}

	tests := []struct {
		name       string
		statusCode int
		body       string
		wantStatus int
		wantErr    string
	}{
		{name: "server unavailable", statusCode: http.StatusServiceUnavailable, body: "try later", wantStatus: http.StatusServiceUnavailable},
		{name: "bad json", statusCode: http.StatusAccepted, body: `not-json`, wantStatus: http.StatusAccepted, wantErr: "decode proxy response"},
		{name: "extra json", statusCode: http.StatusAccepted, body: `{"accepted":1,"retryable":0,"rejected":0,"results":[{"index":0,"status":"accepted"}]} {}`, wantStatus: http.StatusAccepted, wantErr: "one json object"},
		{name: "unknown field", statusCode: http.StatusAccepted, body: `{"accepted":1,"retryable":0,"rejected":0,"results":[{"index":0,"status":"accepted"}],"extra":true}`, wantStatus: http.StatusAccepted, wantErr: "decode proxy response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			_, status, err := postBatch(context.Background(), server.Client(), ClientConfig{BackendURL: server.URL, APIKey: "key"}, items)
			if status != tt.wantStatus {
				t.Fatalf("status = %d, want %d", status, tt.wantStatus)
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("postBatch() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("postBatch() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSleepWithContext(t *testing.T) {
	t.Parallel()

	if !sleepWithContext(context.Background(), time.Nanosecond) {
		t.Fatal("sleepWithContext completed = false, want true")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleepWithContext(ctx, time.Hour) {
		t.Fatal("sleepWithContext canceled = true, want false")
	}
}

func TestLogRejectedResultsNoPanic(t *testing.T) {
	t.Parallel()

	logRejectedResults(nil)
	logRejectedResults([]ProxyRecordResult{
		{Index: 0, Status: "accepted"},
		{Index: 1, Status: "rejected", ErrorCode: "malformed_packet"},
		{Index: 2, Status: "rejected", ErrorCode: "malformed_packet"},
		{Index: 3, Status: "rejected", ErrorCode: "unsupported_version"},
	})
}

func TestSendBatchWithRetryStopsWhenContextCanceledDuringBackoff(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sendBatchWithRetry(ctx, server.Client(), ClientConfig{BackendURL: server.URL, APIKey: "key"}, []QueueItem{{sourceIP: "192.0.2.1", packetData: []byte("packet"), receivedAt: time.Now()}})
}

func TestPostBatchPropagatesClientDoError(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network down")
	})}
	_, _, err := postBatch(context.Background(), client, ClientConfig{BackendURL: "http://quiver.invalid", APIKey: "key"}, []QueueItem{{sourceIP: "192.0.2.1", packetData: []byte("packet"), receivedAt: time.Now()}})
	if err == nil || !strings.Contains(err.Error(), "send proxy request") {
		t.Fatalf("postBatch client error = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
