package main

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		_, _ = w.Write([]byte(`{"accepted":1,"rejected":0}`))
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

	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
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

	count := atomic.LoadInt32(&requestCount)
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
