package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

type ClientConfig struct {
	BackendURL         string `yaml:"backend_url"`
	APIKey             string `yaml:"api_key"`
	ListenAddr         string `yaml:"listen_addr"`
	BatchIntervalMS    int    `yaml:"batch_interval_ms"`
	MaxBatchSize       int    `yaml:"max_batch_size"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CACertPath         string `yaml:"ca_cert_path"`
}

type PacketRecord struct {
	SourceIP   string    `json:"source_ip"`
	PacketData string    `json:"packet_data"`
	ReceivedAt time.Time `json:"received_at"`
}

type ProxyRequest struct {
	Records []PacketRecord `json:"records"`
}

type QueueItem struct {
	sourceIP   string
	packetData []byte
	receivedAt time.Time
}

func main() {
	configPath := flag.String("config", "configs/client.yaml", "path to client YAML config")
	backendURL := flag.String("backend-url", "", "Quiver backend URL")
	apiKey := flag.String("api-key", "", "API key for ingestion authentication")
	listenAddr := flag.String("listen-addr", "", "Local UDP listen address")
	caCertPath := flag.String("ca-cert", "", "Path to custom CA certificate PEM file")
	insecure := flag.Bool("insecure-skip-verify", false, "Skip TLS verification")
	flag.Parse()

	// Load configuration
	cfg := ClientConfig{
		ListenAddr:      "127.0.0.1:2055",
		BatchIntervalMS: 1000,
		MaxBatchSize:    100,
	}

	if *configPath != "" {
		if data, err := os.ReadFile(*configPath); err == nil {
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				log.Fatalf("Error parsing config file: %v", err)
			}
		}
	}

	// Override config with CLI flags
	if *backendURL != "" {
		cfg.BackendURL = *backendURL
	}
	if *apiKey != "" {
		cfg.APIKey = *apiKey
	}
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}
	if *caCertPath != "" {
		cfg.CACertPath = *caCertPath
	}
	if *insecure {
		cfg.InsecureSkipVerify = true
	}

	if cfg.BackendURL == "" {
		log.Fatal("Backend URL is required (specify in config or via --backend-url)")
	}
	if cfg.APIKey == "" {
		log.Fatal("API key is required (specify in config or via --api-key)")
	}

	// Setup HTTP client with custom TLS settings
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec
	}
	if cfg.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			log.Fatalf("Error reading CA cert: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Setup listening socket
	packetConn, err := net.ListenPacket("udp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP %s: %v", cfg.ListenAddr, err)
	}
	defer func() { _ = packetConn.Close() }()

	log.Printf("quiver-client listening on UDP %s", cfg.ListenAddr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	queue := make(chan QueueItem, 10000)
	var wg sync.WaitGroup

	// Start UDP receiver goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_ = packetConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, addr, err := packetConn.ReadFrom(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					select {
					case <-ctx.Done():
						return
					default:
						log.Printf("Error reading UDP packet: %v", err)
						continue
					}
				}

				udpAddr, ok := addr.(*net.UDPAddr)
				if !ok {
					continue
				}

				packetCopy := make([]byte, n)
				copy(packetCopy, buf[:n])

				select {
				case queue <- QueueItem{
					sourceIP:   udpAddr.IP.String(),
					packetData: packetCopy,
					receivedAt: time.Now().UTC(),
				}:
				default:
					// Queue is full, drop packet (to prevent memory leaks under backpressure)
				}
			}
		}
	}()

	// Start single-worker sender goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		var batch []QueueItem
		ticker := time.NewTicker(time.Duration(cfg.BatchIntervalMS) * time.Millisecond)
		defer ticker.Stop()

		flush := func() {
			if len(batch) == 0 {
				return
			}
			sendBatchWithRetry(ctx, httpClient, cfg, batch)
			batch = nil
		}

		for {
			select {
			case <-ctx.Done():
				// Flush final batch on context cancellation
				flush()
				return
			case item := <-queue:
				batch = append(batch, item)
				if len(batch) >= cfg.MaxBatchSize {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down quiver-client...")
	_ = packetConn.Close()
	wg.Wait()
	log.Println("quiver-client stopped cleanly.")
}

func sendBatchWithRetry(ctx context.Context, client *http.Client, cfg ClientConfig, items []QueueItem) {
	reqBody := ProxyRequest{
		Records: make([]PacketRecord, 0, len(items)),
	}
	for _, item := range items {
		reqBody.Records = append(reqBody.Records, PacketRecord{
			SourceIP:   item.sourceIP,
			PacketData: base64.StdEncoding.EncodeToString(item.packetData),
			ReceivedAt: item.receivedAt,
		})
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		log.Printf("Failed to marshal JSON payload: %v", err)
		return
	}

	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	if _, err := gzipWriter.Write(jsonData); err != nil {
		log.Printf("Failed to compress payload: %v", err)
		return
	}
	_ = gzipWriter.Close()

	url := fmt.Sprintf("%s/api/v1/ingest/proxy-netflow", cfg.BackendURL)

	backoff := 100 * time.Millisecond
	maxBackoff := 5 * time.Second
	maxRetries := 5

	for retry := 0; retry < maxRetries; retry++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(buf.Bytes()))
		if err != nil {
			log.Printf("Failed to create request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("X-API-Key", cfg.APIKey)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("HTTP POST failed (retry %d/%d): %v", retry+1, maxRetries, err)
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusAccepted {
			// Success
			return
		}

		log.Printf("Backend rejected batch (status=%d): %s", resp.StatusCode, string(respBody))
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			// Client error (e.g. invalid auth, bad JSON), do not retry
			return
		}

		// Server error or rate limit, retry with backoff
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}

	log.Printf("Dropped batch of %d records after %d failed retries", len(items), maxRetries)
}
