package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
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
	MaxPacketBytes     int    `yaml:"max_packet_bytes"`
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

type ProxyRecordResult struct {
	Index     int    `json:"index"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
}

type ProxyV2Response struct {
	Accepted  int                 `json:"accepted"`
	Retryable int                 `json:"retryable"`
	Rejected  int                 `json:"rejected"`
	Results   []ProxyRecordResult `json:"results"`
}

type QueueItem struct {
	sourceIP   string
	packetData []byte
	receivedAt time.Time
}

func (c ClientConfig) Validate() error {
	backendURL, err := url.ParseRequestURI(strings.TrimSpace(c.BackendURL))
	if err != nil || backendURL.Host == "" || (backendURL.Scheme != "http" && backendURL.Scheme != "https") {
		return errors.New("backend_url must be an absolute http or https URL")
	}
	if backendURL.User != nil {
		return errors.New("backend_url must not contain credentials")
	}
	if strings.TrimSpace(c.APIKey) == "" {
		return errors.New("api_key is required")
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf("listen_addr must be host:port: %w", err)
	}
	if c.BatchIntervalMS <= 0 || c.BatchIntervalMS > 60_000 {
		return errors.New("batch_interval_ms must be within 1..60000")
	}
	if c.MaxBatchSize <= 0 || c.MaxBatchSize > 1000 {
		return errors.New("max_batch_size must be within 1..1000")
	}
	if c.MaxPacketBytes <= 0 || c.MaxPacketBytes > 65535 {
		return errors.New("max_packet_bytes must be within 1..65535")
	}
	return nil
}

func main() {
	configPath := flag.String("config", "configs/client.yaml", "path to client YAML config")
	backendURL := flag.String("backend-url", "", "Quiver backend URL")
	apiKey := flag.String("api-key", "", "API key for ingestion authentication")
	listenAddr := flag.String("listen-addr", "", "Local UDP listen address")
	caCertPath := flag.String("ca-cert", "", "Path to custom CA certificate PEM file")
	insecure := flag.Bool("insecure-skip-verify", false, "Skip TLS verification")
	flag.Parse()
	configFlagSet := false
	flag.Visit(func(current *flag.Flag) {
		if current.Name == "config" {
			configFlagSet = true
		}
	})

	cfg := ClientConfig{
		ListenAddr:      "127.0.0.1:2055",
		BatchIntervalMS: 1000,
		MaxBatchSize:    100,
		MaxPacketBytes:  65535,
	}

	if *configPath != "" {
		data, err := os.ReadFile(*configPath)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) || configFlagSet {
				log.Fatalf("read config file: %v", err)
			}
		} else {
			decoder := yaml.NewDecoder(bytes.NewReader(data))
			decoder.KnownFields(true)
			if err := decoder.Decode(&cfg); err != nil {
				log.Fatalf("parse config file: %v", err)
			}
		}
	}

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

	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
	}
	if cfg.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			log.Fatalf("Error reading CA cert: %v", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			log.Fatal("CA certificate file does not contain a valid PEM certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsConfig,
			MaxIdleConns:          10,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listenConfig := net.ListenConfig{}
	packetConn, err := listenConfig.ListenPacket(ctx, "udp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP %s: %v", cfg.ListenAddr, err)
	}
	defer func() { _ = packetConn.Close() }()
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		log.Fatal("UDP listener did not return a UDP connection")
	}

	log.Printf("quiver-client listening on UDP %s", cfg.ListenAddr)

	queue := make(chan QueueItem, 10000)
	var wg sync.WaitGroup

	wg.Go(func() {
		buf := make([]byte, cfg.MaxPacketBytes)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_ = packetConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, _, flags, addr, err := udpConn.ReadMsgUDP(buf, nil)
				if err != nil {
					var netErr net.Error
					if errors.As(err, &netErr) && netErr.Timeout() {
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

				if flags&syscall.MSG_TRUNC != 0 || n > len(buf) {
					log.Printf("dropped truncated UDP packet source=%s max_packet_bytes=%d", addr.IP.String(), cfg.MaxPacketBytes)
					continue
				}

				packetCopy := append([]byte(nil), buf[:n]...)

				select {
				case queue <- QueueItem{
					sourceIP:   addr.IP.String(),
					packetData: packetCopy,
					receivedAt: time.Now().UTC(),
				}:
				default:
					log.Printf("dropped UDP packet because queue is full source=%s", addr.IP.String())
				}
			}
		}
	})

	wg.Go(func() {
		batch := make([]QueueItem, 0, cfg.MaxBatchSize)
		ticker := time.NewTicker(time.Duration(cfg.BatchIntervalMS) * time.Millisecond)
		defer ticker.Stop()

		flush := func() {
			if len(batch) == 0 {
				return
			}
			sendBatchWithRetry(ctx, httpClient, cfg, batch)
			batch = make([]QueueItem, 0, cfg.MaxBatchSize)
		}

		for {
			select {
			case <-ctx.Done():
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
	})

	<-ctx.Done()
	log.Println("shutting down quiver-client")
	_ = packetConn.Close()
	wg.Wait()
	log.Println("quiver-client stopped cleanly")
}

func sendBatchWithRetry(ctx context.Context, client *http.Client, cfg ClientConfig, items []QueueItem) {
	const maxAttempts = 5
	const maxBackoff = 5 * time.Second

	pending := append([]QueueItem(nil), items...)
	backoff := 100 * time.Millisecond
	for attempt := range maxAttempts {
		if err := ctx.Err(); err != nil {
			return
		}

		response, statusCode, err := postBatch(ctx, client, cfg, pending)
		if err == nil && statusCode == http.StatusAccepted {
			retryable, validationErr := retryableSubset(pending, response)
			if validationErr == nil {
				logRejectedResults(response.Results)
				if len(retryable) == 0 {
					return
				}
				pending = retryable
			} else {
				log.Printf("proxy response invalid attempt=%d records=%d code=malformed_v2_response", attempt+1, len(pending))
			}
		} else if err == nil && statusCode >= 400 && statusCode < 500 && statusCode != http.StatusTooManyRequests {
			log.Printf("proxy batch permanently rejected status=%d records=%d", statusCode, len(pending))
			return
		} else {
			log.Printf("proxy batch retryable attempt=%d records=%d status=%d", attempt+1, len(pending), statusCode)
		}

		if attempt == maxAttempts-1 || !sleepWithContext(ctx, backoff) {
			break
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}

	log.Printf("dropped proxy packets after retry exhaustion records=%d attempts=%d", len(pending), maxAttempts)
}

func postBatch(
	ctx context.Context,
	client *http.Client,
	cfg ClientConfig,
	items []QueueItem,
) (ProxyV2Response, int, error) {
	reqBody := ProxyRequest{Records: make([]PacketRecord, 0, len(items))}
	for _, item := range items {
		reqBody.Records = append(reqBody.Records, PacketRecord{
			SourceIP:   item.sourceIP,
			PacketData: base64.StdEncoding.EncodeToString(item.packetData),
			ReceivedAt: item.receivedAt,
		})
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return ProxyV2Response{}, 0, fmt.Errorf("marshal proxy request: %w", err)
	}

	var body bytes.Buffer
	gzipWriter := gzip.NewWriter(&body)
	if _, err := gzipWriter.Write(jsonData); err != nil {
		_ = gzipWriter.Close()
		return ProxyV2Response{}, 0, fmt.Errorf("compress proxy request: %w", err)
	}
	if err := gzipWriter.Close(); err != nil {
		return ProxyV2Response{}, 0, fmt.Errorf("finish proxy request compression: %w", err)
	}

	endpoint := strings.TrimRight(cfg.BackendURL, "/") + "/api/v1/ingest/proxy-netflow"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body.Bytes()))
	if err != nil {
		return ProxyV2Response{}, 0, fmt.Errorf("create proxy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("X-API-Key", cfg.APIKey)
	req.Header.Set("X-Quiver-Proxy-Protocol", "2")

	resp, err := client.Do(req)
	if err != nil {
		return ProxyV2Response{}, 0, fmt.Errorf("send proxy request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return ProxyV2Response{}, resp.StatusCode, nil
	}

	var response ProxyV2Response
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return ProxyV2Response{}, resp.StatusCode, fmt.Errorf("decode proxy response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ProxyV2Response{}, resp.StatusCode, errors.New("proxy response must contain one json object")
	}
	return response, resp.StatusCode, nil
}

func retryableSubset(items []QueueItem, response ProxyV2Response) ([]QueueItem, error) {
	if len(response.Results) != len(items) {
		return nil, fmt.Errorf("result count %d does not match request count %d", len(response.Results), len(items))
	}
	seen := make([]bool, len(items))
	retryable := make([]QueueItem, 0, response.Retryable)
	var accepted int
	var rejected int
	for _, result := range response.Results {
		if result.Index < 0 || result.Index >= len(items) || seen[result.Index] {
			return nil, fmt.Errorf("invalid or duplicate result index %d", result.Index)
		}
		seen[result.Index] = true
		switch result.Status {
		case "accepted":
			if result.ErrorCode != "" {
				return nil, fmt.Errorf("accepted result %d contains an error code", result.Index)
			}
			accepted++
		case "retryable":
			if strings.TrimSpace(result.ErrorCode) == "" {
				return nil, fmt.Errorf("retryable result %d is missing an error code", result.Index)
			}
			retryable = append(retryable, items[result.Index])
		case "rejected":
			if strings.TrimSpace(result.ErrorCode) == "" {
				return nil, fmt.Errorf("rejected result %d is missing an error code", result.Index)
			}
			rejected++
		default:
			return nil, fmt.Errorf("result %d has unknown status %q", result.Index, result.Status)
		}
	}
	if response.Accepted != accepted || response.Retryable != len(retryable) || response.Rejected != rejected {
		return nil, errors.New("proxy response counts do not match results")
	}
	return retryable, nil
}

func logRejectedResults(results []ProxyRecordResult) {
	codes := map[string]int{}
	for _, result := range results {
		if result.Status == "rejected" {
			codes[result.ErrorCode]++
		}
	}
	if len(codes) == 0 {
		return
	}
	keys := make([]string, 0, len(codes))
	for code := range codes {
		keys = append(keys, code)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, code := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", code, codes[code]))
	}
	log.Printf("proxy packets permanently rejected codes=%s", strings.Join(parts, ","))
}

func sleepWithContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
