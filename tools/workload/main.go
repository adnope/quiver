//nolint:gosec // This live workload generator intentionally uses non-cryptographic randomness and bounded numeric casts.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

// Configuration defaults
const (
	DefaultTargetURL = "http://localhost:8236"
	DefaultAPIKey    = "democlientkey123"
	DefaultRPS       = 20
	DefaultErrorRate = 0.05 // 5% malformed records
	DefaultBatchSize = 10
)

var (
	internalIPs = []string{
		"192.168.1.10", "192.168.1.20", "192.168.1.50", "192.168.1.100",
		"10.0.0.5", "10.0.0.10", "10.0.0.100", "172.16.5.12",
	}

	publicIPs = []string{
		"8.8.8.8", "1.1.1.1", "142.250.190.46", "52.216.102.163",
		"13.107.42.14", "104.244.42.1", "157.240.22.35",
	}
)

type IngestRequest struct {
	Records []IngestRecord `json:"records"`
}

type IngestRecord struct {
	ExternalID          string         `json:"external_id,omitempty"`
	EventStartTime      string         `json:"event_start_time"`
	EventEndTime        string         `json:"event_end_time,omitempty"`
	SrcIP               string         `json:"src_ip"`
	DstIP               string         `json:"dst_ip"`
	SrcPort             *uint32        `json:"src_port,omitempty"`
	DstPort             *uint32        `json:"dst_port,omitempty"`
	TransportProtocol   string         `json:"transport_protocol"`
	ProtocolNumber      uint32         `json:"protocol_number"`
	Bytes               *uint64        `json:"bytes,omitempty"`
	Packets             *uint64        `json:"packets,omitempty"`
	ApplicationProtocol string         `json:"application_protocol,omitempty"`
	TCPFlags            *uint32        `json:"tcp_flags,omitempty"`
	SamplingRate        *uint32        `json:"sampling_rate,omitempty"`
	Attributes          map[string]any `json:"attributes,omitempty"`
}

func main() {
	target := flag.String("target", DefaultTargetURL, "Target backend base URL")
	apiKey := flag.String("key", DefaultAPIKey, "API Key with ingest scope")
	rps := flag.Int("rps", DefaultRPS, "Target requests per second (flow records per second)")
	errRate := flag.Float64("error-rate", DefaultErrorRate, "Fraction of flows that should be malformed (0.0 to 1.0)")
	batchSize := flag.Int("batch", DefaultBatchSize, "Number of flow records per POST request")
	flag.Parse()

	url := fmt.Sprintf("%s/api/v1/ingest/flows", *target)
	fmt.Printf("Starting real-time workload generator against: %s\n", url)
	fmt.Printf("Parameters: Target RPS=%d, Batch Size=%d, Malformed Injection Rate=%.1f%%\n", *rps, *batchSize, *errRate*100)
	fmt.Println("Press Ctrl+C to terminate.")

	// Calculate ticker interval based on RPS and Batch size
	batchesPerSecond := float64(*rps) / float64(*batchSize)
	if batchesPerSecond <= 0 {
		batchesPerSecond = 1
	}
	interval := time.Duration(float64(time.Second) / batchesPerSecond)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Handle shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &http.Client{Timeout: 5 * time.Second}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	var sentCount int64
	var errorCount int64

	go func() {
		<-sigChan
		fmt.Println("\nShutdown signal received. Stopping workload generator...")
		cancel()
	}()

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("Workload generation stopped. Sent: %d records, Failed batches: %d.\n", sentCount, errorCount)
			return
		case <-ticker.C:
			// Prepare batch
			records := make([]IngestRecord, 0, *batchSize)
			for i := 0; i < *batchSize; i++ {
				// Inject an error/malformed flow occasionally
				injectError := r.Float64() < *errRate
				record := generateRecord(r, injectError)
				records = append(records, record)
			}

			reqObj := IngestRequest{Records: records}
			reqBody, err := json.Marshal(reqObj)
			if err != nil {
				fmt.Printf("Failed to serialize batch: %v\n", err)
				continue
			}

			// Send POST request
			go func(body []byte, count int) {
				req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
				if err != nil {
					return
				}
				req.Header.Set("X-API-Key", *apiKey)
				req.Header.Set("Content-Type", "application/json")

				resp, err := client.Do(req)
				if err != nil {
					fmt.Printf("[Error] Network connection failure to backend: %v\n", err)
					atomic.AddInt64(&errorCount, 1)
					return
				}
				defer func() {
					if err := resp.Body.Close(); err != nil {
						fmt.Printf("[Warn] Failed to close response body: %v\n", err)
					}
				}()

				if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
					fmt.Printf("[Warn] Request rejected by backend. Status: %d\n", resp.StatusCode)
					atomic.AddInt64(&errorCount, 1)
				} else {
					atomic.AddInt64(&sentCount, int64(count))
				}
			}(reqBody, len(records))
		}
	}
}

func generateRecord(r *rand.Rand, injectError bool) IngestRecord {
	// Standard protocols
	protocols := []struct {
		proto string
		num   uint32
		port  uint32
		app   string
	}{
		{"tcp", 6, 443, "https"},
		{"tcp", 6, 80, "http"},
		{"tcp", 6, 22, "ssh"},
		{"udp", 17, 53, "dns"},
		{"udp", 17, 123, "ntp"},
	}
	p := protocols[r.Intn(len(protocols))]

	// Random IPs
	srcIP := internalIPs[r.Intn(len(internalIPs))]
	dstIP := publicIPs[r.Intn(len(publicIPs))]
	srcPort := uint32(32768 + r.Intn(32768))
	dstPort := p.port

	if injectError {
		// Create a malformed record
		errorType := r.Intn(4)
		switch errorType {
		case 0:
			// Invalid IP address format
			srcIP = "invalid-ip-address"
		case 1:
			// Port number out of range (greater than 65535)
			overflowPort := uint32(999999)
			srcPort = overflowPort
		case 2:
			// Unsupported protocol name
			p.proto = "invalid-protocol-name"
			p.num = 250
		default:
			// Inconsistent protocol name and protocol number
			p.proto = "tcp"
			p.num = 17 // UDP protocol number
		}
	}

	packets := uint64(1 + r.Int63n(100))
	bytesVal := uint64(packets * uint64(100+r.Int63n(1400)))

	tcpFlags := uint32(0x18)
	sampling := uint32(1)

	now := time.Now().UTC()
	startStr := now.Format(time.RFC3339Nano)
	endStr := now.Add(time.Duration(10+r.Intn(1000)) * time.Millisecond).Format(time.RFC3339Nano)

	return IngestRecord{
		ExternalID:          fmt.Sprintf("live-%d-%d", now.UnixNano(), r.Int63n(100000)),
		EventStartTime:      startStr,
		EventEndTime:        endStr,
		SrcIP:               srcIP,
		DstIP:               dstIP,
		SrcPort:             &srcPort,
		DstPort:             &dstPort,
		TransportProtocol:   p.proto,
		ProtocolNumber:      p.num,
		Bytes:               &bytesVal,
		Packets:             &packets,
		ApplicationProtocol: p.app,
		TCPFlags:            &tcpFlags,
		SamplingRate:        &sampling,
		Attributes:          map[string]any{"generated_by": "workload_script"},
	}
}
