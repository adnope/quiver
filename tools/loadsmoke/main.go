package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/adnope/quiver/internal/domain"
	_ "github.com/lib/pq"
)

type PerformanceSmoke struct {
	StartedAt            string    `json:"started_at"`
	DurationSeconds      float64   `json:"duration_seconds"`
	Mode                 string    `json:"mode"`
	TargetRPS            int       `json:"target_rps"`
	RecordsAttempted     int64     `json:"records_attempted"`
	RecordsAccepted      int64     `json:"records_accepted"`
	RecordsPersisted     int64     `json:"records_persisted"`
	RecordsFailed        int64     `json:"records_failed"`
	RecordsDropped       int64     `json:"records_dropped_or_lag"`
	ThroughputDurableRPS float64   `json:"throughput_durable_rps"`
	QueryLatencies       Latencies `json:"query_latencies"`
	BottleneckDetected   bool      `json:"bottleneck_detected"`
	Warnings             []string  `json:"warnings"`
	Notes                []string  `json:"notes"`
}

type Latencies struct {
	Count int     `json:"count"`
	Min   float64 `json:"min_ms"`
	P50   float64 `json:"p50_ms"`
	P95   float64 `json:"p95_ms"`
	P99   float64 `json:"p99_ms"`
	Max   float64 `json:"max_ms"`
}

type IngestRequest struct {
	Records []IngestRecord `json:"records"`
}

type IngestRecord struct {
	EventStartTime    string  `json:"event_start_time"`
	SrcIP             string  `json:"src_ip"`
	DstIP             string  `json:"dst_ip"`
	SrcPort           *uint32 `json:"src_port,omitempty"`
	DstPort           *uint32 `json:"dst_port,omitempty"`
	TransportProtocol string  `json:"transport_protocol"`
	ProtocolNumber    uint32  `json:"protocol_number"`
	Bytes             *uint64 `json:"bytes,omitempty"`
	Packets           *uint64 `json:"packets,omitempty"`
}

type ZeekRecord struct {
	TS        float64 `json:"ts"`
	UID       string  `json:"uid"`
	OrigH     string  `json:"id.orig_h"`
	OrigP     int     `json:"id.orig_p"`
	RespH     string  `json:"id.resp_h"`
	RespP     int     `json:"id.resp_p"`
	Proto     string  `json:"proto"`
	Service   string  `json:"service,omitempty"`
	Duration  float64 `json:"duration,omitempty"`
	OrigBytes int64   `json:"orig_bytes,omitempty"`
	RespBytes int64   `json:"resp_bytes,omitempty"`
	OrigPkts  int64   `json:"orig_pkts,omitempty"`
	RespPkts  int64   `json:"resp_pkts,omitempty"`
	ConnState string  `json:"conn_state,omitempty"`
}

type MetricSnapshot struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	Value  uint64            `json:"value"`
}

type LiveMetricsResponse struct {
	Metrics []MetricSnapshot `json:"metrics"`
}

var (
	internalIPs = []string{"192.168.1.10", "192.168.1.50", "10.0.0.5", "172.16.5.12"}
	publicIPs   = []string{"8.8.8.8", "1.1.1.1", "142.250.190.46", "104.244.42.1"}

	attempted int64
	accepted  int64
	failed    int64
)

type Config struct {
	TargetREST   string
	TargetUDP    string
	TargetZeek   string
	TargetDB     string
	ZeekMode     string
	AdminKey     string
	ClientKey    string
	ZeekKey      string
	DurationSec  int
	RPS          int
	Workers      int
	QueryWorkers int
	Ramp         bool
	RampStart    int
	RampStep     int
	RampInterval time.Duration
	RampMax      int
}

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.TargetREST, "rest", "http://localhost:8236", "Target REST API Base URL")
	flag.StringVar(&cfg.TargetUDP, "udp", "localhost:2055", "Target UDP address host:port")
	flag.StringVar(&cfg.TargetZeek, "zeek", "/tmp/zeek/conn.log", "Target Zeek log file path or URL if mode=http")
	flag.StringVar(&cfg.TargetDB, "db", "postgres://postgres:postgres@localhost:5432/quiver?sslmode=disable", "Target Database URL")
	flag.StringVar(&cfg.ZeekMode, "zeek-mode", "file", "Zeek ingest mode: 'file' or 'http'")
	flag.StringVar(&cfg.AdminKey, "admin-key", "demoadminkey123", "Admin API Key for metrics/query")
	flag.StringVar(&cfg.ClientKey, "client-key", "democlientkey123", "Client API Key for REST ingest")
	flag.StringVar(&cfg.ZeekKey, "zeek-key", "zeekshipperkey123", "Zeek Shipper API Key")
	flag.IntVar(&cfg.DurationSec, "duration", 30, "Duration of the fixed load test in seconds")
	flag.IntVar(&cfg.RPS, "rps", 1000, "Target records per second for fixed mode")
	flag.IntVar(&cfg.Workers, "workers", 4, "Number of concurrent REST ingestion workers")
	flag.IntVar(&cfg.QueryWorkers, "query-workers", 2, "Number of concurrent query contention workers")
	flag.BoolVar(&cfg.Ramp, "ramp", false, "Enable ramping auto-tuning mode to find max throughput")
	flag.IntVar(&cfg.RampStart, "ramp-start", 200, "Start RPS for ramp mode")
	flag.IntVar(&cfg.RampStep, "ramp-step", 200, "Step RPS for ramp mode")
	flag.DurationVar(&cfg.RampInterval, "ramp-interval", 10*time.Second, "Step duration for ramp mode")
	flag.IntVar(&cfg.RampMax, "ramp-max", 10000, "Maximum RPS for ramp mode")
	flag.Parse()

	fmt.Println("=== Quiver End-to-End Capacity Benchmark ===")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Ensure Database is accessible
	db, err := sql.Open("postgres", cfg.TargetDB)
	if err != nil {
		fmt.Printf("Fatal: Invalid DB connection string: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	db.SetMaxOpenConns(2)

	initialPersisted, err := getDatabaseInsertCount(ctx, db)
	if err != nil {
		fmt.Printf("Fatal: Could not reach Database. Is the backend running? Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Initial database records persisted: %d\n", initialPersisted)

	var wg sync.WaitGroup
	var queryLatencies []float64
	var queryMu sync.Mutex

	startTime := time.Now()
	warnings := []string{}
	bottleneckDetected := false
	actualDuration := float64(0)
	targetRPS := cfg.RPS

	var (
		targetRpsREST atomic.Int64
		targetRpsUDP  atomic.Int64
		targetRpsZeek atomic.Int64
	)

	// Calculate RPS splits: 50% REST, 40% NetFlow, 10% Zeek
	updateRPS := func(totalRPS int) {
		rREST := (totalRPS * 50) / 100
		rUDP := (totalRPS * 40) / 100
		rZeek := (totalRPS * 10) / 100
		if rREST == 0 {
			rREST = 1
		}
		if rUDP == 0 {
			rUDP = 1
		}
		if rZeek == 0 {
			rZeek = 1
		}
		targetRpsREST.Store(int64(rREST))
		targetRpsUDP.Store(int64(rUDP))
		targetRpsZeek.Store(int64(rZeek))
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// Start Contending Query Workers
	for i := 0; i < cfg.QueryWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runQueryWorker(ctx, client, cfg.TargetREST, cfg.AdminKey, &queryMu, &queryLatencies)
		}()
	}

	// Start Ingestion Workers
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runRESTWorker(ctx, cfg, &targetRpsREST)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		runUDPWorker(ctx, cfg, &targetRpsUDP)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		runZeekWorker(ctx, cfg, &targetRpsZeek)
	}()

	if !cfg.Ramp {
		fmt.Printf("Mode: Fixed | Target RPS: %d | Duration: %ds\n", cfg.RPS, cfg.DurationSec)
		updateRPS(cfg.RPS)

		// Fixed mode execution
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(cfg.DurationSec) * time.Second):
		}
		cancel()
		actualDuration = float64(cfg.DurationSec)
	} else {
		fmt.Printf("Mode: Ramping | Start: %d | Step: %d | Interval: %s | Max: %d\n", cfg.RampStart, cfg.RampStep, cfg.RampInterval, cfg.RampMax)
		currentRPS := cfg.RampStart

		for {
			targetRPS = currentRPS
			updateRPS(currentRPS)
			fmt.Printf("-> Ramp Step: %d RPS\n", currentRPS)

			startAccepted := atomic.LoadInt64(&accepted)

			select {
			case <-ctx.Done():
				break
			case <-time.After(cfg.RampInterval):
			}
			if ctx.Err() != nil {
				break
			}

			endAccepted := atomic.LoadInt64(&accepted)
			stepAccepted := endAccepted - startAccepted
			stepAcceptedRPS := float64(stepAccepted) / cfg.RampInterval.Seconds()

			fmt.Printf("   Achieved Accepted RPS: %.2f\n", stepAcceptedRPS)

			// Detect bottleneck: If accepted RPS is < 80% of target after the interval, or high failure rate
			failCount := atomic.LoadInt64(&failed)
			attemptCount := atomic.LoadInt64(&attempted)
			failRate := 0.0
			if attemptCount > 0 {
				failRate = float64(failCount) / float64(attemptCount)
			}

			if stepAcceptedRPS < float64(currentRPS)*0.80 || failRate > 0.05 {
				bottleneckDetected = true
				warnings = append(warnings, fmt.Sprintf("Bottleneck detected at %d RPS. Accepted RPS was %.2f and failure rate was %.1f%%.", currentRPS, stepAcceptedRPS, failRate*100))
				fmt.Println(warnings[len(warnings)-1])
				break
			}

			currentRPS += cfg.RampStep
			if currentRPS > cfg.RampMax {
				fmt.Println("-> Reached maximum ramp RPS.")
				break
			}
		}
		cancel()
		actualDuration = time.Since(startTime).Seconds()
	}

	wg.Wait()

	fmt.Println("Load generation stopped. Entering drain phase to measure durable storage persistence...")

	// Drain Phase: poll metrics until insert count stops increasing
	finalPersisted := uint64(0)
	var prevPersisted uint64
	stagnantCycles := 0
	drainStart := time.Now()

	for time.Since(drainStart) < 120*time.Second {
		currentPersisted, err := getDatabaseInsertCount(context.Background(), db)
		if err == nil {
			if currentPersisted == prevPersisted {
				stagnantCycles++
				if stagnantCycles >= 10 {
					finalPersisted = currentPersisted
					break // Queue is drained
				}
			} else {
				stagnantCycles = 0
			}
			prevPersisted = currentPersisted
			finalPersisted = currentPersisted
		}
		time.Sleep(1 * time.Second)
	}

	totalPersisted := int64(finalPersisted - initialPersisted)
	droppedOrLag := atomic.LoadInt64(&accepted) - totalPersisted
	if droppedOrLag < 0 {
		droppedOrLag = 0
	}

	if droppedOrLag > 0 {
		warnings = append(warnings, fmt.Sprintf("%d records were accepted but not persisted within drain timeout. Kafka consumer lag or drops occurred.", droppedOrLag))
	}

	durableThroughput := float64(totalPersisted) / actualDuration

	// Compute Query Latencies
	queryMu.Lock()
	var lats Latencies
	lats.Count = len(queryLatencies)
	if lats.Count > 0 {
		sort.Float64s(queryLatencies)
		lats.Min = queryLatencies[0]
		lats.Max = queryLatencies[lats.Count-1]
		lats.P50 = queryLatencies[int(float64(lats.Count)*0.50)]
		lats.P95 = queryLatencies[int(float64(lats.Count)*0.95)]
		lats.P99 = queryLatencies[int(float64(lats.Count)*0.99)]
	}
	queryMu.Unlock()

	modeName := "fixed"
	if cfg.Ramp {
		modeName = "ramping"
	}

	result := PerformanceSmoke{
		StartedAt:            startTime.UTC().Format(time.RFC3339),
		DurationSeconds:      actualDuration,
		Mode:                 modeName,
		TargetRPS:            targetRPS,
		RecordsAttempted:     atomic.LoadInt64(&attempted),
		RecordsAccepted:      atomic.LoadInt64(&accepted),
		RecordsPersisted:     totalPersisted,
		RecordsFailed:        atomic.LoadInt64(&failed),
		RecordsDropped:       droppedOrLag,
		ThroughputDurableRPS: durableThroughput,
		QueryLatencies:       lats,
		BottleneckDetected:   bottleneckDetected,
		Warnings:             warnings,
		Notes:                []string{"Load smoke capacity benchmark run complete."},
	}

	artifactPath := "artifacts/performance-smoke.json"
	_ = os.MkdirAll("artifacts", 0755)
	fileBytes, _ := json.MarshalIndent(result, "", "    ")
	_ = os.WriteFile(artifactPath, fileBytes, 0644)

	fmt.Printf("\n=== Results ===\n")
	fmt.Printf("Durable Throughput: %.2f records/sec\n", durableThroughput)
	fmt.Printf("Persisted: %d | Accepted: %d | Failed: %d | Dropped/Lag: %d\n", result.RecordsPersisted, result.RecordsAccepted, result.RecordsFailed, result.RecordsDropped)
	fmt.Printf("Query Latency (P95): %.2f ms\n", lats.P95)
	if bottleneckDetected {
		fmt.Println("⚠️ Bottleneck limit reached during ramp.")
	}
	fmt.Printf("Saved detailed artifact to %s\n", artifactPath)
}

func getDatabaseInsertCount(ctx context.Context, db *sql.DB) (uint64, error) {
	var count uint64
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM quiver.flow_records").Scan(&count)
	return count, err
}

func runRESTWorker(ctx context.Context, cfg Config, targetRPS *atomic.Int64) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	url := fmt.Sprintf("%s/api/v1/ingest/flows", cfg.TargetREST)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	batchSize := 100
	var ticker *time.Ticker

	for {
		currentRPS := int(targetRPS.Load())
		if currentRPS == 0 {
			currentRPS = 1
		}
		rate := (currentRPS / cfg.Workers) / batchSize
		if rate == 0 {
			rate = 1
		}

		if ticker == nil {
			ticker = time.NewTicker(time.Second / time.Duration(rate))
			defer ticker.Stop()
		} else {
			ticker.Reset(time.Second / time.Duration(rate))
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			records := make([]IngestRecord, 0, batchSize)
			for i := 0; i < batchSize; i++ {
				srcPort := uint32(32768 + r.Intn(32768))
				dstPort := uint32(80)
				if r.Intn(2) == 0 {
					dstPort = 443
				}
				bytesVal := uint64(500 + r.Int63n(10000))
				packetsVal := uint64(5 + r.Int63n(100))

				// Slightly vary start time strictly in the past to avoid deduplication
				start := time.Now().UTC().Add(-time.Duration(r.Intn(10000)) * time.Millisecond).Format(time.RFC3339Nano)

				records = append(records, IngestRecord{
					EventStartTime:    start,
					SrcIP:             internalIPs[r.Intn(len(internalIPs))],
					DstIP:             publicIPs[r.Intn(len(publicIPs))],
					SrcPort:           &srcPort,
					DstPort:           &dstPort,
					TransportProtocol: "tcp",
					ProtocolNumber:    6,
					Bytes:             &bytesVal,
					Packets:           &packetsVal,
				})
			}

			atomic.AddInt64(&attempted, int64(batchSize))

			reqBody, err := json.Marshal(IngestRequest{Records: records})
			if err != nil {
				continue
			}

			req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
			req.Header.Set("X-API-Key", cfg.ClientKey)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				atomic.AddInt64(&failed, int64(batchSize))
				continue
			}

			if resp.StatusCode == http.StatusAccepted {
				var ingestResp struct {
					Accepted int `json:"accepted"`
					Rejected int `json:"rejected"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&ingestResp); err == nil {
					atomic.AddInt64(&accepted, int64(ingestResp.Accepted))
					atomic.AddInt64(&failed, int64(ingestResp.Rejected))
				} else {
					atomic.AddInt64(&failed, int64(batchSize))
				}
			} else {
				atomic.AddInt64(&failed, int64(batchSize))
			}
			resp.Body.Close()
		}
	}
}

func runUDPWorker(ctx context.Context, cfg Config, targetRPS *atomic.Int64) {
	conn, err := net.Dial("udp", cfg.TargetUDP)
	if err != nil {
		fmt.Printf("UDP connection failed: %v\n", err)
		return
	}
	defer conn.Close()

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	batchSize := 10
	var ticker *time.Ticker

	var seq uint32 = 1000

	for {
		currentRPS := int(targetRPS.Load())
		if currentRPS == 0 {
			currentRPS = 1
		}
		rate := currentRPS / batchSize
		if rate == 0 {
			rate = 1
		}

		if ticker == nil {
			ticker = time.NewTicker(time.Second / time.Duration(rate))
			defer ticker.Stop()
		} else {
			ticker.Reset(time.Second / time.Duration(rate))
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			atomic.AddInt64(&attempted, int64(batchSize))
			packet := make([]byte, 24+batchSize*48)
			binary.BigEndian.PutUint16(packet[0:2], 5)
			binary.BigEndian.PutUint16(packet[2:4], uint16(batchSize))
			binary.BigEndian.PutUint32(packet[4:8], 10000)
			binary.BigEndian.PutUint32(packet[8:12], uint32(time.Now().Unix()))
			binary.BigEndian.PutUint32(packet[12:16], 125000000)
			binary.BigEndian.PutUint32(packet[16:20], seq)
			packet[20] = 1
			packet[21] = 2
			binary.BigEndian.PutUint16(packet[22:24], 1)

			for i := 0; i < batchSize; i++ {
				offset := 24 + i*48
				record := packet[offset : offset+48]

				// Randomize Source IP (Internal)
				srcIP := internalIPs[r.Intn(len(internalIPs))]
				copy(record[0:4], net.ParseIP(srcIP).To4())
				// Randomize Dest IP (Public)
				dstIP := publicIPs[r.Intn(len(publicIPs))]
				copy(record[4:8], net.ParseIP(dstIP).To4())

				pkts := uint32(1 + r.Intn(100))
				binary.BigEndian.PutUint32(record[16:20], pkts)
				binary.BigEndian.PutUint32(record[20:24], pkts*uint32(250))

				srcPort := uint16(15000 + r.Intn(40000))
				dstPort := uint16(80)
				if r.Intn(2) == 0 {
					dstPort = 443
				} else if r.Intn(5) == 0 {
					dstPort = 53
				}

				binary.BigEndian.PutUint16(record[32:34], srcPort)
				binary.BigEndian.PutUint16(record[34:36], dstPort)

				prot := uint8(6) // TCP
				if dstPort == 53 {
					prot = 17 // UDP
				}
				record[38] = prot
			}

			seq += uint32(batchSize)
			_, err := conn.Write(packet)
			if err != nil {
				atomic.AddInt64(&failed, int64(batchSize))
			} else {
				// We assume acceptance for UDP. Persistence verified by final metrics query.
				atomic.AddInt64(&accepted, int64(batchSize))
			}
		}
	}
}

func runZeekWorker(ctx context.Context, cfg Config, targetRPS *atomic.Int64) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	batchSize := 10
	var ticker *time.Ticker

	client := &http.Client{Timeout: 5 * time.Second}
	var file *os.File
	var err error

	if cfg.ZeekMode == "file" && cfg.TargetZeek != "" {
		dir := filepath.Dir(cfg.TargetZeek)
		_ = os.MkdirAll(dir, 0755)
		file, err = os.OpenFile(cfg.TargetZeek, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Failed to open Zeek log file %s: %v\n", cfg.TargetZeek, err)
			return
		}
		defer file.Close()
	}

	for {
		currentRPS := int(targetRPS.Load())
		if currentRPS == 0 {
			currentRPS = 1
		}
		rate := currentRPS / batchSize
		if rate == 0 {
			rate = 1
		}

		if ticker == nil {
			ticker = time.NewTicker(time.Second / time.Duration(rate))
			defer ticker.Stop()
		} else {
			ticker.Reset(time.Second / time.Duration(rate))
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			atomic.AddInt64(&attempted, int64(batchSize))

			if cfg.ZeekMode == "http" {
				url := fmt.Sprintf("%s/api/v1/ingest/zeek/conn", cfg.TargetREST)
				var records []json.RawMessage
				for i := 0; i < batchSize; i++ {
					rec := generateZeekRecord(r)
					data, _ := json.Marshal(rec)
					records = append(records, data)
				}

				payload, _ := json.Marshal(map[string]any{"records": records})
				req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-API-Key", cfg.ZeekKey)

				resp, err := client.Do(req)
				if err != nil {
					atomic.AddInt64(&failed, int64(batchSize))
					continue
				}
				if resp.StatusCode == http.StatusAccepted {
					atomic.AddInt64(&accepted, int64(batchSize))
				} else {
					atomic.AddInt64(&failed, int64(batchSize))
				}
				resp.Body.Close()
			} else if file != nil {
				// File mode
				var buf bytes.Buffer
				for i := 0; i < batchSize; i++ {
					rec := generateZeekRecord(r)
					data, _ := json.Marshal(rec)
					buf.Write(data)
					buf.WriteByte('\n')
				}
				if _, err := file.Write(buf.Bytes()); err != nil {
					atomic.AddInt64(&failed, int64(batchSize))
				} else {
					atomic.AddInt64(&accepted, int64(batchSize))
				}
			}
		}
	}
}

func generateZeekRecord(r *rand.Rand) ZeekRecord {
	id, _ := domain.NewUUIDv7(time.Now())

	origP := 32768 + r.Intn(32768)
	respP := 80
	proto := "tcp"
	service := "http"

	if r.Intn(3) == 0 {
		respP = 53
		proto = "udp"
		service = "dns"
	} else if r.Intn(3) == 1 {
		respP = 443
		service = "ssl"
	}

	return ZeekRecord{
		TS:        float64(time.Now().UnixNano()) / 1e9,
		UID:       id,
		OrigH:     internalIPs[r.Intn(len(internalIPs))],
		OrigP:     origP,
		RespH:     publicIPs[r.Intn(len(publicIPs))],
		RespP:     respP,
		Proto:     proto,
		Service:   service,
		Duration:  0.01 + r.Float64()*2.0,
		OrigBytes: int64(40 + r.Intn(1000)),
		RespBytes: int64(40 + r.Intn(1000)),
		OrigPkts:  int64(1 + r.Intn(10)),
		RespPkts:  int64(1 + r.Intn(10)),
		ConnState: "SF",
	}
}

func runQueryWorker(ctx context.Context, client *http.Client, targetREST, adminKey string, mu *sync.Mutex, latencies *[]float64) {
	ticker := time.NewTicker(200 * time.Millisecond) // Max 5 queries per second per worker
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fromTime := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
			toTime := time.Now().UTC().Format(time.RFC3339)
			queryURL := fmt.Sprintf("%s/api/v1/flows?from=%s&to=%s&limit=25", targetREST, url.QueryEscape(fromTime), url.QueryEscape(toTime))

			qStart := time.Now()
			req, _ := http.NewRequestWithContext(ctx, "GET", queryURL, nil)
			req.Header.Set("X-API-Key", adminKey)

			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					lat := float64(time.Since(qStart).Milliseconds())
					mu.Lock()
					*latencies = append(*latencies, lat)
					mu.Unlock()
				}
			}
		}
	}
}
