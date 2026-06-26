//nolint:gosec // This load generator intentionally uses non-cryptographic randomness and local artifact files.
package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"github.com/adnope/quiver/internal/domain"
)

type PerformanceSmoke struct {
	StartedAt            string                 `json:"started_at"`
	DurationSeconds      float64                `json:"duration_seconds"`
	Mode                 string                 `json:"mode"`
	TargetRPS            int                    `json:"target_rps"`
	RecordsAttempted     int64                  `json:"records_attempted"`
	RecordsAccepted      int64                  `json:"records_accepted"`
	RecordsPersisted     int64                  `json:"records_persisted"`
	RecordsFailed        int64                  `json:"records_failed"`
	RecordsDropped       int64                  `json:"records_dropped_or_lag"`
	ThroughputDurableRPS float64                `json:"throughput_durable_rps"`
	QueryLatencies       Latencies              `json:"query_latencies"`
	SourceBreakdown      map[string]SourceStats `json:"source_breakdown"`
	BottleneckDetected   bool                   `json:"bottleneck_detected"`
	Warnings             []string               `json:"warnings"`
	Notes                []string               `json:"notes"`
}

type Latencies struct {
	Count int     `json:"count"`
	Min   float64 `json:"min_ms"`
	P50   float64 `json:"p50_ms"`
	P95   float64 `json:"p95_ms"`
	P99   float64 `json:"p99_ms"`
	Max   float64 `json:"max_ms"`
}

type SourceStats struct {
	TargetRPS        int64   `json:"target_rps"`
	RecordsAttempted int64   `json:"records_attempted"`
	RecordsAccepted  int64   `json:"records_accepted"`
	RecordsFailed    int64   `json:"records_failed"`
	AttemptedRPS     float64 `json:"attempted_rps"`
	AcceptedRPS      float64 `json:"accepted_rps"`
	FailureRate      float64 `json:"failure_rate"`
}

type sourceCounters struct {
	attempted atomic.Int64
	accepted  atomic.Int64
	failed    atomic.Int64
}

type sourceSnapshot struct {
	attempted int64
	accepted  int64
	failed    int64
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

var (
	internalIPs = []string{"192.168.1.10", "192.168.1.50", "10.0.0.5", "172.16.5.12"}
	publicIPs   = []string{"8.8.8.8", "1.1.1.1", "142.250.190.46", "104.244.42.1"}

	attempted atomic.Int64
	accepted  atomic.Int64
	failed    atomic.Int64

	restCounters sourceCounters
	udpCounters  sourceCounters
	zeekCounters sourceCounters
)

type Config struct {
	TargetREST string
	TargetUDP  string
	TargetZeek string
	TargetDB   string
	ZeekMode   string
	AdminKey   string
	ClientKey  string
	ZeekKey    string

	DurationSec  int
	RPS          int
	Workers      int
	RESTWorkers  int
	UDPWorkers   int
	ZeekWorkers  int
	QueryWorkers int

	RESTBatchSize int
	UDPBatchSize  int
	ZeekBatchSize int

	MixREST int
	MixUDP  int
	MixZeek int

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

	flag.IntVar(&cfg.Workers, "workers", 4, "Deprecated alias for -rest-workers when -rest-workers is not set")
	flag.IntVar(&cfg.RESTWorkers, "rest-workers", 0, "Number of REST ingest workers. Defaults to -workers for backwards compatibility")
	flag.IntVar(&cfg.UDPWorkers, "udp-workers", 1, "Number of UDP NetFlow workers")
	flag.IntVar(&cfg.ZeekWorkers, "zeek-workers", 1, "Number of Zeek workers")
	flag.IntVar(&cfg.QueryWorkers, "query-workers", 2, "Number of concurrent query contention workers")

	flag.IntVar(&cfg.RESTBatchSize, "rest-batch-size", 100, "Records per REST ingest request")
	flag.IntVar(&cfg.UDPBatchSize, "udp-batch-size", 10, "NetFlow records per UDP packet")
	flag.IntVar(&cfg.ZeekBatchSize, "zeek-batch-size", 10, "Zeek records per file write or HTTP request")

	flag.IntVar(&cfg.MixREST, "mix-rest", 50, "REST source mix percentage/weight")
	flag.IntVar(&cfg.MixUDP, "mix-udp", 40, "UDP NetFlow source mix percentage/weight")
	flag.IntVar(&cfg.MixZeek, "mix-zeek", 10, "Zeek source mix percentage/weight")

	flag.BoolVar(&cfg.Ramp, "ramp", false, "Enable ramping auto-tuning mode to find max throughput")
	flag.IntVar(&cfg.RampStart, "ramp-start", 200, "Start RPS for ramp mode")
	flag.IntVar(&cfg.RampStep, "ramp-step", 200, "Step RPS for ramp mode")
	flag.DurationVar(&cfg.RampInterval, "ramp-interval", 10*time.Second, "Step duration for ramp mode")
	flag.IntVar(&cfg.RampMax, "ramp-max", 10000, "Maximum RPS for ramp mode")
	flag.Parse()

	if cfg.RESTWorkers <= 0 {
		cfg.RESTWorkers = cfg.Workers
	}
	normalizeConfig(&cfg)

	fmt.Println("=== Quiver End-to-End Capacity Benchmark ===")
	fmt.Printf("Source mix: REST=%d UDP=%d Zeek=%d | workers: REST=%d UDP=%d Zeek=%d | batch sizes: REST=%d UDP=%d Zeek=%d\n",
		cfg.MixREST,
		cfg.MixUDP,
		cfg.MixZeek,
		cfg.RESTWorkers,
		cfg.UDPWorkers,
		cfg.ZeekWorkers,
		cfg.RESTBatchSize,
		cfg.UDPBatchSize,
		cfg.ZeekBatchSize,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	client := &http.Client{Timeout: 5 * time.Second}

	db, err := sql.Open("postgres", cfg.TargetDB)
	if err != nil {
		fmt.Printf("Fatal: Invalid DB connection string: %v\n", err)
		os.Exit(1)
	}
	defer closeAndLog("database connection", db)
	db.SetMaxOpenConns(2)

	initialPersisted, persistedSource, err := getPersistedCount(ctx, cfg, client, db)
	if err != nil {
		fmt.Printf("Fatal: Could not read persisted count. Is the backend running? Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Initial records persisted counter (%s): %d\n", persistedSource, initialPersisted)

	var wg sync.WaitGroup
	var queryLatencies []float64
	var queryMu sync.Mutex

	startTime := time.Now()
	warnings := []string{}
	bottleneckDetected := false
	var actualDuration float64
	targetRPS := cfg.RPS
	generatorUnderproducedSteps := 0

	var (
		targetRpsREST atomic.Int64
		targetRpsUDP  atomic.Int64
		targetRpsZeek atomic.Int64
	)

	updateRPS := func(totalRPS int) {
		rREST, rUDP, rZeek := splitSourceRPS(totalRPS, cfg)
		targetRpsREST.Store(int64(rREST))
		targetRpsUDP.Store(int64(rUDP))
		targetRpsZeek.Store(int64(rZeek))
	}

	for range cfg.QueryWorkers {
		wg.Go(func() {
			runQueryWorker(ctx, client, cfg.TargetREST, cfg.AdminKey, &queryMu, &queryLatencies)
		})
	}

	for i := 0; i < cfg.RESTWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			runRESTWorker(ctx, cfg, workerID, &targetRpsREST)
		}(i)
	}
	for i := 0; i < cfg.UDPWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			runUDPWorker(ctx, cfg, workerID, &targetRpsUDP)
		}(i)
	}
	for i := 0; i < cfg.ZeekWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			runZeekWorker(ctx, cfg, workerID, &targetRpsZeek)
		}(i)
	}

	if !cfg.Ramp {
		fmt.Printf("Mode: Fixed | Target RPS: %d | Duration: %ds\n", cfg.RPS, cfg.DurationSec)
		updateRPS(cfg.RPS)

		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(cfg.DurationSec) * time.Second):
		}
		cancel()
		actualDuration = float64(cfg.DurationSec)
	} else {
		fmt.Printf("Mode: Ramping | Start: %d | Step: %d | Interval: %s | Max: %d\n", cfg.RampStart, cfg.RampStep, cfg.RampInterval, cfg.RampMax)
		currentRPS := cfg.RampStart

	rampLoop:
		for {
			targetRPS = currentRPS
			updateRPS(currentRPS)
			restTarget, udpTarget, zeekTarget := splitSourceRPS(currentRPS, cfg)
			fmt.Printf("-> Ramp Step: %d RPS (REST=%d UDP=%d Zeek=%d)\n", currentRPS, restTarget, udpTarget, zeekTarget)

			startAttempted := attempted.Load()
			startAccepted := accepted.Load()
			startFailed := failed.Load()

			startREST := snapshotCounters(&restCounters)
			startUDP := snapshotCounters(&udpCounters)
			startZeek := snapshotCounters(&zeekCounters)

			select {
			case <-ctx.Done():
				break rampLoop
			case <-time.After(cfg.RampInterval):
			}
			if ctx.Err() != nil {
				break rampLoop
			}

			endAttempted := attempted.Load()
			endAccepted := accepted.Load()
			endFailed := failed.Load()

			stepAttempted := endAttempted - startAttempted
			stepAccepted := endAccepted - startAccepted
			stepFailed := endFailed - startFailed

			stepAttemptedRPS := float64(stepAttempted) / cfg.RampInterval.Seconds()
			stepAcceptedRPS := float64(stepAccepted) / cfg.RampInterval.Seconds()
			stepFailedRPS := float64(stepFailed) / cfg.RampInterval.Seconds()

			stepFailRate := 0.0
			if stepAttempted > 0 {
				stepFailRate = float64(stepFailed) / float64(stepAttempted)
			}

			acceptanceRate := 1.0
			if stepAttempted > 0 {
				acceptanceRate = float64(stepAccepted) / float64(stepAttempted)
			}

			fmt.Printf("   Attempted RPS: %.2f | Accepted RPS: %.2f | Failed RPS: %.2f | Failure Rate: %.1f%% | Accepted/Attempted: %.1f%%\n",
				stepAttemptedRPS, stepAcceptedRPS, stepFailedRPS, stepFailRate*100, acceptanceRate*100)
			printSourceStep("REST", startREST, snapshotCounters(&restCounters), cfg.RampInterval)
			printSourceStep("UDP ", startUDP, snapshotCounters(&udpCounters), cfg.RampInterval)
			printSourceStep("Zeek", startZeek, snapshotCounters(&zeekCounters), cfg.RampInterval)

			if stepAttemptedRPS < float64(currentRPS)*0.80 {
				generatorUnderproducedSteps++
				fmt.Printf("   Load generator under-produced this step: attempted %.2f RPS for target %d RPS. Continuing ramp (%d/3).\n",
					stepAttemptedRPS, currentRPS, generatorUnderproducedSteps)
				if generatorUnderproducedSteps >= 3 {
					bottleneckDetected = true
					warnings = append(warnings, fmt.Sprintf("Load generator limit detected at %d RPS. Attempted RPS was %.2f, accepted RPS was %.2f, failure rate was %.1f%%.", currentRPS, stepAttemptedRPS, stepAcceptedRPS, stepFailRate*100))
					fmt.Println(warnings[len(warnings)-1])
					break
				}
			} else {
				generatorUnderproducedSteps = 0
				if acceptanceRate < 0.95 || stepFailRate > 0.05 {
					bottleneckDetected = true
					warnings = append(warnings, fmt.Sprintf("Backend bottleneck detected at %d RPS. Attempted RPS was %.2f, accepted RPS was %.2f, failure rate was %.1f%%.", currentRPS, stepAttemptedRPS, stepAcceptedRPS, stepFailRate*100))
					fmt.Println(warnings[len(warnings)-1])
					break
				}
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

	finalPersisted := uint64(0)
	var prevPersisted uint64
	stagnantCycles := 0
	drainStart := time.Now()
	lastIncreaseTime := drainStart

	for time.Since(drainStart) < 120*time.Second {
		currentPersisted, _, err := getPersistedCount(context.Background(), cfg, client, db)
		if err == nil {
			if currentPersisted != prevPersisted {
				lastIncreaseTime = time.Now()
				stagnantCycles = 0
			} else {
				stagnantCycles++
				if stagnantCycles >= 10 {
					finalPersisted = currentPersisted
					break
				}
			}
			prevPersisted = currentPersisted
			finalPersisted = currentPersisted
		}
		time.Sleep(1 * time.Second)
	}

	totalPersisted := int64(finalPersisted - initialPersisted)
	droppedOrLag := max(accepted.Load()-totalPersisted, 0)

	if droppedOrLag > 0 {
		warnings = append(warnings, fmt.Sprintf("%d records were accepted but not persisted within drain timeout. Kafka consumer lag or drops occurred.", droppedOrLag))
	}

	totalPersistenceDuration := lastIncreaseTime.Sub(startTime)
	if totalPersistenceDuration <= 0 {
		totalPersistenceDuration = time.Second
	}
	durableThroughput := float64(totalPersisted) / totalPersistenceDuration.Seconds()
	avgIngestionRPS := float64(accepted.Load()) / actualDuration
	drainDuration := lastIncreaseTime.Sub(drainStart)
	drainDuration = max(drainDuration, 0)

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

	sourceBreakdown := map[string]SourceStats{
		"rest": snapshotSourceStats(&restCounters, targetRpsREST.Load(), actualDuration),
		"udp":  snapshotSourceStats(&udpCounters, targetRpsUDP.Load(), actualDuration),
		"zeek": snapshotSourceStats(&zeekCounters, targetRpsZeek.Load(), actualDuration),
	}

	result := PerformanceSmoke{
		StartedAt:            startTime.UTC().Format(time.RFC3339),
		DurationSeconds:      actualDuration,
		Mode:                 modeName,
		TargetRPS:            targetRPS,
		RecordsAttempted:     attempted.Load(),
		RecordsAccepted:      accepted.Load(),
		RecordsPersisted:     totalPersisted,
		RecordsFailed:        failed.Load(),
		RecordsDropped:       droppedOrLag,
		ThroughputDurableRPS: durableThroughput,
		QueryLatencies:       lats,
		SourceBreakdown:      sourceBreakdown,
		BottleneckDetected:   bottleneckDetected,
		Warnings:             warnings,
		Notes: []string{
			fmt.Sprintf("Average Ingestion Rate: %.2f records/sec (over %.2fs active load)", avgIngestionRPS, actualDuration),
			fmt.Sprintf("Durable Write Throughput: %.2f records/sec (over %.2fs total write time)", durableThroughput, totalPersistenceDuration.Seconds()),
			fmt.Sprintf("Drain Phase Duration: %.2fs", drainDuration.Seconds()),
			fmt.Sprintf("Source mix weights: REST=%d UDP=%d Zeek=%d", cfg.MixREST, cfg.MixUDP, cfg.MixZeek),
			fmt.Sprintf("Workers: REST=%d UDP=%d Zeek=%d Query=%d", cfg.RESTWorkers, cfg.UDPWorkers, cfg.ZeekWorkers, cfg.QueryWorkers),
			fmt.Sprintf("Batch sizes: REST=%d UDP=%d Zeek=%d", cfg.RESTBatchSize, cfg.UDPBatchSize, cfg.ZeekBatchSize),
			"Persistence is measured from flow_records_stored_total when /metrics is available, otherwise from SELECT COUNT(*).",
			"Source breakdown uses record counts, not HTTP request counts.",
		},
	}

	artifactPath := "artifacts/performance-smoke.json"
	if err := os.MkdirAll("artifacts", 0o750); err != nil {
		fmt.Printf("Failed to create artifacts directory: %v\n", err)
	} else {
		fileBytes, err := json.MarshalIndent(result, "", "    ")
		if err != nil {
			fmt.Printf("Failed to encode performance artifact: %v\n", err)
		} else if err := os.WriteFile(artifactPath, fileBytes, 0o600); err != nil {
			fmt.Printf("Failed to write performance artifact: %v\n", err)
		}
	}

	fmt.Printf("\n=== Results ===\n")
	fmt.Printf("Average Ingestion Rate:   %.2f records/sec (over %.2fs active load)\n", avgIngestionRPS, actualDuration)
	fmt.Printf("Durable Write Throughput:  %.2f records/sec (over %.2fs total write time)\n", durableThroughput, totalPersistenceDuration.Seconds())
	fmt.Printf("Drain Phase Duration:      %.2fs\n", drainDuration.Seconds())
	fmt.Printf("Persisted: %d | Accepted: %d | Failed: %d | Dropped/Lag: %d\n", result.RecordsPersisted, result.RecordsAccepted, result.RecordsFailed, result.RecordsDropped)
	fmt.Printf("Source Breakdown:\n")
	printSourceSummary("REST", sourceBreakdown["rest"])
	printSourceSummary("UDP ", sourceBreakdown["udp"])
	printSourceSummary("Zeek", sourceBreakdown["zeek"])
	fmt.Printf("Query Latency (P95): %.2f ms\n", lats.P95)
	if bottleneckDetected {
		fmt.Println("⚠️ Bottleneck limit reached during ramp.")
	}
	fmt.Printf("Saved detailed artifact to %s\n", artifactPath)
}

func normalizeConfig(cfg *Config) {
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.RESTWorkers < 0 {
		cfg.RESTWorkers = 0
	}
	if cfg.UDPWorkers < 0 {
		cfg.UDPWorkers = 0
	}
	if cfg.ZeekWorkers < 0 {
		cfg.ZeekWorkers = 0
	}
	if cfg.QueryWorkers < 0 {
		cfg.QueryWorkers = 0
	}
	if cfg.RESTBatchSize <= 0 {
		cfg.RESTBatchSize = 100
	}
	if cfg.UDPBatchSize <= 0 {
		cfg.UDPBatchSize = 10
	}
	if cfg.ZeekBatchSize <= 0 {
		cfg.ZeekBatchSize = 10
	}
	if cfg.MixREST < 0 {
		cfg.MixREST = 0
	}
	if cfg.MixUDP < 0 {
		cfg.MixUDP = 0
	}
	if cfg.MixZeek < 0 {
		cfg.MixZeek = 0
	}
	if cfg.MixREST+cfg.MixUDP+cfg.MixZeek == 0 {
		cfg.MixREST = 50
		cfg.MixUDP = 40
		cfg.MixZeek = 10
	}
	if cfg.MixREST > 0 && cfg.RESTWorkers == 0 {
		cfg.RESTWorkers = 1
	}
	if cfg.MixUDP > 0 && cfg.UDPWorkers == 0 {
		cfg.UDPWorkers = 1
	}
	if cfg.MixZeek > 0 && cfg.ZeekWorkers == 0 {
		cfg.ZeekWorkers = 1
	}
}

func splitSourceRPS(totalRPS int, cfg Config) (int, int, int) {
	if totalRPS <= 0 {
		return 0, 0, 0
	}

	totalWeight := cfg.MixREST + cfg.MixUDP + cfg.MixZeek
	if totalWeight <= 0 {
		return 0, 0, 0
	}

	rest := (totalRPS * cfg.MixREST) / totalWeight
	udp := (totalRPS * cfg.MixUDP) / totalWeight
	zeek := totalRPS - rest - udp

	if cfg.MixREST == 0 {
		rest = 0
	}
	if cfg.MixUDP == 0 {
		udp = 0
	}
	if cfg.MixZeek == 0 {
		zeek = 0
	}

	if cfg.MixREST > 0 && rest == 0 {
		rest = 1
	}
	if cfg.MixUDP > 0 && udp == 0 {
		udp = 1
	}
	if cfg.MixZeek > 0 && zeek == 0 {
		zeek = 1
	}

	return rest, udp, zeek
}

func getPersistedCount(ctx context.Context, cfg Config, client *http.Client, db *sql.DB) (uint64, string, error) {
	count, err := getStoredMetric(ctx, client, cfg.TargetREST, cfg.AdminKey)
	if err == nil {
		return count, "metrics:flow_records_stored_total", nil
	}

	dbCount, dbErr := getDatabaseInsertCount(ctx, db)
	if dbErr == nil {
		return dbCount, "db:count_flow_records", nil
	}

	return 0, "", fmt.Errorf("metrics read failed: %w; db count failed: %w", err, dbErr)
}

func getStoredMetric(ctx context.Context, client *http.Client, targetREST, adminKey string) (uint64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/metrics", targetREST), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-API-Key", adminKey)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Failed to close metrics response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("metrics returned status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "flow_records_stored_total ") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			value, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				return 0, err
			}
			if value < 0 {
				return 0, fmt.Errorf("flow_records_stored_total was negative: %f", value)
			}
			return uint64(value), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return 0, fmt.Errorf("flow_records_stored_total not found")
}

func getDatabaseInsertCount(ctx context.Context, db *sql.DB) (uint64, error) {
	var count uint64
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM quiver.flow_records").Scan(&count)
	return count, err
}

func runRESTWorker(ctx context.Context, cfg Config, workerID int, targetRPS *atomic.Int64) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        maxInt(100, cfg.RESTWorkers*4),
			MaxIdleConnsPerHost: maxInt(100, cfg.RESTWorkers*4),
			IdleConnTimeout:     90 * time.Second,
		},
	}
	targetURL := fmt.Sprintf("%s/api/v1/ingest/flows", cfg.TargetREST)
	r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))

	batchSize := cfg.RESTBatchSize
	var ticker *time.Ticker

	for {
		if ctx.Err() != nil {
			return
		}

		currentRPS := int(targetRPS.Load())
		if currentRPS <= 0 {
			if !waitOrDone(ctx, 100*time.Millisecond) {
				return
			}
			continue
		}

		activeWorkers := activeWorkersForTarget(currentRPS, cfg.RESTWorkers, batchSize)
		if workerID >= activeWorkers {
			if !waitOrDone(ctx, 100*time.Millisecond) {
				return
			}
			continue
		}

		interval := intervalForBatch(currentRPS, batchSize, activeWorkers)
		if ticker == nil {
			ticker = time.NewTicker(interval)
			defer ticker.Stop()
		} else {
			ticker.Reset(interval)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			records := make([]IngestRecord, 0, batchSize)
			for range batchSize {
				srcPort := uint32(32768 + r.Intn(32768))
				dstPort := uint32(80)
				if r.Intn(2) == 0 {
					dstPort = 443
				}
				bytesVal := uint64(500 + r.Int63n(10000))
				packetsVal := uint64(5 + r.Int63n(100))

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

			recordAttempt(&restCounters, int64(batchSize))

			reqBody, err := json.Marshal(IngestRequest{Records: records})
			if err != nil {
				recordFailure(&restCounters, int64(batchSize))
				continue
			}

			sendRESTIngestBatch(ctx, client, targetURL, cfg.ClientKey, reqBody, batchSize)
		}
	}
}

func sendRESTIngestBatch(ctx context.Context, client *http.Client, targetURL string, clientKey string, reqBody []byte, batchSize int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(reqBody))
	if err != nil {
		recordFailure(&restCounters, int64(batchSize))
		return
	}
	req.Header.Set("X-API-Key", clientKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		recordFailure(&restCounters, int64(batchSize))
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Failed to close REST ingest response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusAccepted {
		recordFailure(&restCounters, int64(batchSize))
		return
	}

	var ingestResp struct {
		Accepted int `json:"accepted"`
		Rejected int `json:"rejected"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ingestResp); err != nil {
		recordFailure(&restCounters, int64(batchSize))
		return
	}

	recordAccepted(&restCounters, int64(ingestResp.Accepted))
	recordFailure(&restCounters, int64(ingestResp.Rejected))
}

func runUDPWorker(ctx context.Context, cfg Config, workerID int, targetRPS *atomic.Int64) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", cfg.TargetUDP)
	if err != nil {
		fmt.Printf("UDP connection failed for worker %d: %v\n", workerID, err)
		return
	}
	defer closeAndLog("UDP connection", conn)

	r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)*1009))
	batchSize := cfg.UDPBatchSize
	var ticker *time.Ticker

	seq := uint32(1000 + workerID*1_000_000)

	for {
		if ctx.Err() != nil {
			return
		}

		currentRPS := int(targetRPS.Load())
		if currentRPS <= 0 {
			if !waitOrDone(ctx, 100*time.Millisecond) {
				return
			}
			continue
		}

		activeWorkers := activeWorkersForTarget(currentRPS, cfg.UDPWorkers, batchSize)
		if workerID >= activeWorkers {
			if !waitOrDone(ctx, 100*time.Millisecond) {
				return
			}
			continue
		}

		interval := intervalForBatch(currentRPS, batchSize, activeWorkers)
		if ticker == nil {
			ticker = time.NewTicker(interval)
			defer ticker.Stop()
		} else {
			ticker.Reset(interval)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			recordAttempt(&udpCounters, int64(batchSize))

			packet := make([]byte, 24+batchSize*48)
			binary.BigEndian.PutUint16(packet[0:2], 5)
			binary.BigEndian.PutUint16(packet[2:4], uint16(batchSize))
			binary.BigEndian.PutUint32(packet[4:8], 10000)
			binary.BigEndian.PutUint32(packet[8:12], uint32(time.Now().Unix()))
			binary.BigEndian.PutUint32(packet[12:16], 125000000)
			binary.BigEndian.PutUint32(packet[16:20], seq)
			packet[20] = 1
			packet[21] = 2
			binary.BigEndian.PutUint16(packet[22:24], uint16(workerID+1))

			for i := range batchSize {
				offset := 24 + i*48
				record := packet[offset : offset+48]

				srcIP := internalIPs[r.Intn(len(internalIPs))]
				copy(record[0:4], net.ParseIP(srcIP).To4())

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

				prot := uint8(6)
				if dstPort == 53 {
					prot = 17
				}
				record[38] = prot
			}

			seq += uint32(batchSize)
			_, err := conn.Write(packet)
			if err != nil {
				recordFailure(&udpCounters, int64(batchSize))
			} else {
				recordAccepted(&udpCounters, int64(batchSize))
			}
		}
	}
}

func runZeekWorker(ctx context.Context, cfg Config, workerID int, targetRPS *atomic.Int64) {
	r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)*2003))
	batchSize := cfg.ZeekBatchSize
	var ticker *time.Ticker

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        maxInt(100, cfg.ZeekWorkers*4),
			MaxIdleConnsPerHost: maxInt(100, cfg.ZeekWorkers*4),
			IdleConnTimeout:     90 * time.Second,
		},
	}
	var file *os.File
	var err error

	if cfg.ZeekMode == "file" && cfg.TargetZeek != "" {
		dir := filepath.Dir(cfg.TargetZeek)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			fmt.Printf("Failed to create Zeek log directory %s: %v\n", dir, err)
			return
		}
		file, err = os.OpenFile(cfg.TargetZeek, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Printf("Failed to open Zeek log file %s: %v\n", cfg.TargetZeek, err)
			return
		}
		defer closeAndLog("Zeek log file", file)
	}

	for {
		if ctx.Err() != nil {
			return
		}

		currentRPS := int(targetRPS.Load())
		if currentRPS <= 0 {
			if !waitOrDone(ctx, 100*time.Millisecond) {
				return
			}
			continue
		}

		activeWorkers := activeWorkersForTarget(currentRPS, cfg.ZeekWorkers, batchSize)
		if workerID >= activeWorkers {
			if !waitOrDone(ctx, 100*time.Millisecond) {
				return
			}
			continue
		}

		interval := intervalForBatch(currentRPS, batchSize, activeWorkers)
		if ticker == nil {
			ticker = time.NewTicker(interval)
			defer ticker.Stop()
		} else {
			ticker.Reset(interval)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			recordAttempt(&zeekCounters, int64(batchSize))

			if cfg.ZeekMode == "http" {
				targetURL := fmt.Sprintf("%s/api/v1/ingest/zeek/conn", cfg.TargetREST)
				records := make([]json.RawMessage, 0, batchSize)
				for range batchSize {
					rec := generateZeekRecord(r)
					data, _ := json.Marshal(rec)
					records = append(records, data)
				}

				payload, _ := json.Marshal(map[string]any{"records": records})
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
				if err != nil {
					recordFailure(&zeekCounters, int64(batchSize))
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-API-Key", cfg.ZeekKey)

				resp, err := client.Do(req)
				if err != nil {
					recordFailure(&zeekCounters, int64(batchSize))
					continue
				}
				if resp.StatusCode == http.StatusAccepted {
					recordAccepted(&zeekCounters, int64(batchSize))
				} else {
					recordFailure(&zeekCounters, int64(batchSize))
				}
				if err := resp.Body.Close(); err != nil {
					fmt.Printf("Failed to close Zeek ingest response body: %v\n", err)
				}
			} else if file != nil {
				var buf bytes.Buffer
				for range batchSize {
					rec := generateZeekRecord(r)
					data, _ := json.Marshal(rec)
					buf.Write(data)
					buf.WriteByte('\n')
				}
				if _, err := file.Write(buf.Bytes()); err != nil {
					recordFailure(&zeekCounters, int64(batchSize))
				} else {
					recordAccepted(&zeekCounters, int64(batchSize))
				}
			}
		}
	}
}

func generateZeekRecord(r *rand.Rand) ZeekRecord {
	id, _ := domain.NewUUIDv7(time.Now())

	origP := 32768 + r.Intn(32768)
	respP := 80
	protoName := "tcp"
	service := "http"

	if r.Intn(3) == 0 {
		respP = 53
		protoName = "udp"
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
		Proto:     protoName,
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
	ticker := time.NewTicker(200 * time.Millisecond)
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
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("X-API-Key", adminKey)

			resp, err := client.Do(req)
			if err == nil {
				statusCode := resp.StatusCode
				if err := resp.Body.Close(); err != nil {
					fmt.Printf("Failed to close query response body: %v\n", err)
				}
				if statusCode == http.StatusOK {
					lat := float64(time.Since(qStart).Milliseconds())
					mu.Lock()
					*latencies = append(*latencies, lat)
					mu.Unlock()
				}
			}
		}
	}
}

func intervalForBatch(targetRPS int, batchSize int, workers int) time.Duration {
	if targetRPS <= 0 {
		targetRPS = 1
	}
	if batchSize <= 0 {
		batchSize = 1
	}
	if workers <= 0 {
		workers = 1
	}

	perWorkerRPS := float64(targetRPS) / float64(workers)
	if perWorkerRPS <= 0 {
		perWorkerRPS = 1
	}

	interval := time.Duration(float64(time.Second) * float64(batchSize) / perWorkerRPS)
	if interval < time.Millisecond {
		return time.Millisecond
	}
	return interval
}

func activeWorkersForTarget(targetRPS int, workers int, batchSize int) int {
	if workers <= 0 || targetRPS <= 0 {
		return 0
	}
	if batchSize <= 0 {
		batchSize = 1
	}

	const desiredMinInterval = 100 * time.Millisecond

	active := int(math.Ceil(float64(targetRPS) * desiredMinInterval.Seconds() / float64(batchSize)))
	active = max(active, 1)
	active = min(active, workers)
	return active
}

func waitOrDone(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func recordAttempt(c *sourceCounters, n int64) {
	c.attempted.Add(n)
	attempted.Add(n)
}

func recordAccepted(c *sourceCounters, n int64) {
	c.accepted.Add(n)
	accepted.Add(n)
}

func recordFailure(c *sourceCounters, n int64) {
	c.failed.Add(n)
	failed.Add(n)
}

func snapshotCounters(c *sourceCounters) sourceSnapshot {
	return sourceSnapshot{
		attempted: c.attempted.Load(),
		accepted:  c.accepted.Load(),
		failed:    c.failed.Load(),
	}
}

func snapshotSourceStats(c *sourceCounters, targetRPS int64, durationSeconds float64) SourceStats {
	s := snapshotCounters(c)
	if durationSeconds <= 0 {
		durationSeconds = 1
	}

	failureRate := 0.0
	if s.attempted > 0 {
		failureRate = float64(s.failed) / float64(s.attempted)
	}

	return SourceStats{
		TargetRPS:        targetRPS,
		RecordsAttempted: s.attempted,
		RecordsAccepted:  s.accepted,
		RecordsFailed:    s.failed,
		AttemptedRPS:     float64(s.attempted) / durationSeconds,
		AcceptedRPS:      float64(s.accepted) / durationSeconds,
		FailureRate:      failureRate,
	}
}

func printSourceStep(name string, before sourceSnapshot, after sourceSnapshot, interval time.Duration) {
	seconds := interval.Seconds()
	if seconds <= 0 {
		seconds = 1
	}

	attemptedDelta := after.attempted - before.attempted
	acceptedDelta := after.accepted - before.accepted
	failedDelta := after.failed - before.failed

	failRate := 0.0
	if attemptedDelta > 0 {
		failRate = float64(failedDelta) / float64(attemptedDelta)
	}

	fmt.Printf("      %s attempted %.2f rps | accepted %.2f rps | failed %.2f rps | failure %.1f%%\n",
		name,
		float64(attemptedDelta)/seconds,
		float64(acceptedDelta)/seconds,
		float64(failedDelta)/seconds,
		failRate*100,
	)
}

func printSourceSummary(name string, stats SourceStats) {
	fmt.Printf("  %s target=%d rps | attempted=%.2f rps | accepted=%.2f rps | failed=%d | failure=%.1f%%\n",
		name,
		stats.TargetRPS,
		stats.AttemptedRPS,
		stats.AcceptedRPS,
		stats.RecordsFailed,
		stats.FailureRate*100,
	)
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func closeAndLog(name string, closer interface{ Close() error }) {
	if err := closer.Close(); err != nil {
		fmt.Printf("Failed to close %s: %v\n", name, err)
	}
}
