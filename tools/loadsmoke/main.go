package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type PerformanceSmoke struct {
	StartedAt        string   `json:"started_at"`
	DurationSeconds  float64  `json:"duration_seconds"`
	Source           string   `json:"source"`
	RecordsAttempted int64    `json:"records_attempted"`
	RecordsAccepted  int64    `json:"records_accepted"`
	RecordsStored    int64    `json:"records_stored"`
	RecordsFailed    int64    `json:"records_failed"`
	RecordsPerSecond float64  `json:"records_per_second"`
	QueryP95Ms       float64  `json:"query_p95_ms"`
	Notes            []string `json:"notes"`
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

func main() {
	targetREST := flag.String("rest", "http://localhost:8080", "Target REST API Base URL")
	targetUDP := flag.String("udp", "localhost:2055", "Target UDP address host:port")
	targetZeek := flag.String("zeek", "/tmp/zeek/conn.log", "Target Zeek log file path")
	key := flag.String("key", "democlientkey456", "API Key with ingest scope")
	durationSec := flag.Int("duration", 30, "Duration of the smoke test in seconds")
	flag.Parse()

	fmt.Printf("Starting load smoke test for %ds against REST=%s, UDP=%s, Zeek=%s\n", *durationSec, *targetREST, *targetUDP, *targetZeek)

	startTime := time.Now()

	var attempted int64
	var accepted int64
	var failed int64

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*durationSec)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	// 1. REST Worker Loop
	wg.Go(func() {
		client := &http.Client{Timeout: 3 * time.Second}
		url := fmt.Sprintf("%s/api/v1/ingest/flows", *targetREST)

		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Generate batch of 100 records
				batchSize := 100
				records := make([]IngestRecord, 0, batchSize)
				for range batchSize {
					srcPort := uint32(20000 + rand.Intn(10000))
					dstPort := uint32(80)
					bytesVal := uint64(500 + rand.Int63n(10000))
					packetsVal := uint64(5 + rand.Int63n(100))
					records = append(records, IngestRecord{
						EventStartTime:    time.Now().UTC().Format(time.RFC3339Nano),
						SrcIP:             "192.168.1.10",
						DstIP:             "8.8.8.8",
						SrcPort:           &srcPort,
						DstPort:           &dstPort,
						TransportProtocol: "tcp",
						ProtocolNumber:    6,
						Bytes:             &bytesVal,
						Packets:           &packetsVal,
					})
				}

				reqObj := IngestRequest{Records: records}
				reqBody, err := json.Marshal(reqObj)
				if err != nil {
					continue
				}

				atomic.AddInt64(&attempted, int64(batchSize))

				req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
				if err != nil {
					atomic.AddInt64(&failed, int64(batchSize))
					continue
				}
				req.Header.Set("X-API-Key", *key)
				req.Header.Set("Content-Type", "application/json")

				resp, err := client.Do(req)
				if err != nil {
					atomic.AddInt64(&failed, int64(batchSize))
					continue
				}
				respBody, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if resp.StatusCode == http.StatusAccepted {
					var ingestResp struct {
						Accepted int `json:"accepted"`
						Rejected int `json:"rejected"`
					}
					if err := json.Unmarshal(respBody, &ingestResp); err == nil {
						atomic.AddInt64(&accepted, int64(ingestResp.Accepted))
						atomic.AddInt64(&failed, int64(ingestResp.Rejected))
					} else {
						atomic.AddInt64(&failed, int64(batchSize))
					}
				} else {
					atomic.AddInt64(&failed, int64(batchSize))
				}
				time.Sleep(20 * time.Microsecond) // Throttle slightly
			}
		}
	})

	// 2. UDP NetFlow Worker Loop
	wg.Go(func() {
		conn, err := net.Dial("udp", *targetUDP)
		if err != nil {
			fmt.Printf("UDP connection failed: %v\n", err)
			return
		}
		defer conn.Close()

		var seq uint32 = 1000
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Send a packet containing 10 records
				recordCount := 10
				atomic.AddInt64(&attempted, int64(recordCount))
				packet := make([]byte, 24+recordCount*48)
				binary.BigEndian.PutUint16(packet[0:2], 5)
				binary.BigEndian.PutUint16(packet[2:4], uint16(recordCount))
				binary.BigEndian.PutUint32(packet[4:8], 10000)
				binary.BigEndian.PutUint32(packet[8:12], uint32(time.Now().Unix()))
				binary.BigEndian.PutUint32(packet[12:16], 125000000)
				binary.BigEndian.PutUint32(packet[16:20], seq)
				packet[20] = 1
				packet[21] = 2
				binary.BigEndian.PutUint16(packet[22:24], 1)

				for i := range recordCount {
					offset := 24 + i*48
					record := packet[offset : offset+48]
					copy(record[0:4], []byte{172, 18, 0, 1}) // Match allowed router-docker-18 gateway IP
					copy(record[4:8], []byte{192, 168, 1, 10})
					binary.BigEndian.PutUint32(record[16:20], 5)
					binary.BigEndian.PutUint32(record[20:24], 250)
					binary.BigEndian.PutUint16(record[32:34], uint16(15000+i))
					binary.BigEndian.PutUint16(record[34:36], 80)
					record[38] = 6 // TCP
				}

				seq += uint32(recordCount)
				_, err := conn.Write(packet)
				if err != nil {
					atomic.AddInt64(&failed, int64(recordCount))
				} else {
					// UDP is fire-and-forget, assume accepted by transport level
					atomic.AddInt64(&accepted, int64(recordCount))
				}
				time.Sleep(10 * time.Microsecond) // Throttle slightly
			}
		}
	})

	// 3. Zeek Worker Loop
	wg.Go(func() {
		if *targetZeek == "" {
			return
		}
		dir := filepath.Dir(*targetZeek)
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("Failed to create Zeek directory %s: %v\n", dir, err)
			return
		}
		file, err := os.OpenFile(*targetZeek, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Failed to open Zeek log file %s: %v\n", *targetZeek, err)
			return
		}
		defer file.Close()

		var i int
		for {
			select {
			case <-ctx.Done():
				return
			default:
				recordCount := 1
				atomic.AddInt64(&attempted, int64(recordCount))

				record := ZeekRecord{
					TS:        float64(time.Now().UnixNano()) / 1e9,
					UID:       fmt.Sprintf("C%x", rand.Int63()),
					OrigH:     "192.168.1.50",
					OrigP:     49000 + (i % 10000),
					RespH:     "8.8.8.8",
					RespP:     53,
					Proto:     "udp",
					Service:   "dns",
					Duration:  0.045,
					OrigBytes: 42,
					RespBytes: 84,
					OrigPkts:  1,
					RespPkts:  1,
					ConnState: "SF",
				}
				data, err := json.Marshal(record)
				if err != nil {
					atomic.AddInt64(&failed, int64(recordCount))
					continue
				}
				_, err = file.Write(append(data, '\n'))
				if err != nil {
					atomic.AddInt64(&failed, int64(recordCount))
				} else {
					atomic.AddInt64(&accepted, int64(recordCount))
				}
				i++
				time.Sleep(10 * time.Millisecond) // Throttle slightly to prevent disk IO saturation
			}
		}
	})

	wg.Wait()

	// Wait a moment for final DB writes to complete
	time.Sleep(3 * time.Second)

	// 3. Measure Query Latencies (Run 20 search queries and calculate p95)
	queryDurations := make([]float64, 0, 20)
	client := &http.Client{Timeout: 5 * time.Second}
	fromTime := startTime.UTC().Format(time.RFC3339)
	toTime := time.Now().UTC().Format(time.RFC3339)
	queryURL := fmt.Sprintf("%s/api/v1/flows?from=%s&to=%s&limit=100", *targetREST, fromTime, toTime)

	for range 20 {
		qStart := time.Now()
		req, _ := http.NewRequest("GET", queryURL, nil)
		req.Header.Set("X-API-Key", "demoadminkey123") // Admin key has query scope
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				queryDurations = append(queryDurations, float64(time.Since(qStart).Milliseconds()))
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	p95 := 0.0
	if len(queryDurations) > 0 {
		sort.Float64s(queryDurations)
		p95Idx := int(float64(len(queryDurations)) * 0.95)
		if p95Idx >= len(queryDurations) {
			p95Idx = len(queryDurations) - 1
		}
		p95 = queryDurations[p95Idx]
	}

	// 4. Fetch count of stored records (if possible)
	var recordsStored int64 = 0
	req, _ := http.NewRequest("GET", queryURL, nil)
	req.Header.Set("X-API-Key", "demoadminkey123")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		var flowsResp struct {
			Items []any `json:"items"`
		}
		if json.NewDecoder(resp.Body).Decode(&flowsResp) == nil {
			recordsStored = int64(len(flowsResp.Items))
		}
	}

	actualDuration := time.Since(startTime).Seconds()
	recordsPerSecond := float64(accepted) / actualDuration

	result := PerformanceSmoke{
		StartedAt:        startTime.UTC().Format(time.RFC3339),
		DurationSeconds:  actualDuration,
		Source:           "rest_and_netflow",
		RecordsAttempted: attempted,
		RecordsAccepted:  accepted,
		RecordsStored:    recordsStored,
		RecordsFailed:    failed,
		RecordsPerSecond: recordsPerSecond,
		QueryP95Ms:       p95,
		Notes:            []string{"Load smoke integration run complete."},
	}

	// Write performance smoke artifact
	artifactPath := "artifacts/performance-smoke.json"
	_ = os.MkdirAll("artifacts", 0755)
	fileBytes, _ := json.MarshalIndent(result, "", "    ")
	_ = os.WriteFile(artifactPath, fileBytes, 0644)

	fmt.Printf("Load smoke test complete. Saved results to %s\n", artifactPath)
	fmt.Printf("Throughput: %.2f records/sec. p95 Query Latency: %.2f ms\n", recordsPerSecond, p95)
}
