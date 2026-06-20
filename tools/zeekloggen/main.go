package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
	filePath := flag.String("file", "/tmp/zeek/conn.log", "Path to Zeek conn.log file")
	target := flag.String("target", "", "Quiver base URL for HTTP Zeek ingest; when set, records are posted instead of written to a file")
	apiKey := flag.String("key", "", "API key for HTTP Zeek ingest")
	mode := flag.String("mode", "append", "Mode: 'append' or 'rotate'")
	malformed := flag.Bool("malformed", false, "Write a malformed JSON line")
	count := flag.Int("count", 1, "Number of records to append")
	flag.Parse()

	if strings.TrimSpace(*target) != "" {
		if err := postRecords(*target, *apiKey, *count, *malformed); err != nil {
			fmt.Printf("Failed to post Zeek records: %v\n", err)
			os.Exit(1)
		}
		return
	}

	dir := filepath.Dir(*filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("Failed to create directory %s: %v\n", dir, err)
		os.Exit(1)
	}

	if *mode == "rotate" {
		rotatedPath := *filePath + ".rotated"
		if err := os.Rename(*filePath, rotatedPath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("Failed to rotate file to %s: %v\n", rotatedPath, err)
			os.Exit(1)
		}
		fmt.Printf("Rotated log file to %s\n", rotatedPath)
	}

	file, err := os.OpenFile(*filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open file %s: %v\n", *filePath, err)
		os.Exit(1)
	}
	defer file.Close()

	if *malformed {
		_, err := file.WriteString("{bad-json\n")
		if err != nil {
			fmt.Printf("Failed to write malformed line: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Appended malformed line to Zeek log")
		return
	}

	for i := 0; i < *count; i++ {
		record := newRecord(i)
		data, err := json.Marshal(record)
		if err != nil {
			fmt.Printf("Failed to marshal JSON: %v\n", err)
			os.Exit(1)
		}
		_, err = file.Write(append(data, '\n'))
		if err != nil {
			fmt.Printf("Failed to write to file: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Appended %d valid records to %s\n", *count, *filePath)
}

type zeekIngestRequest struct {
	Records []json.RawMessage `json:"records"`
}

type zeekIngestResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}

func postRecords(target string, apiKey string, count int, malformed bool) error {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return fmt.Errorf("api key is required")
	}
	records, err := buildRecords(count, malformed)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(zeekIngestRequest{Records: records})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	endpoint := strings.TrimRight(target, "/") + "/api/v1/ingest/zeek/conn"
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-API-Key", apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("post request: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("unexpected status %s", response.Status)
	}
	var body zeekIngestResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	fmt.Printf("Posted Zeek records: accepted=%d rejected=%d\n", body.Accepted, body.Rejected)
	return nil
}

func buildRecords(count int, malformed bool) ([]json.RawMessage, error) {
	if malformed {
		line, err := json.Marshal("{bad-json")
		if err != nil {
			return nil, fmt.Errorf("marshal malformed line: %w", err)
		}
		return []json.RawMessage{line}, nil
	}
	if count <= 0 {
		return nil, fmt.Errorf("count must be positive")
	}
	records := make([]json.RawMessage, 0, count)
	for i := 0; i < count; i++ {
		record := newRecord(i)
		data, err := json.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("marshal record: %w", err)
		}
		records = append(records, data)
	}
	return records, nil
}

func newRecord(index int) ZeekRecord {
	return ZeekRecord{
		TS:        float64(time.Now().UnixNano()) / 1e9,
		UID:       fmt.Sprintf("C%x", rand.Int63()),
		OrigH:     "192.168.1.50",
		OrigP:     49000 + index,
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
}
