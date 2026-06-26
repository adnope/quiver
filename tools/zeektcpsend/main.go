package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type zeekRecord struct {
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
	target := flag.String("target", "", "Quiver zeek_conn_tcp address host:port")
	apiKey := flag.String("key", "", "API key with ingest scope and source_host mapping")
	count := flag.Int("count", 1, "Number of valid records to send")
	malformed := flag.Bool("malformed", false, "Send one malformed JSON line")
	timeout := flag.Duration("timeout", 10*time.Second, "Connection timeout")
	flag.Parse()

	if err := run(*target, *apiKey, *count, *malformed, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "zeektcpsend failed: %v\n", err)
		os.Exit(1)
	}
}

func run(target string, apiKey string, count int, malformed bool, timeout time.Duration) error {
	target = strings.TrimSpace(target)
	apiKey = strings.TrimSpace(apiKey)
	if target == "" {
		return fmt.Errorf("target is required")
	}
	if apiKey == "" {
		return fmt.Errorf("api key is required")
	}
	if count <= 0 {
		return fmt.Errorf("count must be positive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("dial tcp: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	if _, err := fmt.Fprintf(conn, "X-API-Key: %s\n", apiKey); err != nil {
		return fmt.Errorf("write auth preface: %w", err)
	}
	if malformed {
		if _, err := fmt.Fprint(conn, "{bad-json\n"); err != nil {
			return fmt.Errorf("write malformed line: %w", err)
		}
		fmt.Println("Sent malformed Zeek TCP line")
		return nil
	}
	for i := range count {
		data, err := json.Marshal(newRecord(i))
		if err != nil {
			return fmt.Errorf("marshal record: %w", err)
		}
		if _, err := conn.Write(append(data, '\n')); err != nil {
			return fmt.Errorf("write record: %w", err)
		}
	}
	fmt.Printf("Sent %d Zeek TCP records\n", count)
	return nil
}

func newRecord(index int) zeekRecord {
	return zeekRecord{
		TS:        float64(time.Now().UnixNano()) / 1e9,
		UID:       randomUID(),
		OrigH:     "192.168.1.60",
		OrigP:     50000 + index,
		RespH:     "1.1.1.1",
		RespP:     443,
		Proto:     "tcp",
		Service:   "ssl",
		Duration:  0.125,
		OrigBytes: 120,
		RespBytes: 340,
		OrigPkts:  2,
		RespPkts:  3,
		ConnState: "SF",
	}
}

func randomUID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("C%x", time.Now().UnixNano())
	}
	return "C" + hex.EncodeToString(b[:])
}
