package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
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
	mode := flag.String("mode", "append", "Mode: 'append' or 'rotate'")
	malformed := flag.Bool("malformed", false, "Write a malformed JSON line")
	count := flag.Int("count", 1, "Number of records to append")
	flag.Parse()

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
		record := ZeekRecord{
			TS:        float64(time.Now().UnixNano()) / 1e9,
			UID:       fmt.Sprintf("C%x", rand.Int63()),
			OrigH:     "192.168.1.50",
			OrigP:     49000 + i,
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
