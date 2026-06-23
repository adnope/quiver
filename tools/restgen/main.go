package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
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
	target := flag.String("target", "http://localhost:8080", "Target REST API Base URL")
	key := flag.String("key", "democlientkey456", "API Key with ingest scope")
	count := flag.Int("count", 10, "Number of flow records to send")
	malformed := flag.Bool("malformed", false, "Include invalid records in the batch")
	badJSON := flag.Bool("bad-json", false, "Send a completely malformed JSON request body")
	flag.Parse()

	url := fmt.Sprintf("%s/api/v1/ingest/flows", *target)

	var requestBody []byte
	if *badJSON {
		requestBody = []byte("{bad-json")
	} else {
		records := make([]IngestRecord, 0, *count)
		for i := 0; i < *count; i++ {
			srcPort := uint32(50000 + i)
			dstPort := uint32(443)
			bytesVal := uint64(1500 * (i + 1))
			packetsVal := uint64(10 * (i + 1))
			tcpFlagsVal := uint32(0x18) // PSH, ACK
			sampling := uint32(1)

			record := IngestRecord{
				ExternalID:          fmt.Sprintf("ext-%d-%d", time.Now().UnixNano(), i),
				EventStartTime:      time.Now().UTC().Format(time.RFC3339Nano),
				EventEndTime:        time.Now().Add(500 * time.Millisecond).UTC().Format(time.RFC3339Nano),
				SrcIP:               "192.168.1.10",
				DstIP:               "8.8.8.8",
				SrcPort:             &srcPort,
				DstPort:             &dstPort,
				TransportProtocol:   "tcp",
				ProtocolNumber:      6,
				Bytes:               &bytesVal,
				Packets:             &packetsVal,
				ApplicationProtocol: "https",
				TCPFlags:            &tcpFlagsVal,
				SamplingRate:        &sampling,
				Attributes:          map[string]any{"client_version": "1.0", "custom_tag": "demo"},
			}
			records = append(records, record)
		}

		if *malformed {
			// Add a malformed record (invalid IP and negative/overflow port check)
			overflowPort := uint32(999999)
			records = append(records, IngestRecord{
				EventStartTime:    time.Now().UTC().Format(time.RFC3339Nano),
				SrcIP:             "invalid-ip",
				DstIP:             "8.8.8.8",
				SrcPort:           &overflowPort,
				TransportProtocol: "tcp",
				ProtocolNumber:    6,
			})
		}

		reqObj := IngestRequest{Records: records}
		var err error
		requestBody, err = json.Marshal(reqObj)
		if err != nil {
			fmt.Printf("Failed to marshal request: %v\n", err)
			os.Exit(1)
		}
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(requestBody))
	if err != nil {
		fmt.Printf("Failed to create request: %v\n", err)
		os.Exit(1)
	}

	req.Header.Set("X-API-Key", *key)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("HTTP request failed: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Failed to close response body: %v\n", err)
		}
	}()

	bodyBytes, _ := io.ReadAll(resp.Body)
	fmt.Printf("HTTP Status: %d\n", resp.StatusCode)
	fmt.Printf("Response Body: %s\n", string(bodyBytes))

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}
