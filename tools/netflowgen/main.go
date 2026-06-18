package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

const (
	v5HeaderLen = 24
	v5RecordLen = 48
)

func main() {
	target := flag.String("target", "localhost:2055", "Target UDP address host:port")
	count := flag.Int("count", 1, "Number of flow records to send in the packet")
	sequence := flag.Int("seq", 1, "Initial packet sequence number")
	malformed := flag.String("malformed", "", "Type of malformed packet: 'short', 'version', 'mismatch', or ''")
	flag.Parse()

	conn, err := net.Dial("udp", *target)
	if err != nil {
		fmt.Printf("Failed to dial target: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	var payload []byte
	switch *malformed {
	case "short":
		payload = []byte{0x00, 0x05, 0x00, 0x01} // Too short
	case "version":
		payload = generatePacket(uint32(*sequence), uint16(*count))
		binary.BigEndian.PutUint16(payload[0:2], 9) // Version 9 instead of 5
	case "mismatch":
		payload = generatePacket(uint32(*sequence), uint16(*count))
		// Truncate the payload so record count doesn't match physical size
		if len(payload) > v5HeaderLen {
			payload = payload[:len(payload)-10]
		}
	default:
		payload = generatePacket(uint32(*sequence), uint16(*count))
	}

	_, err = conn.Write(payload)
	if err != nil {
		fmt.Printf("Failed to send packet: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully sent packet (malformed=%q, records=%d, seq=%d) to %s\n", *malformed, *count, *sequence, *target)
}

func generatePacket(sequence uint32, count uint16) []byte {
	recordCount := int(count)
	packet := make([]byte, v5HeaderLen+recordCount*v5RecordLen)
	// Version
	binary.BigEndian.PutUint16(packet[0:2], 5)
	// Count
	binary.BigEndian.PutUint16(packet[2:4], count)
	// SysUptime
	binary.BigEndian.PutUint32(packet[4:8], 10000)
	// Exporter Unix Secs
	binary.BigEndian.PutUint32(packet[8:12], uint32(time.Now().Unix()))
	// Exporter Unix Nsecs
	binary.BigEndian.PutUint32(packet[12:16], 125000000)
	// Sequence
	binary.BigEndian.PutUint32(packet[16:20], sequence)
	// Engine type & ID
	packet[20] = 1
	packet[21] = 2
	// Sampling interval
	binary.BigEndian.PutUint16(packet[22:24], 1)

	for i := 0; i < recordCount; i++ {
		offset := v5HeaderLen + i*v5RecordLen
		record := packet[offset : offset+v5RecordLen]
		// Source IP: 10.10.0.1
		copy(record[0:4], []byte{10, 10, 0, 1})
		// Dest IP: 192.168.1.100
		copy(record[4:8], []byte{192, 168, 1, byte(100 + i)})
		// Next hop
		copy(record[8:12], []byte{0, 0, 0, 0})
		// Input/output interfaces
		binary.BigEndian.PutUint16(record[12:14], 1)
		binary.BigEndian.PutUint16(record[14:16], 2)
		// Packets
		binary.BigEndian.PutUint32(record[16:20], 5)
		// Bytes
		binary.BigEndian.PutUint32(record[20:24], 250)
		// Switched switched ms
		binary.BigEndian.PutUint32(record[24:28], 1000)
		binary.BigEndian.PutUint32(record[28:32], 2000)
		// Source port
		binary.BigEndian.PutUint16(record[32:34], uint16(12345+i))
		// Dest port
		binary.BigEndian.PutUint16(record[34:36], 80)
		// Pad
		record[36] = 0
		// TCP Flags
		record[37] = 0x10 // ACK
		// Protocol
		record[38] = 6 // TCP
		// TOS
		record[39] = 0
		// Source AS & Dest AS
		binary.BigEndian.PutUint16(record[40:42], 64512)
		binary.BigEndian.PutUint16(record[42:44], 64513)
		// Source mask & Dest mask
		record[44] = 24
		record[45] = 24
	}
	return packet
}
