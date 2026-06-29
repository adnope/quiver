//nolint:gosec // This CLI emits bounded synthetic NetFlow v9 packets for local verification.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"time"
)

func main() {
	target := flag.String("target", "localhost:2055", "Target UDP address host:port")
	count := flag.Int("count", 1, "Number of flow records to send in the packet")
	sequence := flag.Int("seq", 1, "Initial packet sequence number")
	malformed := flag.String("malformed", "", "Type of malformed packet: 'short', 'version', 'mismatch', or ''")
	flag.Parse()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(context.Background(), "udp", *target)
	if err != nil {
		fmt.Printf("Failed to dial target: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			fmt.Printf("Failed to close UDP connection: %v\n", err)
		}
	}()

	if *count < 0 || *count > math.MaxUint16 {
		fmt.Printf("Invalid count %d: must be between 0 and %d\n", *count, math.MaxUint16)
		os.Exit(1)
	}
	if *sequence < 0 || *sequence > math.MaxUint32 {
		fmt.Printf("Invalid sequence %d: must be between 0 and %d\n", *sequence, uint64(math.MaxUint32))
		os.Exit(1)
	}
	seq := uint32(*sequence)
	recordCount := uint16(*count)

	var payload []byte
	switch *malformed {
	case "short":
		payload = []byte{0x00, 0x09, 0x00, 0x01} // Too short
	case "version":
		payload = generateV9Packet(seq, recordCount)
		binary.BigEndian.PutUint16(payload[0:2], 5) // Version 5 instead of 9
	case "mismatch":
		payload = generateV9Packet(seq, recordCount)
		if len(payload) > 20 {
			payload = payload[:len(payload)-10]
		}
	default:
		payload = generateV9Packet(seq, recordCount)
	}

	_, err = conn.Write(payload)
	if err != nil {
		fmt.Printf("Failed to send packet: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully sent NetFlow v9 packet (malformed=%q, records=%d, seq=%d) to %s\n", *malformed, *count, *sequence, *target)
}

func generateV9Packet(sequence uint32, count uint16) []byte {
	recordCount := int(count)
	recordLen := 30
	dataFlowSetLen := 4 + recordCount*recordLen
	padding := (4 - (dataFlowSetLen % 4)) % 4
	dataFlowSetLenAligned := dataFlowSetLen + padding

	templateFlowSetLen := 48 // 4 byte header + 4 byte template header + 10*4 byte fields

	packet := make([]byte, 20+templateFlowSetLen+dataFlowSetLenAligned)

	// Header (20 bytes)
	binary.BigEndian.PutUint16(packet[0:2], 9)
	binary.BigEndian.PutUint16(packet[2:4], count+1) // 1 template + count records
	binary.BigEndian.PutUint32(packet[4:8], 10000)
	binary.BigEndian.PutUint32(packet[8:12], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(packet[12:16], sequence)
	binary.BigEndian.PutUint32(packet[16:20], 1) // Source ID

	// Template FlowSet (48 bytes)
	tmplOffset := 20
	binary.BigEndian.PutUint16(packet[tmplOffset:tmplOffset+2], 0) // Template FlowSet ID
	binary.BigEndian.PutUint16(packet[tmplOffset+2:tmplOffset+4], uint16(templateFlowSetLen))
	binary.BigEndian.PutUint16(packet[tmplOffset+4:tmplOffset+6], 256) // Template ID
	binary.BigEndian.PutUint16(packet[tmplOffset+6:tmplOffset+8], 10)  // Field Count

	fields := []struct {
		id  uint16
		len uint16
	}{
		{8, 4},  // sourceIPv4Address
		{12, 4}, // destinationIPv4Address
		{7, 2},  // sourceTransportPort
		{11, 2}, // destinationTransportPort
		{4, 1},  // protocolIdentifier
		{1, 4},  // octetDeltaCount
		{2, 4},  // packetDeltaCount
		{6, 1},  // tcpControlBits
		{22, 4}, // flowStartSysUpTime
		{21, 4}, // flowEndSysUpTime
	}

	for i, f := range fields {
		off := tmplOffset + 8 + i*4
		binary.BigEndian.PutUint16(packet[off:off+2], f.id)
		binary.BigEndian.PutUint16(packet[off+2:off+4], f.len)
	}

	// Data FlowSet
	dataOffset := tmplOffset + templateFlowSetLen
	binary.BigEndian.PutUint16(packet[dataOffset:dataOffset+2], 256) // Matches Template ID
	binary.BigEndian.PutUint16(packet[dataOffset+2:dataOffset+4], uint16(dataFlowSetLenAligned))

	for i := range recordCount {
		off := dataOffset + 4 + i*recordLen
		// sourceIPv4Address: 10.10.0.1
		copy(packet[off:off+4], []byte{10, 10, 0, 1})
		// destinationIPv4Address: 192.168.1.100+i
		copy(packet[off+4:off+8], []byte{192, 168, 1, byte(100 + i)})
		// sourceTransportPort: 12345+i
		binary.BigEndian.PutUint16(packet[off+8:off+10], uint16(12345+i))
		// destinationTransportPort: 80
		binary.BigEndian.PutUint16(packet[off+10:off+12], 80)
		// protocolIdentifier: 6 (TCP)
		packet[off+12] = 6
		// octetDeltaCount: 250
		binary.BigEndian.PutUint32(packet[off+13:off+17], 250)
		// packetDeltaCount: 5
		binary.BigEndian.PutUint32(packet[off+17:off+21], 5)
		// tcpControlBits: 0x10 (ACK)
		packet[off+21] = 0x10
		// flowStartSysUpTime: 1000
		binary.BigEndian.PutUint32(packet[off+22:off+26], 1000)
		// flowEndSysUpTime: 2000
		binary.BigEndian.PutUint32(packet[off+26:off+30], 2000)
	}

	return packet
}
