package main

import (
	"encoding/binary"
	"testing"
)

func TestGeneratePacketHeaderAndRecords(t *testing.T) {
	t.Parallel()

	packet := generatePacket(42, 2)
	if len(packet) != v5HeaderLen+2*v5RecordLen {
		t.Fatalf("packet len = %d", len(packet))
	}
	if got := binary.BigEndian.Uint16(packet[0:2]); got != 5 {
		t.Fatalf("version = %d, want 5", got)
	}
	if got := binary.BigEndian.Uint16(packet[2:4]); got != 2 {
		t.Fatalf("count = %d, want 2", got)
	}
	if got := binary.BigEndian.Uint32(packet[16:20]); got != 42 {
		t.Fatalf("sequence = %d, want 42", got)
	}
	first := packet[v5HeaderLen : v5HeaderLen+v5RecordLen]
	if got := first[0:4]; string(got) != string([]byte{10, 10, 0, 1}) {
		t.Fatalf("src ip bytes = %v", got)
	}
	if got := binary.BigEndian.Uint16(first[32:34]); got != 12345 {
		t.Fatalf("src port = %d, want 12345", got)
	}
	if got := binary.BigEndian.Uint16(first[34:36]); got != 80 {
		t.Fatalf("dst port = %d, want 80", got)
	}
	if got := first[38]; got != 6 {
		t.Fatalf("protocol = %d, want TCP", got)
	}
}

func TestGeneratePacketAllowsZeroRecords(t *testing.T) {
	t.Parallel()

	packet := generatePacket(7, 0)
	if len(packet) != v5HeaderLen {
		t.Fatalf("packet len = %d, want header only", len(packet))
	}
	if got := binary.BigEndian.Uint16(packet[2:4]); got != 0 {
		t.Fatalf("count = %d, want 0", got)
	}
}
