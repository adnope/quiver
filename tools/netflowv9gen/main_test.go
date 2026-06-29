package main

import (
	"encoding/binary"
	"testing"
)

func TestGenerateV9Packet(t *testing.T) {
	t.Parallel()

	packet := generateV9Packet(1, 2)
	if len(packet) < 20 {
		t.Fatalf("packet too short: len=%d", len(packet))
	}

	version := binary.BigEndian.Uint16(packet[0:2])
	if version != 9 {
		t.Fatalf("version = %d, want 9", version)
	}

	count := binary.BigEndian.Uint16(packet[2:4])
	if count != 3 {
		t.Fatalf("count = %d, want 3 (1 template + 2 data records)", count)
	}

	sequence := binary.BigEndian.Uint32(packet[12:16])
	if sequence != 1 {
		t.Fatalf("sequence = %d, want 1", sequence)
	}

	sourceID := binary.BigEndian.Uint32(packet[16:20])
	if sourceID != 1 {
		t.Fatalf("sourceID = %d, want 1", sourceID)
	}
}
