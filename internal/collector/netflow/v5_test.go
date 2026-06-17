package netflow

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseV5Packet(t *testing.T) {
	t.Parallel()

	packet, err := ParseV5Packet(validV5Packet(42, 2))
	if err != nil {
		t.Fatalf("ParseV5Packet() error = %v", err)
	}
	if packet.Sequence != 42 || len(packet.Records) != 2 {
		t.Fatalf("packet sequence=%d records=%d", packet.Sequence, len(packet.Records))
	}
	first := packet.Records[0]
	if first.GetSrcAddr() != "192.0.2.10" || first.GetDstAddr() != "198.51.100.20" {
		t.Fatalf("addresses = %s/%s", first.GetSrcAddr(), first.GetDstAddr())
	}
	if first.GetSrcPort() != 51524 || first.GetDstPort() != 443 || first.GetProtocolNumber() != 6 {
		t.Fatalf("transport fields = src_port:%d dst_port:%d proto:%d", first.GetSrcPort(), first.GetDstPort(), first.GetProtocolNumber())
	}
	if first.GetPackets() != 3 || first.GetBytes() != 420 || first.GetSamplingRate() != 1 {
		t.Fatalf("counters/sampling = packets:%d bytes:%d sampling:%d", first.GetPackets(), first.GetBytes(), first.GetSamplingRate())
	}
}

func TestParseV5PacketRejectsUnsupportedVersion(t *testing.T) {
	t.Parallel()

	packet := validV5Packet(1, 1)
	binary.BigEndian.PutUint16(packet[0:2], 9)
	_, err := ParseV5Packet(packet)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("ParseV5Packet() error = %v, want ErrUnsupportedVersion", err)
	}
}

func TestParseV5PacketRejectsCountLengthMismatch(t *testing.T) {
	t.Parallel()

	packet := validV5Packet(1, 1)
	_, err := ParseV5Packet(packet[:len(packet)-1])
	if !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("ParseV5Packet() error = %v, want ErrInvalidPacket", err)
	}
}

func validV5Packet(sequence uint32, count uint16) []byte {
	recordCount := int(count)
	packet := make([]byte, v5HeaderLen+recordCount*v5RecordLen)
	binary.BigEndian.PutUint16(packet[0:2], 5)
	binary.BigEndian.PutUint16(packet[2:4], count)
	binary.BigEndian.PutUint32(packet[4:8], 10_000)
	binary.BigEndian.PutUint32(packet[8:12], 1_718_532_920)
	binary.BigEndian.PutUint32(packet[12:16], 125_000_000)
	binary.BigEndian.PutUint32(packet[16:20], sequence)
	packet[20] = 1
	packet[21] = 2
	binary.BigEndian.PutUint16(packet[22:24], 1)
	for i := 0; i < recordCount; i++ {
		offset := v5HeaderLen + i*v5RecordLen
		record := packet[offset : offset+v5RecordLen]
		copy(record[0:4], []byte{192, 0, 2, byte(10 + i)})
		copy(record[4:8], []byte{198, 51, 100, byte(20 + i)})
		copy(record[8:12], []byte{203, 0, 113, 1})
		binary.BigEndian.PutUint16(record[12:14], 10)
		binary.BigEndian.PutUint16(record[14:16], 20)
		binary.BigEndian.PutUint32(record[16:20], 3)
		binary.BigEndian.PutUint32(record[20:24], 420)
		binary.BigEndian.PutUint32(record[24:28], 1_000)
		binary.BigEndian.PutUint32(record[28:32], 2_000)
		binary.BigEndian.PutUint16(record[32:34], uint16(51524+i))
		binary.BigEndian.PutUint16(record[34:36], 443)
		record[37] = 0x12
		record[38] = 6
		record[39] = 0
		binary.BigEndian.PutUint16(record[40:42], 64512)
		binary.BigEndian.PutUint16(record[42:44], 64513)
		record[44] = 24
		record[45] = 24
	}
	return packet
}
