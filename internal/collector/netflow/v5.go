package netflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	flowv1 "github.com/adnope/quiver/internal/gen/flow/v1"
)

const (
	v5HeaderLen = 24
	v5RecordLen = 48
)

var (
	ErrInvalidPacket      = errors.New("netflow: invalid v5 packet")
	ErrUnsupportedVersion = errors.New("netflow: unsupported version")
)

type V5Packet struct {
	Sequence       uint32
	ExporterTime   time.Time
	ExporterUptime uint32
	EngineType     uint32
	EngineID       uint32
	SamplingRate   uint32
	Records        []*flowv1.NetFlowV5Flow
}

func ParseV5Packet(data []byte) (V5Packet, error) {
	if len(data) < v5HeaderLen {
		return V5Packet{}, fmt.Errorf("%w: packet too short", ErrInvalidPacket)
	}
	version := binary.BigEndian.Uint16(data[0:2])
	if version != 5 {
		return V5Packet{}, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
	count := int(binary.BigEndian.Uint16(data[2:4]))
	if count <= 0 || count > 30 {
		return V5Packet{}, fmt.Errorf("%w: invalid record count", ErrInvalidPacket)
	}
	expectedLen := v5HeaderLen + count*v5RecordLen
	if len(data) != expectedLen {
		return V5Packet{}, fmt.Errorf("%w: count length mismatch", ErrInvalidPacket)
	}
	sysUptime := binary.BigEndian.Uint32(data[4:8])
	unixSecs := binary.BigEndian.Uint32(data[8:12])
	unixNsecs := binary.BigEndian.Uint32(data[12:16])
	if unixNsecs >= 1_000_000_000 {
		return V5Packet{}, fmt.Errorf("%w: invalid nanoseconds", ErrInvalidPacket)
	}
	sequence := binary.BigEndian.Uint32(data[16:20])
	engineType := uint32(data[20])
	engineID := uint32(data[21])
	sampling := uint32(binary.BigEndian.Uint16(data[22:24]) & 0x3fff)
	exporterTime := time.Unix(int64(unixSecs), int64(unixNsecs)).UTC()

	packet := V5Packet{
		Sequence:       sequence,
		ExporterTime:   exporterTime,
		ExporterUptime: sysUptime,
		EngineType:     engineType,
		EngineID:       engineID,
		SamplingRate:   sampling,
		Records:        make([]*flowv1.NetFlowV5Flow, 0, count),
	}
	for i := range count {
		offset := v5HeaderLen + i*v5RecordLen
		record := data[offset : offset+v5RecordLen]
		packet.Records = append(packet.Records, &flowv1.NetFlowV5Flow{
			PacketSequence:   sequence,
			RecordIndex:      uint32(i),
			SrcAddr:          net.IP(record[0:4]).String(),
			DstAddr:          net.IP(record[4:8]).String(),
			NextHop:          new(net.IP(record[8:12]).String()),
			InputInterface:   new(uint32(binary.BigEndian.Uint16(record[12:14]))),
			OutputInterface:  new(uint32(binary.BigEndian.Uint16(record[14:16]))),
			Packets:          uint64(binary.BigEndian.Uint32(record[16:20])),
			Bytes:            uint64(binary.BigEndian.Uint32(record[20:24])),
			FirstSwitchedMs:  binary.BigEndian.Uint32(record[24:28]),
			LastSwitchedMs:   binary.BigEndian.Uint32(record[28:32]),
			ExporterUnixTime: timestamppb.New(exporterTime),
			ExporterUptimeMs: &sysUptime,
			SrcPort:          new(uint32(binary.BigEndian.Uint16(record[32:34]))),
			DstPort:          new(uint32(binary.BigEndian.Uint16(record[34:36]))),
			TcpFlags:         uint32(record[37]),
			ProtocolNumber:   uint32(record[38]),
			Tos:              uint32(record[39]),
			SrcAs:            new(uint32(binary.BigEndian.Uint16(record[40:42]))),
			DstAs:            new(uint32(binary.BigEndian.Uint16(record[42:44]))),
			SrcMask:          new(uint32(record[44])),
			DstMask:          new(uint32(record[45])),
			EngineType:       &engineType,
			EngineId:         &engineID,
			SamplingRate:     &sampling,
		})
	}
	return packet, nil
}
