package domain

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

func NewUUIDv7(now time.Time) (string, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var b [16]byte
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("read uuid randomness: %w", err)
	}

	millis := now.UTC().UnixMilli()
	if millis < 0 || millis > 0xffffffffffff {
		return "", fmt.Errorf("uuidv7 timestamp out of 48-bit range")
	}
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(millis))
	copy(b[0:6], timestamp[2:8])
	b[6] = (b[6] & 0x0f) | 0x70
	b[8] = (b[8] & 0x3f) | 0x80

	return formatUUID(b), nil
}

func formatUUID(b [16]byte) string {
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		uint64(b[10])<<40|uint64(b[11])<<32|uint64(b[12])<<24|uint64(b[13])<<16|uint64(b[14])<<8|uint64(b[15]),
	)
}
