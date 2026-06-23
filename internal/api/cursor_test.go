package api

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/adnope/quiver/internal/storage/postgres"
)

func TestCursorCodecRoundTripAndTamper(t *testing.T) {
	t.Parallel()

	codec, err := NewCursorCodec("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewCursorCodec() error = %v", err)
	}
	cursor := postgres.FlowCursor{
		EventStartTime: time.Date(2026, 6, 16, 10, 15, 20, 0, time.UTC),
		ID:             "01934d7c-79b4-7000-8b69-001122334455",
	}
	encoded, err := codec.Encode(cursor)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := codec.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if !decoded.EventStartTime.Equal(cursor.EventStartTime) || decoded.ID != cursor.ID {
		t.Fatalf("decoded cursor = %+v", decoded)
	}

	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	var token cursorToken
	if err := json.Unmarshal(data, &token); err != nil {
		t.Fatalf("unmarshal token: %v", err)
	}
	token.Payload.ID = "01934d7c-79b4-7000-8b69-001122334456"
	tampered, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("marshal tampered token: %v", err)
	}
	if _, err := codec.Decode(base64.RawURLEncoding.EncodeToString(tampered)); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("Decode(tampered) error = %v", err)
	}
	if _, err := codec.Decode("not-base64!"); err == nil {
		t.Fatal("expected malformed base64 cursor error")
	}
}

func TestAggregationCursorCodecRoundTripAndTamper(t *testing.T) {
	t.Parallel()

	codec, err := NewCursorCodec("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewCursorCodec() error = %v", err)
	}
	ip := netip.MustParseAddr("192.168.1.10")
	cursor := postgres.AggregationCursor{
		Endpoint:  postgres.AggregationEndpointTopTalkers,
		QueryHash: strings.Repeat("a", 64),
		Metric:    postgres.AggregationMetricBytes,
		Direction: postgres.AggregationDirectionSrc,
		Value:     100,
		FlowCount: 2,
		IP:        &ip,
	}
	encoded, err := codec.EncodeAggregation(cursor)
	if err != nil {
		t.Fatalf("EncodeAggregation() error = %v", err)
	}
	decoded, err := codec.DecodeAggregation(encoded)
	if err != nil {
		t.Fatalf("DecodeAggregation() error = %v", err)
	}
	if decoded.Endpoint != cursor.Endpoint || decoded.QueryHash != cursor.QueryHash || decoded.IP == nil || decoded.IP.String() != cursor.IP.String() {
		t.Fatalf("decoded cursor = %+v", decoded)
	}

	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	var token aggregationCursorToken
	if err := json.Unmarshal(data, &token); err != nil {
		t.Fatalf("unmarshal token: %v", err)
	}
	token.Payload.Value = 101
	tampered, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("marshal tampered token: %v", err)
	}
	if _, err := codec.DecodeAggregation(base64.RawURLEncoding.EncodeToString(tampered)); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("DecodeAggregation(tampered) error = %v", err)
	}
	if _, err := codec.DecodeAggregation("not-base64!"); err == nil {
		t.Fatal("expected malformed base64 cursor error")
	}
	if _, err := codec.DecodeAggregation(encoded[:len(encoded)-1]); err == nil {
		t.Fatal("expected truncated cursor error")
	}
}
