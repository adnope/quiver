//nolint:gosec // tests use deterministic pseudo-randomness for reproducible generated records.
package main

import (
	"math/rand"
	"net"
	"testing"
)

func TestGenerateRecordValid(t *testing.T) {
	t.Parallel()

	rec := generateRecord(rand.New(rand.NewSource(1)), false)
	if rec.ExternalID == "" || rec.EventStartTime == "" || rec.EventEndTime == "" {
		t.Fatalf("missing identity or timestamps: %+v", rec)
	}
	if net.ParseIP(rec.SrcIP) == nil || net.ParseIP(rec.DstIP) == nil {
		t.Fatalf("invalid generated IPs: %+v", rec)
	}
	if rec.SrcPort == nil || *rec.SrcPort < 32768 || rec.DstPort == nil || *rec.DstPort == 0 {
		t.Fatalf("invalid ports: %+v", rec)
	}
	if rec.Bytes == nil || *rec.Bytes == 0 || rec.Packets == nil || *rec.Packets == 0 {
		t.Fatalf("invalid counters: %+v", rec)
	}
	if rec.SamplingRate == nil || *rec.SamplingRate != 1 {
		t.Fatalf("sampling rate = %v", rec.SamplingRate)
	}
	if rec.Attributes["generated_by"] != "workload_script" {
		t.Fatalf("attributes = %+v", rec.Attributes)
	}
}

func TestGenerateRecordInjectsErrors(t *testing.T) {
	t.Parallel()

	seenInvalidIP := false
	seenOverflowPort := false
	seenInvalidProtocol := false
	seenMismatch := false
	for seed := range 200 {
		rec := generateRecord(rand.New(rand.NewSource(int64(seed))), true)
		if rec.SrcIP == "invalid-ip-address" {
			seenInvalidIP = true
		}
		if rec.SrcPort != nil && *rec.SrcPort == 999999 {
			seenOverflowPort = true
		}
		if rec.TransportProtocol == "invalid-protocol-name" && rec.ProtocolNumber == 250 {
			seenInvalidProtocol = true
		}
		if rec.TransportProtocol == "tcp" && rec.ProtocolNumber == 17 {
			seenMismatch = true
		}
	}
	if !seenInvalidIP || !seenOverflowPort || !seenInvalidProtocol || !seenMismatch {
		t.Fatalf("did not observe all injected errors: ip=%v port=%v proto=%v mismatch=%v", seenInvalidIP, seenOverflowPort, seenInvalidProtocol, seenMismatch)
	}
}
