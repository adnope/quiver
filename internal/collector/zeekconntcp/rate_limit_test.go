package zeekconntcp

import (
	"context"
	"testing"
	"time"
)

func TestRecordLimiter_AllowAndRefill(t *testing.T) {
	// Disabled limiter
	var nilLimiter *recordLimiter
	if !nilLimiter.allow() {
		t.Error("nil limiter should allow")
	}

	cfgDisabled := rateLimitSettings{Enabled: false}
	limDisabled := newRecordLimiter(cfgDisabled)
	if !limDisabled.allow() {
		t.Error("disabled limiter should allow")
	}

	// Enabled limiter
	cfgEnabled := rateLimitSettings{
		Enabled:       true,
		RecordsPerSec: 10,
		Burst:         2,
		Mode:          "drop",
	}
	lim := newRecordLimiter(cfgEnabled)

	// Should allow up to burst (2)
	if !lim.allow() {
		t.Error("expected first allow")
	}
	if !lim.allow() {
		t.Error("expected second allow")
	}
	// 3rd should be blocked
	if lim.allow() {
		t.Error("expected 3rd call to be rate limited")
	}

	// Wait enough for refill
	lim.last = time.Now().Add(-200 * time.Millisecond) // Should refill 2 tokens
	lim.refill()
	if !lim.allow() {
		t.Error("expected allow after refill")
	}

	// Test zero last time refill
	lim.last = time.Time{}
	lim.refill() // should just reset last time and not panic
}

func TestRecordLimiter_DropMode(t *testing.T) {
	var nilLimiter *recordLimiter
	if nilLimiter.dropMode() {
		t.Error("nil limiter dropMode should be false")
	}

	cfg := rateLimitSettings{Enabled: true, Mode: "drop"}
	lim := newRecordLimiter(cfg)
	if !lim.dropMode() {
		t.Error("expected dropMode to be true")
	}

	cfg.Mode = "delay"
	lim2 := newRecordLimiter(cfg)
	if lim2.dropMode() {
		t.Error("expected dropMode to be false for delay mode")
	}
}

func TestRecordLimiter_Wait(t *testing.T) {
	// Nil / Disabled cases
	var nilLimiter *recordLimiter
	nilLimiter.wait(context.Background()) // no panic

	cfgDisabled := rateLimitSettings{Enabled: false}
	limDisabled := newRecordLimiter(cfgDisabled)
	limDisabled.wait(context.Background())

	// Enabled wait
	cfg := rateLimitSettings{Enabled: true, RecordsPerSec: 100}
	lim := newRecordLimiter(cfg)

	start := time.Now()
	lim.wait(context.Background())
	if duration := time.Since(start); duration < 10*time.Millisecond {
		t.Errorf("wait duration too short: %v", duration)
	}

	// Wait with canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	lim.wait(ctx)
	if duration := time.Since(start); duration > 5*time.Millisecond {
		t.Errorf("wait with canceled context took too long: %v", duration)
	}
}
