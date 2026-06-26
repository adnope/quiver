package zeekconntcp

import (
	"context"
	"time"
)

type recordLimiter struct {
	cfg    rateLimitSettings
	tokens int
	last   time.Time
}

func newRecordLimiter(cfg rateLimitSettings) *recordLimiter {
	return &recordLimiter{cfg: cfg, tokens: cfg.Burst, last: time.Now()}
}

func (l *recordLimiter) allow() bool {
	if l == nil || !l.cfg.Enabled {
		return true
	}
	l.refill()
	if l.tokens > 0 {
		l.tokens--
		return true
	}
	return false
}

func (l *recordLimiter) dropMode() bool {
	return l != nil && l.cfg.Enabled && l.cfg.Mode == "drop"
}

func (l *recordLimiter) wait(ctx context.Context) {
	if l == nil || !l.cfg.Enabled || l.cfg.RecordsPerSec <= 0 {
		return
	}
	delay := time.Second / time.Duration(l.cfg.RecordsPerSec)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (l *recordLimiter) refill() {
	now := time.Now()
	if l.last.IsZero() {
		l.last = now
		return
	}
	add := int(now.Sub(l.last).Seconds() * float64(l.cfg.RecordsPerSec))
	if add <= 0 {
		return
	}
	l.tokens += add
	if l.tokens > l.cfg.Burst {
		l.tokens = l.cfg.Burst
	}
	l.last = now
}
