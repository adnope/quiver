package observability

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type Registry struct {
	mu       sync.RWMutex
	counters map[seriesKey]uint64
}

type seriesKey struct {
	name   string
	labels string
}

func NewRegistry() *Registry {
	return &Registry{counters: map[seriesKey]uint64{}}
}

func (r *Registry) Inc(name string, labels map[string]string) {
	r.Add(name, labels, 1)
}

func (r *Registry) Add(name string, labels map[string]string, value uint64) {
	if r == nil || value == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := seriesKey{name: name, labels: encodeLabels(labels)}
	r.counters[key] += value
}

func (r *Registry) ObserveDuration(name string, labels map[string]string, start time.Time) {
	if start.IsZero() {
		return
	}
	millis := durationMillis(time.Since(start))
	r.Add(name+"_milliseconds_total", labels, millis)
	r.Inc(name+"_count", labels)
}

func durationMillis(elapsed time.Duration) uint64 {
	if elapsed <= 0 {
		return 1
	}
	millis := elapsed.Milliseconds()
	if millis <= 0 {
		return 1
	}
	// time.Duration is int64, so a positive millisecond count always fits in uint64.
	return uint64(millis) //nolint:gosec
}

func (r *Registry) WritePrometheus() []byte {
	if r == nil {
		r = NewRegistry()
	}
	r.mu.RLock()
	keys := make([]seriesKey, 0, len(r.counters))
	for key := range r.counters {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name == keys[j].name {
			return keys[i].labels < keys[j].labels
		}
		return keys[i].name < keys[j].name
	})
	var out bytes.Buffer
	for _, key := range keys {
		value := r.counters[key]
		if key.labels == "" {
			fmt.Fprintf(&out, "%s %d\n", key.name, value)
			continue
		}
		fmt.Fprintf(&out, "%s{%s} %d\n", key.name, key.labels, value)
	}
	r.mu.RUnlock()
	return out.Bytes()
}

func encodeLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, key, escapeLabelValue(labels[key])))
	}
	return strings.Join(parts, ",")
}

func escapeLabelValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}
