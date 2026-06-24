package observability

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

const durationReservoirSize = 1000

type Registry struct {
	mu        sync.RWMutex
	counters  map[seriesKey]uint64
	durations map[seriesKey][]uint64
}

type seriesKey struct {
	name   string
	labels string
}

func NewRegistry() *Registry {
	return &Registry{
		counters:  map[seriesKey]uint64{},
		durations: map[seriesKey][]uint64{},
	}
}

func (r *Registry) ensureCounters() {
	if r.counters == nil {
		r.counters = map[seriesKey]uint64{}
	}
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
	r.ensureCounters()
	key := seriesKey{name: name, labels: encodeLabels(labels)}
	r.counters[key] += value
}

func (r *Registry) Set(name string, labels map[string]string, value uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureCounters()
	key := seriesKey{name: name, labels: encodeLabels(labels)}
	r.counters[key] = value
}

func (r *Registry) ObserveDuration(name string, labels map[string]string, start time.Time) {
	if r == nil || start.IsZero() {
		return
	}
	millis := durationMillis(time.Since(start))
	r.Add(name+"_milliseconds_total", labels, millis)
	r.Inc(name+"_count", labels)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.durations == nil {
		r.durations = map[seriesKey][]uint64{}
	}
	key := seriesKey{name: name, labels: encodeLabels(labels)}
	samples := append(r.durations[key], millis)
	if len(samples) > durationReservoirSize {
		samples = samples[len(samples)-durationReservoirSize:]
	}
	r.durations[key] = samples
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
	snapshots := r.Snapshot()
	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].Name == snapshots[j].Name {
			return encodeLabels(snapshots[i].Labels) < encodeLabels(snapshots[j].Labels)
		}
		return snapshots[i].Name < snapshots[j].Name
	})

	var out bytes.Buffer
	for _, snap := range snapshots {
		labels := encodeLabels(snap.Labels)
		if labels == "" {
			fmt.Fprintf(&out, "%s %d\n", snap.Name, snap.Value)
			continue
		}
		fmt.Fprintf(&out, "%s{%s} %d\n", snap.Name, labels, snap.Value)
	}
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

type MetricSnapshot struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	Value  uint64            `json:"value"`
}

func (r *Registry) Snapshot() []MetricSnapshot {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshots := make([]MetricSnapshot, 0, len(r.counters)+(len(r.durations)*2))
	for key, val := range r.counters {
		snapshots = append(snapshots, MetricSnapshot{
			Name:   key.name,
			Labels: decodeLabels(key.labels),
			Value:  val,
		})
	}
	for key, samples := range r.durations {
		if len(samples) == 0 {
			continue
		}
		snapshots = append(snapshots,
			MetricSnapshot{
				Name:   key.name + "_p95",
				Labels: decodeLabels(key.labels),
				Value:  percentile(samples, 0.95),
			},
			MetricSnapshot{
				Name:   key.name + "_p99",
				Labels: decodeLabels(key.labels),
				Value:  percentile(samples, 0.99),
			},
		)
	}
	return snapshots
}

func percentile(samples []uint64, quantile float64) uint64 {
	if len(samples) == 0 {
		return 0
	}
	if len(samples) == 1 {
		return samples[0]
	}
	ordered := append([]uint64(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := int(math.Ceil(quantile*float64(len(ordered)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(ordered) {
		index = len(ordered) - 1
	}
	return ordered[index]
}

func decodeLabels(s string) map[string]string {
	if s == "" {
		return nil
	}
	res := make(map[string]string)
	pairs := strings.Split(s, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			k := kv[0]
			v := strings.Trim(kv[1], `"`)
			v = strings.ReplaceAll(v, `\"`, `"`)
			v = strings.ReplaceAll(v, `\n`, "\n")
			v = strings.ReplaceAll(v, `\\`, `\`)
			res[k] = v
		}
	}
	return res
}
