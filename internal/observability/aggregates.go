package observability

import "time"

type MetricKind string

const (
	MetricKindCounter  MetricKind = "counter"
	MetricKindGauge    MetricKind = "gauge"
	MetricKindDuration MetricKind = "duration"
)

type MetricAggregate struct {
	BucketStart        time.Time         `json:"bucket_start"`
	BucketWidthSeconds int               `json:"bucket_width_seconds"`
	MetricName         string            `json:"metric_name"`
	Labels             map[string]string `json:"labels"`
	MetricKind         MetricKind        `json:"metric_kind"`
	SampleCount        uint64            `json:"sample_count"`
	Count              uint64            `json:"count"`
	Sum                *float64          `json:"sum,omitempty"`
	Avg                *float64          `json:"avg,omitempty"`
	Min                *float64          `json:"min,omitempty"`
	Max                *float64          `json:"max,omitempty"`
	P90                *float64          `json:"p90,omitempty"`
	P95                *float64          `json:"p95,omitempty"`
	P99                *float64          `json:"p99,omitempty"`
	First              *float64          `json:"first,omitempty"`
	Last               *float64          `json:"last,omitempty"`
	Delta              *float64          `json:"delta,omitempty"`
}

type MetricHistogramBucket struct {
	BucketStart        time.Time         `json:"bucket_start"`
	BucketWidthSeconds int               `json:"bucket_width_seconds"`
	MetricName         string            `json:"metric_name"`
	Labels             map[string]string `json:"labels"`
	BucketIndex        int               `json:"bucket_index"`
	BucketUpperBound   *float64          `json:"bucket_upper_bound,omitempty"`
	Count              uint64            `json:"count"`
}

type metricAccumulator struct {
	kind        MetricKind
	sampleCount uint64
	count       uint64
	sum         float64
	min         float64
	max         float64
	first       float64
	last        float64
	delta       float64
	hasValue    bool
}

func (a *metricAccumulator) observeGauge(value float64) {
	a.kind = MetricKindGauge
	a.sampleCount++
	a.count++
	a.sum += value
	a.observeValue(value)
	a.delta = a.last - a.first
}

func (a *metricAccumulator) observeCounter(previous uint64, current uint64, delta uint64) {
	a.kind = MetricKindCounter
	a.sampleCount++
	a.count++
	a.sum += float64(delta)
	if !a.hasValue {
		a.first = float64(previous)
		a.min = float64(current)
		a.max = float64(current)
		a.hasValue = true
	} else {
		currentFloat := float64(current)
		if currentFloat < a.min {
			a.min = currentFloat
		}
		if currentFloat > a.max {
			a.max = currentFloat
		}
	}
	a.last = float64(current)
	a.delta += float64(delta)
}

func (a *metricAccumulator) observeDuration(value float64) {
	a.kind = MetricKindDuration
	a.sampleCount++
	a.count++
	a.sum += value
	a.observeValue(value)
}

func (a *metricAccumulator) observeValue(value float64) {
	if !a.hasValue {
		a.first = value
		a.min = value
		a.max = value
		a.hasValue = true
	} else {
		if value < a.min {
			a.min = value
		}
		if value > a.max {
			a.max = value
		}
	}
	a.last = value
}

func (a metricAccumulator) toAggregate(
	bucketStart time.Time,
	bucketWidth time.Duration,
	key seriesKey,
	histogram []uint64,
) MetricAggregate {
	agg := MetricAggregate{
		BucketStart:        bucketStart.UTC(),
		BucketWidthSeconds: int(bucketWidth.Seconds()),
		MetricName:         key.name,
		Labels:             normalizeLabels(decodeLabels(key.labels)),
		MetricKind:         a.kind,
		SampleCount:        a.sampleCount,
		Count:              a.count,
	}
	if a.count > 0 {
		agg.Sum = floatPtr(a.sum)
		agg.Avg = floatPtr(a.sum / float64(a.count))
	}
	if a.hasValue {
		agg.Min = floatPtr(a.min)
		agg.Max = floatPtr(a.max)
		agg.First = floatPtr(a.first)
		agg.Last = floatPtr(a.last)
	}
	if a.kind == MetricKindCounter || a.kind == MetricKindGauge {
		agg.Delta = floatPtr(a.delta)
	}
	if a.kind == MetricKindDuration && len(histogram) > 0 {
		agg.P90 = floatPtr(percentileFromHistogram(histogram, 0.90))
		agg.P95 = floatPtr(percentileFromHistogram(histogram, 0.95))
		agg.P99 = floatPtr(percentileFromHistogram(histogram, 0.99))
	}
	return agg
}

func normalizeLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return map[string]string{}
	}
	return labels
}

func floatPtr(value float64) *float64 {
	return &value
}

func alignBucketStart(now time.Time, width time.Duration) time.Time {
	if width <= 0 {
		return now.UTC()
	}
	return now.UTC().Truncate(width)
}
