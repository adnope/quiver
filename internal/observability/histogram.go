package observability

import "math"

var durationHistogramUpperBounds = []float64{
	1,
	2,
	5,
	10,
	25,
	50,
	100,
	250,
	500,
	1000,
	2500,
	5000,
	10000,
	math.Inf(1),
}

func durationHistogramBucketCount() int {
	return len(durationHistogramUpperBounds)
}

func durationHistogramBucketIndex(value float64) int {
	for i, upperBound := range durationHistogramUpperBounds {
		if value <= upperBound {
			return i
		}
	}
	return len(durationHistogramUpperBounds) - 1
}

func durationHistogramBucketUpperBound(index int) *float64 {
	if index < 0 || index >= len(durationHistogramUpperBounds) {
		return nil
	}
	upperBound := durationHistogramUpperBounds[index]
	if math.IsInf(upperBound, 1) {
		return nil
	}
	return new(upperBound)
}

func PercentileFromHistogramBuckets(counts []uint64, quantile float64) float64 {
	return percentileFromHistogram(counts, quantile)
}

func percentileFromHistogram(counts []uint64, quantile float64) float64 {
	if len(counts) == 0 {
		return 0
	}
	var total uint64
	for _, count := range counts {
		total += count
	}
	if total == 0 {
		return 0
	}

	rank := uint64(math.Ceil(quantile * float64(total)))
	if rank == 0 {
		rank = 1
	}

	var cumulative uint64
	for i, count := range counts {
		cumulative += count
		if cumulative >= rank {
			if upperBound := durationHistogramBucketUpperBound(i); upperBound != nil {
				return *upperBound
			}
			return durationHistogramUpperBounds[len(durationHistogramUpperBounds)-2]
		}
	}
	return durationHistogramUpperBounds[len(durationHistogramUpperBounds)-2]
}
