package observability

import (
	"testing"
)

func TestHistogram_BucketUpperBound_OutOfBounds(t *testing.T) {
	t.Parallel()

	if bound := durationHistogramBucketUpperBound(-1); bound != nil {
		t.Errorf("expected nil for negative index, got %v", *bound)
	}
	if bound := durationHistogramBucketUpperBound(9999); bound != nil {
		t.Errorf("expected nil for out of bounds index, got %v", *bound)
	}
}

func TestPercentileFromHistogramBuckets(t *testing.T) {
	t.Parallel()

	// Empty counts
	if p := PercentileFromHistogramBuckets(nil, 0.95); p != 0 {
		t.Errorf("expected 0 for nil counts, got %f", p)
	}

	// Zero total count
	if p := PercentileFromHistogramBuckets([]uint64{0, 0}, 0.95); p != 0 {
		t.Errorf("expected 0 for zero total count, got %f", p)
	}

	// Valid calculations
	counts := make([]uint64, durationHistogramBucketCount())
	counts[0] = 10 // 10 samples in <=1 bucket
	counts[1] = 5  // 5 samples in <=2 bucket

	// Total = 15. Quantile 0.5 rank is Ceil(0.5 * 15) = 8.
	// 8 <= cumulative 10. So it falls in index 0 (upperBound 1).
	p := PercentileFromHistogramBuckets(counts, 0.5)
	if p != 1.0 {
		t.Errorf("expected p50 to be 1.0, got %f", p)
	}

	// Quantile 0.9 rank is Ceil(0.9 * 15) = 14.
	// 14 > cumulative 10, <= cumulative 15 (index 1, upperBound 2).
	p = PercentileFromHistogramBuckets(counts, 0.9)
	if p != 2.0 {
		t.Errorf("expected p90 to be 2.0, got %f", p)
	}

	// Fallback to highest non-infinity bucket
	counts[len(counts)-1] = 100 // add a lot to Inf bucket
	p = PercentileFromHistogramBuckets(counts, 0.99)
	expectedFallback := durationHistogramUpperBounds[len(durationHistogramUpperBounds)-2]
	if p != expectedFallback {
		t.Errorf("expected fallback to %f, got %f", expectedFallback, p)
	}
}
