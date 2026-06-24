package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/adnope/quiver/internal/config"
	"github.com/adnope/quiver/internal/observability"
)

type MetricAggregatePoint struct {
	BucketStart        time.Time         `json:"bucket_start"`
	BucketWidthSeconds int               `json:"bucket_width_seconds"`
	MetricName         string            `json:"metric_name"`
	Labels             map[string]string `json:"labels"`
	MetricKind         string            `json:"metric_kind"`
	SampleCount        uint64            `json:"sample_count"`
	Count              uint64            `json:"count"`
	Sum                *float64          `json:"sum"`
	Avg                *float64          `json:"avg"`
	Min                *float64          `json:"min"`
	Max                *float64          `json:"max"`
	P90                *float64          `json:"p90"`
	P95                *float64          `json:"p95"`
	P99                *float64          `json:"p99"`
	First              *float64          `json:"first"`
	Last               *float64          `json:"last"`
	Delta              *float64          `json:"delta"`
}

type MetricAggregatesResponse struct {
	From        time.Time              `json:"from"`
	To          time.Time              `json:"to"`
	StepSeconds int                    `json:"step_seconds"`
	Points      []MetricAggregatePoint `json:"points"`
}

type metricAggregatesQuery struct {
	From            time.Time
	To              time.Time
	Step            time.Duration
	Metrics         []string
	BaseBucketWidth time.Duration
	MaxPoints       int
}

type aggregateRollupKey struct {
	BucketStart time.Time
	MetricName  string
	LabelsKey   string
}

type aggregateRollup struct {
	point              MetricAggregatePoint
	hasSum             bool
	sum                float64
	hasMin             bool
	min                float64
	hasMax             bool
	max                float64
	hasDelta           bool
	delta              float64
	earliestBucket     time.Time
	latestBucket       time.Time
	hasFirst           bool
	first              float64
	hasLast            bool
	last               float64
	hasP90             bool
	p90                float64
	hasP95             bool
	p95                float64
	hasP99             bool
	p99                float64
	histogramByBucket  map[int]uint64
	hasHistogramCounts bool
}

// MetricsAggregatesHandler godoc
// @Summary Bucketed metric aggregates
// @Description Returns bounded system metric aggregate points for arbitrary from/to/step windows. Duration percentiles are recomputed from merged histogram buckets when histogram data exists.
// @Tags metrics
// @Produce json
// @Security ApiKeyAuth
// @Param X-API-Key header string true "API key with metrics scope when metrics auth is enabled"
// @Param from query string true "RFC3339 inclusive start timestamp"
// @Param to query string true "RFC3339 exclusive end timestamp"
// @Param step query string false "Rollup step duration, for example 5s, 20s, 1m"
// @Param metric query []string false "Metric name filter; repeat metric for multiple names" collectionFormat(multi)
// @Success 200 {object} MetricAggregatesResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Router /api/v1/metrics/aggregates [get]
func MetricsAggregatesHandler(db *sql.DB, cfg config.ObservabilityConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if db == nil {
			writeError(w, r, http.StatusServiceUnavailable, CodeServiceUnavailable, "metrics aggregate storage is unavailable", nil)
			return
		}

		query, ok := parseMetricAggregatesQuery(w, r, cfg)
		if !ok {
			return
		}

		points, err := queryMetricAggregates(r.Context(), db, query)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, CodeInternalError, "failed to query metric aggregates", nil)
			return
		}

		writeJSON(w, http.StatusOK, MetricAggregatesResponse{
			From:        query.From,
			To:          query.To,
			StepSeconds: int(query.Step.Seconds()),
			Points:      points,
		})
	})
}

func parseMetricAggregatesQuery(
	w http.ResponseWriter,
	r *http.Request,
	cfg config.ObservabilityConfig,
) (metricAggregatesQuery, bool) {
	baseBucketWidth := cfg.MetricsAggregateBucketWidth.Std()
	if baseBucketWidth <= 0 {
		baseBucketWidth = config.DefaultMetricsAggregateBucketWidth.Std()
	}
	maxPoints := cfg.MetricsAggregateMaxPoints
	if maxPoints <= 0 {
		maxPoints = config.DefaultMetricsAggregateMaxPoints
	}

	values := r.URL.Query()
	from, err := parseRequiredRFC3339(values.Get("from"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, CodeInvalidParameter, "from must be a required RFC3339 timestamp", nil)
		return metricAggregatesQuery{}, false
	}
	to, err := parseRequiredRFC3339(values.Get("to"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, CodeInvalidParameter, "to must be a required RFC3339 timestamp", nil)
		return metricAggregatesQuery{}, false
	}
	if !to.After(from) {
		writeError(w, r, http.StatusBadRequest, CodeInvalidParameter, "to must be after from", nil)
		return metricAggregatesQuery{}, false
	}

	step := baseBucketWidth
	if rawStep := strings.TrimSpace(values.Get("step")); rawStep != "" {
		step, err = time.ParseDuration(rawStep)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, CodeInvalidParameter, "step must be a valid duration", nil)
			return metricAggregatesQuery{}, false
		}
	}
	if step < baseBucketWidth {
		writeError(w, r, http.StatusBadRequest, CodeInvalidParameter, "step must be greater than or equal to the aggregate bucket width", nil)
		return metricAggregatesQuery{}, false
	}
	if step%baseBucketWidth != 0 {
		writeError(w, r, http.StatusBadRequest, CodeInvalidParameter, "step must be an integer multiple of the aggregate bucket width", nil)
		return metricAggregatesQuery{}, false
	}
	pointCount := ceilDurationDiv(to.Sub(from), step)
	if pointCount > maxPoints {
		writeError(w, r, http.StatusBadRequest, CodeQueryWindowTooLarge, "metric aggregate query would return too many chart points", map[string]any{
			"max_points": maxPoints,
			"points":     pointCount,
		})
		return metricAggregatesQuery{}, false
	}

	metrics := make([]string, 0)
	for _, metric := range values["metric"] {
		metric = strings.TrimSpace(metric)
		if metric != "" {
			metrics = append(metrics, metric)
		}
	}

	return metricAggregatesQuery{
		From:            from.UTC(),
		To:              to.UTC(),
		Step:            step,
		Metrics:         metrics,
		BaseBucketWidth: baseBucketWidth,
		MaxPoints:       maxPoints,
	}, true
}

func parseRequiredRFC3339(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, fmt.Errorf("timestamp is required")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed, nil
}

func ceilDurationDiv(window time.Duration, step time.Duration) int {
	points := int(window / step)
	if window%step != 0 {
		points++
	}
	return points
}

func queryMetricAggregates(
	ctx context.Context,
	db *sql.DB,
	query metricAggregatesQuery,
) ([]MetricAggregatePoint, error) {
	rollups := map[aggregateRollupKey]*aggregateRollup{}
	if err := queryBaseMetricAggregates(ctx, db, query, rollups); err != nil {
		return nil, err
	}
	if err := queryMetricHistogramBuckets(ctx, db, query, rollups); err != nil {
		return nil, err
	}

	points := make([]MetricAggregatePoint, 0, len(rollups))
	for _, rollup := range rollups {
		points = append(points, rollup.toPoint())
	}
	sort.Slice(points, func(i, j int) bool {
		if points[i].BucketStart.Equal(points[j].BucketStart) {
			if points[i].MetricName == points[j].MetricName {
				return labelsStableKey(points[i].Labels) < labelsStableKey(points[j].Labels)
			}
			return points[i].MetricName < points[j].MetricName
		}
		return points[i].BucketStart.Before(points[j].BucketStart)
	})
	return points, nil
}

func queryBaseMetricAggregates(
	ctx context.Context,
	db *sql.DB,
	query metricAggregatesQuery,
	rollups map[aggregateRollupKey]*aggregateRollup,
) error {
	rows, err := queryBaseMetricAggregateRows(ctx, db, query)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		row, err := scanMetricAggregateRow(rows)
		if err != nil {
			return err
		}
		key := rollupKeyFor(row.BucketStart, row.MetricName, row.Labels, query.From, query.Step)
		rollup := rollups[key]
		if rollup == nil {
			rollup = newAggregateRollup(key, row, query.Step)
			rollups[key] = rollup
		}
		rollup.addRow(row)
	}
	return rows.Err()
}

func queryMetricHistogramBuckets(
	ctx context.Context,
	db *sql.DB,
	query metricAggregatesQuery,
	rollups map[aggregateRollupKey]*aggregateRollup,
) error {
	rows, err := queryMetricHistogramBucketRows(ctx, db, query)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var bucketStart time.Time
		var metricName string
		var labelsJSON []byte
		var bucketIndex int
		var count int64
		if err := rows.Scan(&bucketStart, &metricName, &labelsJSON, &bucketIndex, &count); err != nil {
			return err
		}
		labels, err := decodeMetricLabels(labelsJSON)
		if err != nil {
			return err
		}
		key := rollupKeyFor(bucketStart, metricName, labels, query.From, query.Step)
		rollup := rollups[key]
		if rollup == nil {
			rollup = &aggregateRollup{
				point: MetricAggregatePoint{
					BucketStart:        key.BucketStart,
					BucketWidthSeconds: int(query.Step.Seconds()),
					MetricName:         metricName,
					Labels:             labels,
					MetricKind:         string(observability.MetricKindDuration),
				},
				histogramByBucket: map[int]uint64{},
			}
			rollups[key] = rollup
		}
		if bucketIndex >= 0 && count > 0 {
			rollup.histogramByBucket[bucketIndex] += uint64(count) //nolint:gosec
			rollup.hasHistogramCounts = true
		}
	}
	return rows.Err()
}

const baseMetricAggregatesQuery = `
	SELECT
		bucket_start,
		metric_name,
		labels,
		metric_kind,
		sample_count,
		count,
		sum,
		avg,
		min,
		max,
		p90,
		p95,
		p99,
		first,
		last,
		delta
	FROM quiver.system_metric_aggregates
	WHERE bucket_start >= $1
	  AND bucket_start < $2
	  AND bucket_width_seconds = $3
	ORDER BY bucket_start ASC, metric_name ASC, labels ASC`

const baseMetricAggregatesByMetricQuery = `
	SELECT
		bucket_start,
		metric_name,
		labels,
		metric_kind,
		sample_count,
		count,
		sum,
		avg,
		min,
		max,
		p90,
		p95,
		p99,
		first,
		last,
		delta
	FROM quiver.system_metric_aggregates
	WHERE bucket_start >= $1
	  AND bucket_start < $2
	  AND bucket_width_seconds = $3
	  AND metric_name = ANY($4::text[])
	ORDER BY bucket_start ASC, metric_name ASC, labels ASC`

const metricHistogramBucketsQuery = `
	SELECT bucket_start, metric_name, labels, bucket_index, count
	FROM quiver.system_metric_histogram_buckets
	WHERE bucket_start >= $1
	  AND bucket_start < $2
	  AND bucket_width_seconds = $3
	ORDER BY bucket_start ASC, metric_name ASC, labels ASC, bucket_index ASC`

const metricHistogramBucketsByMetricQuery = `
	SELECT bucket_start, metric_name, labels, bucket_index, count
	FROM quiver.system_metric_histogram_buckets
	WHERE bucket_start >= $1
	  AND bucket_start < $2
	  AND bucket_width_seconds = $3
	  AND metric_name = ANY($4::text[])
	ORDER BY bucket_start ASC, metric_name ASC, labels ASC, bucket_index ASC`

func queryBaseMetricAggregateRows(ctx context.Context, db *sql.DB, query metricAggregatesQuery) (*sql.Rows, error) {
	args := []any{query.From, query.To, int(query.BaseBucketWidth.Seconds())}
	if len(query.Metrics) == 0 {
		return db.QueryContext(ctx, baseMetricAggregatesQuery, args...)
	}
	return db.QueryContext(ctx, baseMetricAggregatesByMetricQuery, append(args, pq.Array(query.Metrics))...)
}

func queryMetricHistogramBucketRows(ctx context.Context, db *sql.DB, query metricAggregatesQuery) (*sql.Rows, error) {
	args := []any{query.From, query.To, int(query.BaseBucketWidth.Seconds())}
	if len(query.Metrics) == 0 {
		return db.QueryContext(ctx, metricHistogramBucketsQuery, args...)
	}
	return db.QueryContext(ctx, metricHistogramBucketsByMetricQuery, append(args, pq.Array(query.Metrics))...)
}

func scanMetricAggregateRow(rows *sql.Rows) (MetricAggregatePoint, error) {
	var point MetricAggregatePoint
	var labelsJSON []byte
	var sampleCount int64
	var count int64
	var sum sql.NullFloat64
	var avg sql.NullFloat64
	var min sql.NullFloat64
	var max sql.NullFloat64
	var p90 sql.NullFloat64
	var p95 sql.NullFloat64
	var p99 sql.NullFloat64
	var first sql.NullFloat64
	var last sql.NullFloat64
	var delta sql.NullFloat64

	err := rows.Scan(
		&point.BucketStart,
		&point.MetricName,
		&labelsJSON,
		&point.MetricKind,
		&sampleCount,
		&count,
		&sum,
		&avg,
		&min,
		&max,
		&p90,
		&p95,
		&p99,
		&first,
		&last,
		&delta,
	)
	if err != nil {
		return MetricAggregatePoint{}, err
	}
	labels, err := decodeMetricLabels(labelsJSON)
	if err != nil {
		return MetricAggregatePoint{}, err
	}
	point.Labels = labels
	point.SampleCount = nonNegativeInt64(sampleCount)
	point.Count = nonNegativeInt64(count)
	point.Sum = nullFloatPtr(sum)
	point.Avg = nullFloatPtr(avg)
	point.Min = nullFloatPtr(min)
	point.Max = nullFloatPtr(max)
	point.P90 = nullFloatPtr(p90)
	point.P95 = nullFloatPtr(p95)
	point.P99 = nullFloatPtr(p99)
	point.First = nullFloatPtr(first)
	point.Last = nullFloatPtr(last)
	point.Delta = nullFloatPtr(delta)
	return point, nil
}

func decodeMetricLabels(raw []byte) (map[string]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]string{}, nil
	}
	labels := map[string]string{}
	if err := json.Unmarshal(raw, &labels); err != nil {
		return nil, err
	}
	if labels == nil {
		return map[string]string{}, nil
	}
	return labels, nil
}

func nonNegativeInt64(value int64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value) //nolint:gosec
}

func nullFloatPtr(value sql.NullFloat64) *float64 {
	if !value.Valid {
		return nil
	}
	return &value.Float64
}

func rollupKeyFor(
	bucketStart time.Time,
	metricName string,
	labels map[string]string,
	from time.Time,
	step time.Duration,
) aggregateRollupKey {
	return aggregateRollupKey{
		BucketStart: alignToQueryStart(bucketStart.UTC(), from.UTC(), step),
		MetricName:  metricName,
		LabelsKey:   labelsStableKey(labels),
	}
}

func alignToQueryStart(value time.Time, from time.Time, step time.Duration) time.Time {
	if step <= 0 || !value.After(from) {
		return from
	}
	offset := value.Sub(from)
	return from.Add((offset / step) * step).UTC()
}

func labelsStableKey(labels map[string]string) string {
	if len(labels) == 0 {
		return "{}"
	}
	data, err := json.Marshal(labels)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func newAggregateRollup(
	key aggregateRollupKey,
	row MetricAggregatePoint,
	step time.Duration,
) *aggregateRollup {
	return &aggregateRollup{
		point: MetricAggregatePoint{
			BucketStart:        key.BucketStart,
			BucketWidthSeconds: int(step.Seconds()),
			MetricName:         row.MetricName,
			Labels:             row.Labels,
			MetricKind:         row.MetricKind,
		},
		histogramByBucket: map[int]uint64{},
	}
}

func (r *aggregateRollup) addRow(row MetricAggregatePoint) {
	r.point.SampleCount += row.SampleCount
	r.point.Count += row.Count
	if row.Sum != nil {
		r.hasSum = true
		r.sum += *row.Sum
	}
	if row.Min != nil && (!r.hasMin || *row.Min < r.min) {
		r.hasMin = true
		r.min = *row.Min
	}
	if row.Max != nil && (!r.hasMax || *row.Max > r.max) {
		r.hasMax = true
		r.max = *row.Max
	}
	if row.Delta != nil {
		r.hasDelta = true
		r.delta += *row.Delta
	}
	if row.First != nil && (!r.hasFirst || row.BucketStart.Before(r.earliestBucket)) {
		r.hasFirst = true
		r.first = *row.First
		r.earliestBucket = row.BucketStart
	}
	if row.Last != nil && (!r.hasLast || row.BucketStart.After(r.latestBucket)) {
		r.hasLast = true
		r.last = *row.Last
		r.latestBucket = row.BucketStart
	}
	if row.P90 != nil && (!r.hasP90 || *row.P90 > r.p90) {
		r.hasP90 = true
		r.p90 = *row.P90
	}
	if row.P95 != nil && (!r.hasP95 || *row.P95 > r.p95) {
		r.hasP95 = true
		r.p95 = *row.P95
	}
	if row.P99 != nil && (!r.hasP99 || *row.P99 > r.p99) {
		r.hasP99 = true
		r.p99 = *row.P99
	}
}

func (r *aggregateRollup) toPoint() MetricAggregatePoint {
	if r.hasSum {
		r.point.Sum = floatPtr(r.sum)
		if r.point.Count > 0 {
			r.point.Avg = floatPtr(r.sum / float64(r.point.Count))
		} else if r.point.SampleCount > 0 {
			r.point.Avg = floatPtr(r.sum / float64(r.point.SampleCount))
		}
	}
	if r.hasMin {
		r.point.Min = floatPtr(r.min)
	}
	if r.hasMax {
		r.point.Max = floatPtr(r.max)
	}
	if r.hasFirst {
		r.point.First = floatPtr(r.first)
	}
	if r.hasLast {
		r.point.Last = floatPtr(r.last)
	}
	if r.hasDelta {
		r.point.Delta = floatPtr(r.delta)
	}
	if r.hasHistogramCounts {
		counts := histogramCountsSlice(r.histogramByBucket)
		r.point.P90 = floatPtr(observability.PercentileFromHistogramBuckets(counts, 0.90))
		r.point.P95 = floatPtr(observability.PercentileFromHistogramBuckets(counts, 0.95))
		r.point.P99 = floatPtr(observability.PercentileFromHistogramBuckets(counts, 0.99))
		return r.point
	}
	if r.hasP90 {
		r.point.P90 = floatPtr(r.p90)
	}
	if r.hasP95 {
		r.point.P95 = floatPtr(r.p95)
	}
	if r.hasP99 {
		r.point.P99 = floatPtr(r.p99)
	}
	return r.point
}

func histogramCountsSlice(countsByBucket map[int]uint64) []uint64 {
	if len(countsByBucket) == 0 {
		return nil
	}
	maxIndex := 0
	for index := range countsByBucket {
		if index > maxIndex {
			maxIndex = index
		}
	}
	counts := make([]uint64, maxIndex+1)
	for index, count := range countsByBucket {
		if index >= 0 {
			counts[index] = count
		}
	}
	return counts
}

func floatPtr(value float64) *float64 {
	return &value
}
