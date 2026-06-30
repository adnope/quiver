import { describe, expect, it } from 'vitest'
import {
  buildAggregateChart,
  buildHistoryChart,
  buildLiveWidgetSnapshot,
  labelForMetric,
  liveSnapshotsToHistoryPoints,
  metricWidgetForName,
  parsePrometheusMetrics,
} from '@/lib/metrics-parser'
import type { MetricAggregatePoint, MetricHistoryPoint, MetricSnapshot } from '@/types/api'

describe('metrics parser', () => {
  it('maps metric names to dashboard widgets', () => {
    expect(metricWidgetForName('flow_records_normalized_total')).toBe('ingestion')
    expect(metricWidgetForName('flow_records_stored_total')).toBe('ingestion')
    expect(metricWidgetForName('flow_records_failed_total')).toBe('deadLetter')
    expect(metricWidgetForName('rate_limit_rejections_total')).toBe('deadLetter')
    expect(metricWidgetForName('storage_insert_duration_milliseconds_total')).toBe('dbLatency')
    expect(metricWidgetForName('storage_insert_duration_p90')).toBe('dbLatency')
    expect(metricWidgetForName('storage_insert_duration_p95')).toBe('dbLatency')
    expect(metricWidgetForName('storage_insert_duration_p99')).toBe('dbLatency')
    expect(metricWidgetForName('kafka_consumer_lag')).toBe('kafkaLag')
    expect(metricWidgetForName('unknown_metric')).toBeUndefined()
  })

  it('uses stable fallback labels when expected labels are missing', () => {
    expect(labelForMetric('ingestion', null)).toBe('unknown_source')
    expect(labelForMetric('ingestion', null, 'flow_records_stored_total')).toBe('Persisted')
    expect(labelForMetric('deadLetter', {})).toBe('unknown_reason')
    expect(labelForMetric('deadLetter', {}, 'rate_limit_rejections_total')).toBe('Rate Limited')
    expect(labelForMetric('dbLatency', {})).toBe('storage')
    expect(labelForMetric('dbLatency', {}, 'storage_insert_duration_milliseconds')).toBe('Average')
    expect(labelForMetric('dbLatency', {}, 'storage_insert_duration_p90')).toBe('p90')
    expect(labelForMetric('dbLatency', {}, 'storage_insert_duration_p95')).toBe('p95')
    expect(labelForMetric('dbLatency', {}, 'storage_insert_duration_p99')).toBe('p99')
    expect(labelForMetric('kafkaLag', { topic: 'flow.raw', partition: '2' })).toBe('flow.raw:2')
    expect(labelForMetric('ingestion', { source_type: 'SOURCE_TYPE_NETFLOW_V5' })).toBe(
      'NetFlow v5'
    )
    expect(labelForMetric('ingestion', { source_type: 'SOURCE_TYPE_NETFLOW_V9' })).toBe(
      'NetFlow v9'
    )
    expect(labelForMetric('ingestion', { source_type: 'SOURCE_TYPE_REST_JSON' })).toBe('REST')
    expect(labelForMetric('ingestion', { source_type: 'SOURCE_TYPE_ZEEK_CONN_JSON' })).toBe('Zeek')
  })

  it('parses Prometheus text exposition samples', () => {
    const snapshots = parsePrometheusMetrics(String.raw`
# HELP flow_records_normalized_total Normalized flows.
flow_records_normalized_total{source_type="rest_json"} 42
storage_insert_duration_milliseconds_total{status="ok"} 125.5
quoted_label_total{path="C:\\data\"set"} 3
ignored_bucket{le="+Inf"} +Inf
`)

    expect(snapshots).toEqual([
      {
        name: 'flow_records_normalized_total',
        labels: { source_type: 'rest_json' },
        value: 42,
      },
      {
        name: 'storage_insert_duration_milliseconds_total',
        labels: { status: 'ok' },
        value: 125.5,
      },
      {
        name: 'quoted_label_total',
        labels: { path: 'C:\\data"set' },
        value: 3,
      },
    ])
  })

  it('derives live counter rates and protects against counter resets', () => {
    const current: MetricSnapshot[] = [
      {
        name: 'flow_records_normalized_total',
        labels: { source_type: 'rest_json' },
        value: 150,
      },
      {
        name: 'flow_records_normalized_total',
        labels: { source_type: 'zeek_conn_json' },
        value: 3,
      },
    ]
    const previous: MetricSnapshot[] = [
      {
        name: 'flow_records_normalized_total',
        labels: { source_type: 'rest_json' },
        value: 125,
      },
      {
        name: 'flow_records_normalized_total',
        labels: { source_type: 'zeek_conn_json' },
        value: 10,
      },
    ]

    const chart = buildLiveWidgetSnapshot(
      current,
      previous,
      'ingestion',
      1,
      new Date('2026-06-20T15:00:01.900Z')
    )

    expect(chart.data).toHaveLength(1)
    expect(chart.data[0]?.REST).toBe(25)
    expect(chart.data[0]?.Zeek).toBe(0)
    expect(chart.data[0]?.total).toBe(25)
  })

  it('converts live snapshots into one-second history deltas', () => {
    const previous: MetricSnapshot[] = [
      {
        name: 'flow_records_normalized_total',
        labels: { source_type: 'rest_json' },
        value: 100,
      },
      {
        name: 'flow_records_failed_total',
        labels: { reason: 'validation_failed' },
        value: 10,
      },
    ]
    const current: MetricSnapshot[] = [
      {
        name: 'flow_records_normalized_total',
        labels: { source_type: 'rest_json' },
        value: 112,
      },
      {
        name: 'flow_records_failed_total',
        labels: { reason: 'validation_failed' },
        value: 2,
      },
    ]

    const points = liveSnapshotsToHistoryPoints(current, previous, new Date('2026-06-22T10:00:01Z'))

    expect(points.map((point) => point.delta)).toEqual([12, 0])
    expect(points.every((point) => point.timestamp === '2026-06-22T10:00:01.000Z')).toBe(true)
  })

  it('derives DB latency from duration total and count deltas', () => {
    const current: MetricSnapshot[] = [
      {
        name: 'storage_insert_duration_milliseconds_total',
        labels: { status: 'ok' },
        value: 1_600,
      },
      {
        name: 'storage_insert_duration_count',
        labels: { status: 'ok' },
        value: 40,
      },
    ]
    const previous: MetricSnapshot[] = [
      {
        name: 'storage_insert_duration_milliseconds_total',
        labels: { status: 'ok' },
        value: 1_000,
      },
      {
        name: 'storage_insert_duration_count',
        labels: { status: 'ok' },
        value: 20,
      },
    ]

    const chart = buildLiveWidgetSnapshot(
      current,
      previous,
      'dbLatency',
      1,
      new Date('2026-06-20T15:00:00Z')
    )

    expect(chart.data[0]?.Average).toBe(30)
  })

  it('overlays durable persisted, rate-limited, and DB percentile series', () => {
    const now = new Date('2026-06-20T15:00:01Z')
    const previous: MetricSnapshot[] = [
      { name: 'flow_records_stored_total', labels: null, value: 100 },
      {
        name: 'rate_limit_rejections_total',
        labels: { key: 'demo-client', scope: 'ingest' },
        value: 2,
      },
      { name: 'storage_insert_duration_milliseconds_total', labels: null, value: 1000 },
      { name: 'storage_insert_duration_count', labels: null, value: 20 },
    ]
    const current: MetricSnapshot[] = [
      { name: 'flow_records_stored_total', labels: null, value: 115 },
      {
        name: 'rate_limit_rejections_total',
        labels: { key: 'demo-client', scope: 'ingest' },
        value: 5,
      },
      { name: 'storage_insert_duration_milliseconds_total', labels: null, value: 1600 },
      { name: 'storage_insert_duration_count', labels: null, value: 40 },
      { name: 'storage_insert_duration_p95', labels: null, value: 55 },
      { name: 'storage_insert_duration_p99', labels: null, value: 90 },
    ]

    const ingestion = buildLiveWidgetSnapshot(current, previous, 'ingestion', 1, now)
    const deadLetter = buildLiveWidgetSnapshot(current, previous, 'deadLetter', 1, now)
    const dbLatency = buildLiveWidgetSnapshot(current, previous, 'dbLatency', 1, now)

    expect(ingestion.data[0]?.['Persisted']).toBe(15)
    expect(deadLetter.data[0]?.['Rate Limited']).toBe(3)
    expect(dbLatency.data[0]?.Average).toBe(30)
    expect(dbLatency.data[0]?.p95).toBe(55)
    expect(dbLatency.data[0]?.p99).toBe(90)
  })

  it('pivots history points and fills missing buckets with zeroes', () => {
    const now = new Date('2026-06-20T15:02:00Z')
    const points: MetricHistoryPoint[] = [
      {
        timestamp: '2026-06-20T15:00:00Z',
        name: 'flow_records_normalized_total',
        labels: { source_type: 'rest_json' },
        value: 100,
        delta: 60,
      },
      {
        timestamp: '2026-06-20T15:02:00Z',
        name: 'flow_records_normalized_total',
        labels: { source_type: 'rest_json' },
        value: 220,
        delta: 120,
      },
    ]

    const chart = buildHistoryChart(points, 'ingestion', '1m', now)

    const first = chart.data.find((datum) => datum.timestamp === '2026-06-20T15:00:00.000Z')
    const missing = chart.data.find((datum) => datum.timestamp === '2026-06-20T15:01:00.000Z')
    const last = chart.data.find((datum) => datum.timestamp === '2026-06-20T15:02:00.000Z')

    expect(first?.REST).toBe(12)
    expect(missing?.REST).toBe(0)
    expect(last?.REST).toBe(24)
  })

  it('builds aggregate charts with rollup stats for tooltips', () => {
    const now = new Date('2026-06-24T10:00:20Z')
    const points: MetricAggregatePoint[] = [
      {
        bucket_start: '2026-06-24T10:00:00Z',
        bucket_width_seconds: 20,
        metric_name: 'storage_insert_duration',
        labels: null,
        metric_kind: 'duration',
        sample_count: 4,
        count: 4,
        sum: 100,
        avg: 25,
        min: 10,
        max: 40,
        p90: 40,
        p95: 40,
        p99: 40,
        first: 10,
        last: 40,
        delta: null,
      },
    ]

    const chart = buildAggregateChart(points, 'dbLatency', '1h', now)
    const datum = chart.data.find((item) => item.timestamp === '2026-06-24T10:00:00.000Z')

    expect(datum?.Average).toBe(25)
    expect(datum?.p90).toBe(40)
    expect(datum?.aggregateStats?.Average?.count).toBe(4)
    expect(datum?.aggregateStats?.Average?.p95).toBe(40)
  })

  it('builds aggregate counter charts with peak and average rate stats', () => {
    const now = new Date('2026-06-24T10:00:20Z')
    const points: MetricAggregatePoint[] = [
      {
        bucket_start: '2026-06-24T10:00:00Z',
        bucket_width_seconds: 20,
        metric_name: 'flow_records_normalized_total',
        labels: { source_type: 'rest_json' },
        metric_kind: 'counter',
        sample_count: 4,
        count: 4,
        sum: 30000,
        avg: 7500,
        min: 0,
        max: 30000,
        p90: null,
        p95: null,
        p99: null,
        first: 0,
        last: 30000,
        delta: 30000,
        rate_avg: 1500,
        rate_peak: 6000,
      },
    ]

    const chart = buildAggregateChart(points, 'ingestion', '1h', now)
    const datum = chart.data.find((item) => item.timestamp === '2026-06-24T10:00:00.000Z')

    expect(datum?.REST).toBe(1500)
    expect(datum?.aggregateStats?.REST?.delta).toBe(30000)
    expect(datum?.aggregateStats?.REST?.rateAvg).toBe(1500)
    expect(datum?.aggregateStats?.REST?.ratePeak).toBe(6000)
  })

  it('returns an empty zero timeline when no series are present', () => {
    const chart = buildHistoryChart([], 'kafkaLag', '1m', new Date('2026-06-20T15:00:00Z'))

    expect(chart.series).toHaveLength(0)
    expect(chart.data.length).toBeGreaterThan(0)
    expect(chart.data.every((datum) => datum.total === 0)).toBe(true)
  })
})
