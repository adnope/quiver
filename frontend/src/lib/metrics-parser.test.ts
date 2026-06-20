import { describe, expect, it } from 'vitest'
import {
  buildHistoryChart,
  buildLiveWidgetSnapshot,
  labelForMetric,
  metricWidgetForName,
  parsePrometheusMetrics,
} from '@/lib/metrics-parser'
import type { MetricHistoryPoint, MetricSnapshot } from '@/types/api'

describe('metrics parser', () => {
  it('maps metric names to dashboard widgets', () => {
    expect(metricWidgetForName('flow_records_normalized_total')).toBe('ingestion')
    expect(metricWidgetForName('flow_records_failed_total')).toBe('deadLetter')
    expect(metricWidgetForName('storage_insert_duration_milliseconds_total')).toBe(
      'dbLatency',
    )
    expect(metricWidgetForName('kafka_consumer_lag')).toBe('kafkaLag')
    expect(metricWidgetForName('unknown_metric')).toBeUndefined()
  })

  it('uses stable fallback labels when expected labels are missing', () => {
    expect(labelForMetric('ingestion', null)).toBe('unknown_source')
    expect(labelForMetric('deadLetter', {})).toBe('unknown_reason')
    expect(labelForMetric('dbLatency', {})).toBe('storage')
    expect(labelForMetric('kafkaLag', { topic: 'flow.raw', partition: '2' })).toBe(
      'flow.raw:2',
    )
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
      new Date('2026-06-20T15:00:01.900Z'),
    )

    expect(chart.data).toHaveLength(1)
    expect(chart.data[0]?.rest_json).toBe(25)
    expect(chart.data[0]?.zeek_conn_json).toBe(0)
    expect(chart.data[0]?.total).toBe(25)
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
      new Date('2026-06-20T15:00:00Z'),
    )

    expect(chart.data[0]?.ok).toBe(30)
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

    const first = chart.data.find(
      (datum) => datum.timestamp === '2026-06-20T15:00:00.000Z',
    )
    const missing = chart.data.find(
      (datum) => datum.timestamp === '2026-06-20T15:01:00.000Z',
    )
    const last = chart.data.find(
      (datum) => datum.timestamp === '2026-06-20T15:02:00.000Z',
    )

    expect(first?.rest_json).toBe(60)
    expect(missing?.rest_json).toBe(0)
    expect(last?.rest_json).toBe(120)
  })

  it('returns an empty zero timeline when no series are present', () => {
    const chart = buildHistoryChart([], 'kafkaLag', '1m', new Date('2026-06-20T15:00:00Z'))

    expect(chart.series).toHaveLength(0)
    expect(chart.data.length).toBeGreaterThan(0)
    expect(chart.data.every((datum) => datum.total === 0)).toBe(true)
  })
})
