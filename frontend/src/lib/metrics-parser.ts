import type { MetricHistoryPoint, MetricSnapshot } from '@/types/api'

export type MetricWidget = 'ingestion' | 'deadLetter' | 'dbLatency' | 'kafkaLag'

export type MetricRange = '1m' | '1h' | '12h' | '24h' | '1w' | '30d'

export type ChartDatum = { timestamp: string; total: number } & Record<
  string,
  number | string
>

export interface ChartSeries {
  key: string
  label: string
  color: string
}

export interface WidgetChartData {
  widget: MetricWidget
  series: ChartSeries[]
  data: ChartDatum[]
}

interface RangeConfig {
  windowMs: number
  bucketMs: number
  bucketSeconds: number
}

interface SeriesPoint {
  timestamp: string
  seriesKey: string
  value: number
}

const RANGE_CONFIG: Record<MetricRange, RangeConfig> = {
  '1m': { windowMs: 60_000, bucketMs: 1_000, bucketSeconds: 1 },
  '1h': { windowMs: 60 * 60_000, bucketMs: 60_000, bucketSeconds: 60 },
  '12h': {
    windowMs: 12 * 60 * 60_000,
    bucketMs: 10 * 60_000,
    bucketSeconds: 600,
  },
  '24h': {
    windowMs: 24 * 60 * 60_000,
    bucketMs: 20 * 60_000,
    bucketSeconds: 1_200,
  },
  '1w': {
    windowMs: 7 * 24 * 60 * 60_000,
    bucketMs: 60 * 60_000,
    bucketSeconds: 3_600,
  },
  '30d': {
    windowMs: 30 * 24 * 60 * 60_000,
    bucketMs: 8 * 60 * 60_000,
    bucketSeconds: 28_800,
  },
}

const WIDGET_COLORS: Record<MetricWidget, string[]> = {
  ingestion: ['#06B6D4', '#3B82F6', '#0EA5E9', '#22D3EE'],
  deadLetter: ['#EF4444', '#F43F5E', '#DC2626', '#FB7185'],
  dbLatency: ['#10B981', '#22C55E', '#34D399', '#059669'],
  kafkaLag: ['#F59E0B', '#F97316', '#FBBF24', '#EA580C'],
}

const COUNTER_WIDGETS = new Set<MetricWidget>(['ingestion', 'deadLetter'])
const PROMETHEUS_SAMPLE =
  /^(?<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?<labels>.*)\})?\s+(?<value>[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?|[+-]?Inf|NaN)(?:\s+\d+)?$/

export function rangeConfig(range: MetricRange): RangeConfig {
  return RANGE_CONFIG[range]
}

export function metricWidgetForName(name: string): MetricWidget | undefined {
  switch (name) {
    case 'flow_records_normalized_total':
      return 'ingestion'
    case 'flow_records_failed_total':
      return 'deadLetter'
    case 'storage_insert_duration_milliseconds':
    case 'storage_insert_duration_milliseconds_total':
    case 'storage_insert_duration_count':
      return 'dbLatency'
    case 'kafka_consumer_lag':
      return 'kafkaLag'
    default:
      return undefined
  }
}

export function parsePrometheusMetrics(text: string): MetricSnapshot[] {
  const snapshots: MetricSnapshot[] = []

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (line === '' || line.startsWith('#')) {
      continue
    }

    const match = PROMETHEUS_SAMPLE.exec(line)
    if (!match?.groups) {
      continue
    }

    const value = parsePrometheusNumber(match.groups.value ?? '')
    if (!Number.isFinite(value)) {
      continue
    }

    snapshots.push({
      name: match.groups.name ?? '',
      labels: parsePrometheusLabels(match.groups.labels ?? ''),
      value,
    })
  }

  return snapshots
}

function parsePrometheusLabels(rawLabels: string): Record<string, string> | null {
  if (rawLabels.trim() === '') {
    return null
  }

  const labels: Record<string, string> = {}
  let index = 0

  while (index < rawLabels.length) {
    const keyStart = index
    while (index < rawLabels.length && rawLabels[index] !== '=') {
      index += 1
    }
    const key = rawLabels.slice(keyStart, index).trim()
    index += 1

    if (rawLabels[index] !== '"') {
      break
    }
    index += 1

    let value = ''
    while (index < rawLabels.length) {
      const char = rawLabels[index]
      if (char === '\\') {
        const escaped = rawLabels[index + 1]
        if (escaped === undefined) {
          break
        }
        value += unescapePrometheusChar(escaped)
        index += 2
        continue
      }
      if (char === '"') {
        index += 1
        break
      }
      value += char
      index += 1
    }

    if (key !== '') {
      labels[key] = value
    }

    while (index < rawLabels.length && rawLabels[index] !== ',') {
      index += 1
    }
    if (rawLabels[index] === ',') {
      index += 1
    }
  }

  return Object.keys(labels).length > 0 ? labels : null
}

function unescapePrometheusChar(char: string) {
  switch (char) {
    case 'n':
      return '\n'
    case '\\':
      return '\\'
    case '"':
      return '"'
    default:
      return char
  }
}

function parsePrometheusNumber(value: string) {
  switch (value) {
    case '+Inf':
    case 'Inf':
      return Number.POSITIVE_INFINITY
    case '-Inf':
      return Number.NEGATIVE_INFINITY
    case 'NaN':
      return Number.NaN
    default:
      return Number(value)
  }
}

export function labelForMetric(
  widget: MetricWidget,
  labels: Record<string, string> | null | undefined,
) {
  switch (widget) {
    case 'ingestion':
      return labels?.source_type ?? 'unknown_source'
    case 'deadLetter':
      return labels?.reason ?? 'unknown_reason'
    case 'dbLatency':
      return labels?.status ?? 'storage'
    case 'kafkaLag': {
      const topic = labels?.topic ?? 'topic'
      const partition = labels?.partition
      return partition ? `${topic}:${partition}` : topic
    }
  }
}

export function buildHistoryChart(
  points: ReadonlyArray<MetricHistoryPoint>,
  widget: MetricWidget,
  range: MetricRange,
  now = new Date(),
): WidgetChartData {
  const config = RANGE_CONFIG[range]
  const seriesPoints =
    widget === 'dbLatency'
      ? buildHistoricalLatencyPoints(points, config.bucketMs)
      : buildHistoricalWidgetPoints(
          points,
          widget,
          config.bucketSeconds,
          config.bucketMs,
        )

  return pivotSeriesPoints(
    fillMissingBuckets(seriesPoints, range, now),
    widget,
    expectedBuckets(range, now),
  )
}

export function buildLiveWidgetSnapshot(
  current: ReadonlyArray<MetricSnapshot>,
  previous: ReadonlyArray<MetricSnapshot>,
  widget: MetricWidget,
  pollSeconds = 1,
  timestamp = new Date(),
): WidgetChartData {
  const currentByKey = mapSnapshots(current)
  const previousByKey = mapSnapshots(previous)
  const points =
    widget === 'dbLatency'
      ? buildLiveLatencyPoints(currentByKey, previousByKey, timestamp)
      : buildLiveWidgetPoints(
          currentByKey,
          previousByKey,
          widget,
          pollSeconds,
          timestamp,
        )

  return pivotSeriesPoints(points, widget, [
    alignTimestamp(timestamp.getTime(), RANGE_CONFIG['1m'].bucketMs),
  ])
}

export function liveSnapshotsToHistoryPoints(
  current: ReadonlyArray<MetricSnapshot>,
  previous: ReadonlyArray<MetricSnapshot>,
  timestamp = new Date(),
): MetricHistoryPoint[] {
  const previousByKey = mapSnapshots(previous)
  return current.map((snapshot) => {
    const previousSnapshot = previousByKey.get(snapshotKey(snapshot))
    return {
      timestamp: timestamp.toISOString(),
      name: snapshot.name,
      labels: snapshot.labels ?? null,
      value: snapshot.value,
      delta: Math.max(
        0,
        snapshot.value - (previousSnapshot?.value ?? snapshot.value),
      ),
    }
  })
}

function buildHistoricalWidgetPoints(
  points: ReadonlyArray<MetricHistoryPoint>,
  widget: MetricWidget,
  bucketSeconds: number,
  bucketMs: number,
): SeriesPoint[] {
  return points.flatMap((point) => {
    if (metricWidgetForName(point.name) !== widget) {
      return []
    }
    const value = COUNTER_WIDGETS.has(widget)
      ? safeRate(point.delta, bucketSeconds)
      : safeNumber(point.value)
    return [
      {
        timestamp: alignISO(point.timestamp, bucketMs),
        seriesKey: labelForMetric(widget, point.labels),
        value,
      },
    ]
  })
}

function buildHistoricalLatencyPoints(
  points: ReadonlyArray<MetricHistoryPoint>,
  bucketMs: number,
): SeriesPoint[] {
  const direct: SeriesPoint[] = []
  const totals = new Map<string, MetricHistoryPoint>()
  const counts = new Map<string, MetricHistoryPoint>()

  for (const point of points) {
    if (metricWidgetForName(point.name) !== 'dbLatency') {
      continue
    }
    const seriesKey = labelForMetric('dbLatency', point.labels)
    const key = `${alignISO(point.timestamp, bucketMs)}|${seriesKey}`
    if (point.name === 'storage_insert_duration_milliseconds') {
      direct.push({
        timestamp: alignISO(point.timestamp, bucketMs),
        seriesKey,
        value: safeNumber(point.value),
      })
    } else if (point.name === 'storage_insert_duration_milliseconds_total') {
      totals.set(key, point)
    } else if (point.name === 'storage_insert_duration_count') {
      counts.set(key, point)
    }
  }

  if (direct.length > 0) {
    return direct
  }

  const derived: SeriesPoint[] = []
  for (const [key, total] of totals) {
    const count = counts.get(key)
    if (!count) {
      continue
    }
    const [timestamp, seriesKey] = splitPointKey(key)
    const countDelta = Math.max(0, count.delta)
    const totalDelta = Math.max(0, total.delta)
    const fallbackCount = Math.max(0, count.value)
    const fallbackTotal = Math.max(0, total.value)
    const value =
      countDelta > 0
        ? totalDelta / countDelta
        : fallbackCount > 0
          ? fallbackTotal / fallbackCount
          : 0
    derived.push({ timestamp, seriesKey, value })
  }
  return derived
}

function buildLiveWidgetPoints(
  currentByKey: Map<string, MetricSnapshot>,
  previousByKey: Map<string, MetricSnapshot>,
  widget: MetricWidget,
  pollSeconds: number,
  timestamp: Date,
): SeriesPoint[] {
  const points: SeriesPoint[] = []
  for (const [key, current] of currentByKey) {
    if (metricWidgetForName(current.name) !== widget) {
      continue
    }
    const previous = previousByKey.get(key)
    const value = COUNTER_WIDGETS.has(widget)
      ? safeRate(current.value - (previous?.value ?? current.value), pollSeconds)
      : safeNumber(current.value)
    points.push({
      timestamp: alignTimestamp(timestamp.getTime(), RANGE_CONFIG['1m'].bucketMs),
      seriesKey: labelForMetric(widget, current.labels),
      value,
    })
  }
  return points
}

function buildLiveLatencyPoints(
  currentByKey: Map<string, MetricSnapshot>,
  previousByKey: Map<string, MetricSnapshot>,
  timestamp: Date,
): SeriesPoint[] {
  const direct: SeriesPoint[] = []
  for (const snapshot of currentByKey.values()) {
    if (snapshot.name !== 'storage_insert_duration_milliseconds') {
      continue
    }
    direct.push({
      timestamp: alignTimestamp(timestamp.getTime(), RANGE_CONFIG['1m'].bucketMs),
      seriesKey: labelForMetric('dbLatency', snapshot.labels),
      value: safeNumber(snapshot.value),
    })
  }

  if (direct.length > 0) {
    return direct
  }

  const totals = snapshotsByMetric(currentByKey, 'storage_insert_duration_milliseconds_total')
  const counts = snapshotsByMetric(currentByKey, 'storage_insert_duration_count')
  const previousTotals = snapshotsByMetric(
    previousByKey,
    'storage_insert_duration_milliseconds_total',
  )
  const previousCounts = snapshotsByMetric(previousByKey, 'storage_insert_duration_count')

  const points: SeriesPoint[] = []
  for (const [label, total] of totals) {
    const count = counts.get(label)
    if (!count) {
      continue
    }
    const totalDelta = Math.max(
      0,
      total.value - (previousTotals.get(label)?.value ?? total.value),
    )
    const countDelta = Math.max(
      0,
      count.value - (previousCounts.get(label)?.value ?? count.value),
    )
    points.push({
      timestamp: alignTimestamp(timestamp.getTime(), RANGE_CONFIG['1m'].bucketMs),
      seriesKey: label,
      value: countDelta > 0 ? totalDelta / countDelta : 0,
    })
  }
  return points
}

function fillMissingBuckets(
  points: ReadonlyArray<SeriesPoint>,
  range: MetricRange,
  now: Date,
): SeriesPoint[] {
  const buckets = expectedBuckets(range, now)
  const seriesKeys = new Set(points.map((point) => point.seriesKey))
  const existing = new Set(
    points.map((point) => `${point.timestamp}|${point.seriesKey}`),
  )
  const filled = [...points]

  for (const bucket of buckets) {
    for (const seriesKey of seriesKeys) {
      const key = `${bucket}|${seriesKey}`
      if (!existing.has(key)) {
        filled.push({ timestamp: bucket, seriesKey, value: 0 })
      }
    }
  }
  return filled
}

function expectedBuckets(range: MetricRange, now: Date): string[] {
  const config = RANGE_CONFIG[range]
  const end = alignTimestamp(now.getTime(), config.bucketMs)
  const start = alignTimestamp(now.getTime() - config.windowMs, config.bucketMs)
  const buckets: string[] = []
  for (let time = Date.parse(start); time <= Date.parse(end); time += config.bucketMs) {
    buckets.push(new Date(time).toISOString())
  }
  return buckets
}

function pivotSeriesPoints(
  points: ReadonlyArray<SeriesPoint>,
  widget: MetricWidget,
  orderedBuckets?: ReadonlyArray<string>,
): WidgetChartData {
  const bucketMap = new Map<string, ChartDatum>()
  const seriesKeys = Array.from(new Set(points.map((point) => point.seriesKey))).sort()

  for (const bucket of orderedBuckets ?? []) {
    bucketMap.set(bucket, emptyDatum(bucket, seriesKeys))
  }

  for (const point of points) {
    const datum = bucketMap.get(point.timestamp) ?? emptyDatum(point.timestamp, seriesKeys)
    datum[point.seriesKey] = roundMetric(point.value)
    bucketMap.set(point.timestamp, datum)
  }

  const data = Array.from(bucketMap.values())
    .map((datum) => {
      let total = 0
      for (const seriesKey of seriesKeys) {
        const value = numericValue(datum[seriesKey])
        datum[seriesKey] = value
        total += value
      }
      datum.total = roundMetric(total)
      return datum
    })
    .sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))

  return {
    widget,
    series: seriesKeys.map((key, index) => ({
      key,
      label: key,
      color: colorForSeries(widget, index),
    })),
    data,
  }
}

function emptyDatum(timestamp: string, seriesKeys: ReadonlyArray<string>): ChartDatum {
  const datum: ChartDatum = { timestamp, total: 0 }
  for (const key of seriesKeys) {
    datum[key] = 0
  }
  return datum
}

function mapSnapshots(snapshots: ReadonlyArray<MetricSnapshot>) {
  const mapped = new Map<string, MetricSnapshot>()
  for (const snapshot of snapshots) {
    mapped.set(snapshotKey(snapshot), snapshot)
  }
  return mapped
}

function snapshotsByMetric(
  snapshots: ReadonlyMap<string, MetricSnapshot>,
  metricName: string,
) {
  const mapped = new Map<string, MetricSnapshot>()
  for (const snapshot of snapshots.values()) {
    if (snapshot.name === metricName) {
      mapped.set(labelForMetric('dbLatency', snapshot.labels), snapshot)
    }
  }
  return mapped
}

function snapshotKey(snapshot: MetricSnapshot) {
  const labels = snapshot.labels ?? {}
  const encoded = Object.keys(labels)
    .sort()
    .map((key) => `${key}=${labels[key] ?? ''}`)
    .join(',')
  return `${snapshot.name}|${encoded}`
}

function colorForSeries(widget: MetricWidget, index: number) {
  const colors = WIDGET_COLORS[widget]
  return colors[index % colors.length] ?? '#3B82F6'
}

function splitPointKey(key: string): [string, string] {
  const separator = key.indexOf('|')
  if (separator < 0) {
    return [key, 'unknown']
  }
  return [key.slice(0, separator), key.slice(separator + 1)]
}

function alignISO(timestamp: string, bucketMs: number) {
  return alignTimestamp(Date.parse(timestamp), bucketMs)
}

function alignTimestamp(timeMs: number, bucketMs: number) {
  if (!Number.isFinite(timeMs)) {
    return new Date(0).toISOString()
  }
  return new Date(Math.floor(timeMs / bucketMs) * bucketMs).toISOString()
}

function safeRate(delta: number, seconds: number) {
  if (!Number.isFinite(delta) || !Number.isFinite(seconds) || seconds <= 0) {
    return 0
  }
  return Math.max(0, delta) / seconds
}

function safeNumber(value: number) {
  return Number.isFinite(value) ? Math.max(0, value) : 0
}

function numericValue(value: string | number | undefined) {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

function roundMetric(value: number) {
  return Math.round(value * 1000) / 1000
}
