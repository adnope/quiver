import type {
  MetricAggregatePoint,
  MetricAggregatesParams,
  MetricHistoryPoint,
  MetricSnapshot,
} from '@/types/api'

export type MetricWidget = 'ingestion' | 'deadLetter' | 'dbLatency' | 'kafkaLag'

export type MetricRange = '1m' | '10m' | '15m' | '1h' | '12h' | '24h' | '1w' | '30d'
export type MetricChartRange = MetricRange | 'custom'

export interface AggregateTooltipStats {
  count?: number
  sum?: number
  avg?: number
  min?: number
  max?: number
  p90?: number
  p95?: number
  p99?: number
  first?: number
  last?: number
  delta?: number
}

export type ChartDatum = {
  timestamp: string
  total: number
  aggregateStats?: Record<string, AggregateTooltipStats>
} & Record<string, number | string | Record<string, AggregateTooltipStats> | undefined>

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

export interface MetricWindowConfig {
  from: string | Date
  to: string | Date
  bucketSeconds: number
}

export interface MetricWindowSummary {
  totalIngested: number
  totalPersisted: number
  persistSuccessRate: number
  totalFailed: number
  totalRateLimited: number
  averageIngestRate: number
  averagePersistRate: number
  maxKafkaLag: number
  avgKafkaLag: number
  avgStorageLatencyMs: number
  p95StorageLatencyMs: number
  p99StorageLatencyMs: number
  sampleCount: number
}

export interface RangeConfig {
  windowMs: number
  bucketMs: number
  bucketSeconds: number
}

interface SeriesPoint {
  timestamp: string
  seriesKey: string
  value: number
  stats?: AggregateTooltipStats
}

const RANGE_CONFIG: Record<MetricRange, RangeConfig> = {
  '1m': { windowMs: 60_000, bucketMs: 5_000, bucketSeconds: 5 },
  '10m': { windowMs: 10 * 60_000, bucketMs: 1_000, bucketSeconds: 1 },
  '15m': { windowMs: 15 * 60_000, bucketMs: 1_000, bucketSeconds: 1 },
  '1h': { windowMs: 60 * 60_000, bucketMs: 20_000, bucketSeconds: 20 },
  '12h': {
    windowMs: 12 * 60 * 60_000,
    bucketMs: 5 * 60_000,
    bucketSeconds: 300,
  },
  '24h': {
    windowMs: 24 * 60 * 60_000,
    bucketMs: 10 * 60_000,
    bucketSeconds: 600,
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

const SOURCE_TYPE_LABELS: Record<string, string> = {
  SOURCE_TYPE_NETFLOW_V5: 'NetFlow v5',
  source_type_netflow_v5: 'NetFlow v5',
  netflow_v5: 'NetFlow v5',

  SOURCE_TYPE_REST_JSON: 'REST',
  source_type_rest_json: 'REST',
  rest_json: 'REST',

  SOURCE_TYPE_ZEEK_CONN_JSON: 'Zeek',
  source_type_zeek_conn_json: 'Zeek',
  zeek_conn_json: 'Zeek',
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

export function metricAggregateParamsForRange(
  range: MetricRange,
  now = new Date(),
): MetricAggregatesParams {
  const config = RANGE_CONFIG[range]
  const to = now
  const from = new Date(to.getTime() - config.windowMs)
  return {
    from: from.toISOString(),
    to: to.toISOString(),
    step: `${config.bucketSeconds}s`,
    metric: [
      'flow_records_normalized_total',
      'flow_records_stored_total',
      'flow_records_failed_total',
      'rate_limit_rejections_total',
      'storage_insert_duration',
      'kafka_consumer_lag',
    ],
  }
}

export function metricWidgetForName(name: string): MetricWidget | undefined {
  switch (name) {
    case 'flow_records_normalized_total':
    case 'flow_records_stored_total':
      return 'ingestion'
    case 'flow_records_failed_total':
    case 'rate_limit_rejections_total':
      return 'deadLetter'
    case 'storage_insert_duration':
    case 'storage_insert_duration_milliseconds':
    case 'storage_insert_duration_milliseconds_total':
    case 'storage_insert_duration_count':
    case 'storage_insert_duration_p90':
    case 'storage_insert_duration_p95':
    case 'storage_insert_duration_p99':
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
  name?: string,
) {
  switch (widget) {
    case 'ingestion':
      if (name === 'flow_records_stored_total') {
        return 'Persisted'
      }
      return labels?.source_type
        ? sourceTypeLabel(labels.source_type)
        : 'unknown_source'
    case 'deadLetter':
      if (name === 'rate_limit_rejections_total') {
        return 'Rate Limited'
      }
      return labels?.reason ?? 'unknown_reason'
    case 'dbLatency':
      if (name === 'storage_insert_duration_p90') {
        return 'p90'
      }
      if (name === 'storage_insert_duration_p95') {
        return 'p95'
      }
      if (name === 'storage_insert_duration_p99') {
        return 'p99'
      }
      if (
        name === 'storage_insert_duration' ||
        name === 'storage_insert_duration_milliseconds' ||
        name === 'storage_insert_duration_milliseconds_total' ||
        name === 'storage_insert_duration_count'
      ) {
        return 'Average'
      }
      return labels?.status ?? 'storage'
    case 'kafkaLag': {
      const topic = labels?.topic ?? 'topic'
      const partition = labels?.partition
      return partition ? `${topic}:${partition}` : topic
    }
  }
}

function sourceTypeLabel(value: string) {
  const key = value.trim()
  return SOURCE_TYPE_LABELS[key] ?? SOURCE_TYPE_LABELS[key.toLowerCase()] ?? key
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

export function buildAggregateChart(
  points: ReadonlyArray<MetricAggregatePoint>,
  widget: MetricWidget,
  range: MetricRange,
  now = new Date(),
): WidgetChartData {
  const config = RANGE_CONFIG[range]
  return buildAggregateChartForWindow(points, widget, {
    from: new Date(now.getTime() - config.windowMs),
    to: now,
    bucketSeconds: config.bucketSeconds,
  })
}

export function buildAggregateChartForWindow(
  points: ReadonlyArray<MetricAggregatePoint>,
  widget: MetricWidget,
  window: MetricWindowConfig,
): WidgetChartData {
  const normalized = normalizeMetricWindow(window)
  const bucketMs = normalized.bucketSeconds * 1000
  const seriesPoints = buildAggregateWidgetPoints(points, widget, bucketMs)
  const buckets = expectedWindowBuckets(
    normalized.from,
    normalized.to,
    bucketMs,
  )

  return pivotSeriesPoints(
    fillMissingWindowBuckets(seriesPoints, buckets),
    widget,
    buckets,
  )
}

export function summarizeMetricAggregates(
  points: ReadonlyArray<MetricAggregatePoint>,
  from: string | Date,
  to: string | Date,
): MetricWindowSummary {
  const windowSeconds = Math.max(
    1,
    (dateValue(to).getTime() - dateValue(from).getTime()) / 1000,
  )
  const ingested = sumMetricDelta(points, 'flow_records_normalized_total')
  const persisted = sumMetricDelta(points, 'flow_records_stored_total')
  const failed = sumMetricDelta(points, 'flow_records_failed_total')
  const rateLimited = sumMetricDelta(points, 'rate_limit_rejections_total')
  const lagPoints = points.filter((point) => point.metric_name === 'kafka_consumer_lag')
  const latencyPoints = points.filter(
    (point) => point.metric_name === 'storage_insert_duration',
  )
  const latencyStats = weightedLatencyStats(latencyPoints)

  return {
    totalIngested: roundMetric(ingested),
    totalPersisted: roundMetric(persisted),
    persistSuccessRate: ingested > 0 ? roundMetric((persisted / ingested) * 100) : 0,
    totalFailed: roundMetric(failed),
    totalRateLimited: roundMetric(rateLimited),
    averageIngestRate: roundMetric(ingested / windowSeconds),
    averagePersistRate: roundMetric(persisted / windowSeconds),
    maxKafkaLag: roundMetric(maxMetricValue(lagPoints)),
    avgKafkaLag: roundMetric(weightedAverage(lagPoints)),
    avgStorageLatencyMs: roundMetric(latencyStats.avg),
    p95StorageLatencyMs: roundMetric(latencyStats.p95),
    p99StorageLatencyMs: roundMetric(latencyStats.p99),
    sampleCount: points.reduce((sum, point) => sum + Math.max(0, point.count), 0),
  }
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

function buildAggregateWidgetPoints(
  points: ReadonlyArray<MetricAggregatePoint>,
  widget: MetricWidget,
  bucketMs: number,
): SeriesPoint[] {
  return points.flatMap((point) => {
    if (metricWidgetForName(point.metric_name) !== widget) {
      return []
    }
    const timestamp = alignISO(point.bucket_start, bucketMs)
    if (widget === 'dbLatency' && point.metric_name === 'storage_insert_duration') {
      return aggregateLatencyPoints(point, timestamp)
    }
    const value = COUNTER_WIDGETS.has(widget)
      ? safeRate(point.delta ?? 0, point.bucket_width_seconds)
      : safeNumber(point.avg ?? point.last ?? point.max ?? 0)
    return [
      {
        timestamp,
        seriesKey: labelForMetric(widget, point.labels, point.metric_name),
        value,
        stats: aggregateTooltipStats(point),
      },
    ]
  })
}

function aggregateLatencyPoints(
  point: MetricAggregatePoint,
  timestamp: string,
): SeriesPoint[] {
  const labels = point.labels ?? null
  const stats = aggregateTooltipStats(point)
  const points: SeriesPoint[] = []
  if (point.avg != null) {
    points.push({
      timestamp,
      seriesKey: labelForMetric('dbLatency', labels, 'storage_insert_duration'),
      value: safeNumber(point.avg),
      stats,
    })
  }
  if (point.p90 != null) {
    points.push({
      timestamp,
      seriesKey: labelForMetric('dbLatency', labels, 'storage_insert_duration_p90'),
      value: safeNumber(point.p90),
      stats,
    })
  }
  if (point.p95 != null) {
    points.push({
      timestamp,
      seriesKey: labelForMetric('dbLatency', labels, 'storage_insert_duration_p95'),
      value: safeNumber(point.p95),
      stats,
    })
  }
  if (point.p99 != null) {
    points.push({
      timestamp,
      seriesKey: labelForMetric('dbLatency', labels, 'storage_insert_duration_p99'),
      value: safeNumber(point.p99),
      stats,
    })
  }
  return points
}

function aggregateTooltipStats(point: MetricAggregatePoint): AggregateTooltipStats {
  const stats: AggregateTooltipStats = {}
  if (point.count > 0) {
    stats.count = point.count
  }
  if (point.sum != null) {
    stats.sum = point.sum
  }
  if (point.avg != null) {
    stats.avg = point.avg
  }
  if (point.min != null) {
    stats.min = point.min
  }
  if (point.max != null) {
    stats.max = point.max
  }
  if (point.p90 != null) {
    stats.p90 = point.p90
  }
  if (point.p95 != null) {
    stats.p95 = point.p95
  }
  if (point.p99 != null) {
    stats.p99 = point.p99
  }
  if (point.first != null) {
    stats.first = point.first
  }
  if (point.last != null) {
    stats.last = point.last
  }
  if (point.delta != null) {
    stats.delta = point.delta
  }
  return stats
}


function normalizeMetricWindow(window: MetricWindowConfig) {
  const from = dateValue(window.from)
  const to = dateValue(window.to)
  const bucketSeconds = Math.max(1, Math.floor(window.bucketSeconds))
  return { from, to, bucketSeconds }
}

function dateValue(value: string | Date) {
  const date = value instanceof Date ? value : new Date(value)
  return Number.isFinite(date.getTime()) ? date : new Date(0)
}

function sumMetricDelta(
  points: ReadonlyArray<MetricAggregatePoint>,
  metricName: string,
) {
  return points
    .filter((point) => point.metric_name === metricName)
    .reduce((sum, point) => sum + Math.max(0, point.delta ?? 0), 0)
}

function maxMetricValue(points: ReadonlyArray<MetricAggregatePoint>) {
  return points.reduce(
    (max, point) => Math.max(max, safeNumber(point.max ?? point.last ?? point.avg ?? 0)),
    0,
  )
}

function weightedAverage(points: ReadonlyArray<MetricAggregatePoint>) {
  let weightedSum = 0
  let totalWeight = 0
  for (const point of points) {
    const weight = Math.max(1, point.count)
    weightedSum += safeNumber(point.avg ?? point.last ?? point.max ?? 0) * weight
    totalWeight += weight
  }
  return totalWeight > 0 ? weightedSum / totalWeight : 0
}

function weightedLatencyStats(points: ReadonlyArray<MetricAggregatePoint>) {
  let weightedAvg = 0
  let totalWeight = 0
  let p95 = 0
  let p99 = 0
  let p95Weight = 0
  let p99Weight = 0

  for (const point of points) {
    const weight = Math.max(1, point.count)
    if (point.avg != null) {
      weightedAvg += point.avg * weight
      totalWeight += weight
    }
    if (point.p95 != null) {
      p95 += point.p95 * weight
      p95Weight += weight
    }
    if (point.p99 != null) {
      p99 += point.p99 * weight
      p99Weight += weight
    }
  }

  return {
    avg: totalWeight > 0 ? weightedAvg / totalWeight : 0,
    p95: p95Weight > 0 ? p95 / p95Weight : 0,
    p99: p99Weight > 0 ? p99 / p99Weight : 0,
  }
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
        seriesKey: labelForMetric(widget, point.labels, point.name),
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
    const timestamp = alignISO(point.timestamp, bucketMs)
    const key = `${timestamp}|${labelsKey(point.labels)}`
    if (
      point.name === 'storage_insert_duration_milliseconds' ||
      point.name === 'storage_insert_duration_p95' ||
      point.name === 'storage_insert_duration_p99'
    ) {
      direct.push({
        timestamp,
        seriesKey: labelForMetric('dbLatency', point.labels, point.name),
        value: safeNumber(point.value),
      })
    } else if (point.name === 'storage_insert_duration_milliseconds_total') {
      totals.set(key, point)
    } else if (point.name === 'storage_insert_duration_count') {
      counts.set(key, point)
    }
  }

  const derived: SeriesPoint[] = []
  for (const [key, total] of totals) {
    const count = counts.get(key)
    if (!count) {
      continue
    }
    const [timestamp] = splitPointKey(key)
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
    derived.push({
      timestamp,
      seriesKey: labelForMetric(
        'dbLatency',
        total.labels,
        'storage_insert_duration_milliseconds',
      ),
      value,
    })
  }
  return [...derived, ...direct]
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
      seriesKey: labelForMetric(widget, current.labels, current.name),
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
  const pointTimestamp = alignTimestamp(timestamp.getTime(), RANGE_CONFIG['1m'].bucketMs)
  for (const snapshot of currentByKey.values()) {
    if (
      snapshot.name !== 'storage_insert_duration_milliseconds' &&
      snapshot.name !== 'storage_insert_duration_p95' &&
      snapshot.name !== 'storage_insert_duration_p99'
    ) {
      continue
    }
    direct.push({
      timestamp: pointTimestamp,
      seriesKey: labelForMetric('dbLatency', snapshot.labels, snapshot.name),
      value: safeNumber(snapshot.value),
    })
  }

  const totals = snapshotsByMetric(currentByKey, 'storage_insert_duration_milliseconds_total')
  const counts = snapshotsByMetric(currentByKey, 'storage_insert_duration_count')
  const previousTotals = snapshotsByMetric(
    previousByKey,
    'storage_insert_duration_milliseconds_total',
  )
  const previousCounts = snapshotsByMetric(previousByKey, 'storage_insert_duration_count')

  const points: SeriesPoint[] = []
  for (const [labelKey, total] of totals) {
    const count = counts.get(labelKey)
    if (!count) {
      continue
    }
    const totalDelta = Math.max(
      0,
      total.value - (previousTotals.get(labelKey)?.value ?? total.value),
    )
    const countDelta = Math.max(
      0,
      count.value - (previousCounts.get(labelKey)?.value ?? count.value),
    )
    points.push({
      timestamp: pointTimestamp,
      seriesKey: labelForMetric(
        'dbLatency',
        total.labels,
        'storage_insert_duration_milliseconds',
      ),
      value: countDelta > 0 ? totalDelta / countDelta : 0,
    })
  }
  return [...points, ...direct]
}

function fillMissingBuckets(
  points: ReadonlyArray<SeriesPoint>,
  range: MetricRange,
  now: Date,
): SeriesPoint[] {
  const buckets = expectedBuckets(range, now)
  return fillMissingWindowBuckets(points, buckets)
}

function fillMissingWindowBuckets(
  points: ReadonlyArray<SeriesPoint>,
  buckets: ReadonlyArray<string>,
): SeriesPoint[] {
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
  return expectedWindowBuckets(
    new Date(now.getTime() - config.windowMs),
    now,
    config.bucketMs,
  )
}

function expectedWindowBuckets(
  from: Date,
  to: Date,
  bucketMs: number,
): string[] {
  const end = alignTimestamp(to.getTime(), bucketMs)
  const start = alignTimestamp(from.getTime(), bucketMs)
  const buckets: string[] = []
  for (let time = Date.parse(start); time <= Date.parse(end); time += bucketMs) {
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
  const seriesKeys = Array.from(new Set(points.map((point) => point.seriesKey))).sort(
    (left, right) => compareSeriesKeys(widget, left, right),
  )

  for (const bucket of orderedBuckets ?? []) {
    bucketMap.set(bucket, emptyDatum(bucket, seriesKeys))
  }

  for (const point of points) {
    const datum = bucketMap.get(point.timestamp) ?? emptyDatum(point.timestamp, seriesKeys)
    datum[point.seriesKey] = roundMetric(point.value)
    if (point.stats) {
      datum.aggregateStats = {
        ...(datum.aggregateStats ?? {}),
        [point.seriesKey]: point.stats,
      }
    }
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


function compareSeriesKeys(widget: MetricWidget, left: string, right: string) {
  const leftRank = seriesRank(widget, left)
  const rightRank = seriesRank(widget, right)
  if (leftRank !== rightRank) {
    return leftRank - rightRank
  }
  return left.localeCompare(right)
}

function seriesRank(widget: MetricWidget, key: string) {
  if (widget !== 'ingestion') {
    return 100
  }
  const order: Record<string, number> = {
    'NetFlow v5': 0,
    REST: 1,
    Zeek: 2,
    Persisted: 3,
  }
  return order[key] ?? 50
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
      mapped.set(labelsKey(snapshot.labels), snapshot)
    }
  }
  return mapped
}

function labelsKey(labels: Record<string, string> | null | undefined) {
  const safeLabels = labels ?? {}
  return Object.keys(safeLabels)
    .sort()
    .map((key) => `${key}=${safeLabels[key] ?? ''}`)
    .join(',')
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

function numericValue(value: ChartDatum[string] | undefined) {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

function roundMetric(value: number) {
  return Math.round(value * 1000) / 1000
}