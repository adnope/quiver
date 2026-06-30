import { useEffect, useMemo, useRef, useState } from 'react'
import { MetricAreaChart } from '@/components/dashboard/MetricAreaChart'
import { MaterialIcon } from '@/components/shell/MaterialIcon'
import { Button } from '@/components/ui/button'
import { useLiveMetrics, useMetricAggregateWindow } from '@/hooks/useMetrics'
import { formatMetricValue, formatNumber } from '@/lib/format'
import {
  buildHistoryChart,
  liveSnapshotsToHistoryPoints,
  rangeConfig,
  type MetricRange,
  type MetricWidget,
} from '@/lib/metrics-parser'
import type { MetricAggregatePoint, MetricHistoryPoint, MetricSnapshot } from '@/types/api'

const LIVE_RANGE: MetricRange = '10m'
const LIVE_WINDOW_MS = 10 * 60_000
const LIVE_BUCKET_SECONDS = rangeConfig(LIVE_RANGE).bucketSeconds

const DASHBOARD_HISTORY_METRICS = [
  'flow_records_normalized_total',
  'flow_records_stored_total',
  'flow_records_failed_total',
  'rate_limit_rejections_total',
  'storage_insert_duration',
  'kafka_consumer_lag',
]

const cards = [
  {
    widget: 'ingestion',
    title: 'Ingestion Rate',
    icon: 'timeline',
    accent: 'var(--metric-ingest)',
  },
  {
    widget: 'deadLetter',
    title: 'Dead-Letter Errors',
    icon: 'error',
    accent: 'var(--metric-error)',
  },
  {
    widget: 'dbLatency',
    title: 'DB Latency',
    icon: 'database',
    accent: 'var(--metric-db)',
  },
  {
    widget: 'kafkaLag',
    title: 'Kafka Queue Lag',
    icon: 'queue',
    accent: 'var(--metric-kafka)',
  },
] satisfies Array<{
  widget: MetricWidget
  title: string
  icon: string
  accent: string
}>

type DashboardChart = ReturnType<typeof buildHistoryChart>

export function DashboardView() {
  const [livePoints, setLivePoints] = useState<MetricHistoryPoint[]>([])
  const previousLiveMetrics = useRef<MetricSnapshot[]>([])
  const hydratedFromHistory = useRef(false)
  const [initialHistoryWindow] = useState(createInitialHistoryWindow)
  const historyParams = useMemo(
    () => ({
      from: initialHistoryWindow.from,
      to: initialHistoryWindow.to,
      step: `${LIVE_BUCKET_SECONDS}s`,
      metric: DASHBOARD_HISTORY_METRICS,
    }),
    [initialHistoryWindow]
  )
  const live = useLiveMetrics()
  const history = useMetricAggregateWindow(historyParams, true)

  useEffect(() => {
    if (hydratedFromHistory.current || !history.data) {
      return
    }

    hydratedFromHistory.current = true
    const historyCutoff = Date.parse(history.data.to)
    const historicalPoints = aggregatePointsToHistoryPoints(history.data.points)
    setLivePoints((current) => [
      ...historicalPoints,
      ...current.filter((point) => Date.parse(point.timestamp) > historyCutoff),
    ])
  }, [history.data])

  useEffect(() => {
    const metrics = live.data?.metrics
    if (!metrics) {
      return
    }
    if (previousLiveMetrics.current.length === 0) {
      previousLiveMetrics.current = metrics
      return
    }

    const now = new Date()
    const nextPoints = liveSnapshotsToHistoryPoints(metrics, previousLiveMetrics.current, now)
    previousLiveMetrics.current = metrics
    const cutoff = now.getTime() - LIVE_WINDOW_MS
    setLivePoints((current) => [
      ...current.filter((point) => Date.parse(point.timestamp) >= cutoff),
      ...nextPoints,
    ])
  }, [live.data])

  const charts = useMemo(
    () =>
      Object.fromEntries(
        cards.map((card) => [card.widget, buildHistoryChart(livePoints, card.widget, LIVE_RANGE)])
      ) as Record<MetricWidget, DashboardChart>,
    [livePoints]
  )
  const liveStats = useMemo(
    () => deriveLiveStats(live.data?.metrics ?? [], livePoints),
    [live.data?.metrics, livePoints]
  )

  return (
    <section className="space-y-4">
      <div className="grid grid-cols-1 gap-4">
        {cards.map((card) => {
          const chart = charts[card.widget]
          const extraMetric = extraCardMetric(card.widget, liveStats)
          return (
            <article
              key={card.title}
              className={`rounded-lg border border-[var(--border)] bg-[var(--panel)] p-4 shadow-sm transition-all duration-200 ease-in-out hover:border-sky-500/40 ${
                card.widget === 'ingestion' ? 'min-h-[416px]' : 'min-h-[300px]'
              }`}
            >
              <div className="mb-4 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold tracking-normal text-[var(--text-primary)]">
                    {card.title}
                  </h2>
                  <p className="mt-1 text-xs text-[var(--text-secondary)]">
                    {formatMetricValue(card.widget, primaryCardMetricValue(card.widget, chart))}
                  </p>
                  {extraMetric ? (
                    <p className="mt-1 text-xs text-[var(--text-secondary)]">{extraMetric}</p>
                  ) : null}
                </div>
                <div className="flex items-center gap-2">
                  {live.isError ? (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => void live.refetch()}
                    >
                      Retry
                    </Button>
                  ) : null}
                  <div
                    className="grid size-9 place-items-center rounded-md border"
                    style={{
                      borderColor: card.accent,
                      color: card.accent,
                    }}
                  >
                    <MaterialIcon name={card.icon} />
                  </div>
                </div>
              </div>
              <MetricAreaChart
                widget={card.widget}
                range={LIVE_RANGE}
                data={chart.data}
                series={chart.series}
                isLoading={(live.isLoading || history.isLoading) && livePoints.length === 0}
                onRetry={() => void live.refetch()}
                heightClass={card.widget === 'ingestion' ? 'h-72' : 'h-44'}
                {...(live.isError && livePoints.length === 0
                  ? { error: 'Metrics unavailable. Try again.' }
                  : {})}
              />
              <div className="mt-3 flex flex-wrap gap-2">
                {chart.series.map((series) => (
                  <div
                    key={series.key}
                    className="flex max-w-full items-center gap-1.5 text-xs text-[var(--text-secondary)]"
                  >
                    <span
                      className="size-2 shrink-0 rounded-full"
                      style={{ background: series.color }}
                    />
                    <span className="truncate">{series.label}</span>
                  </div>
                ))}
              </div>
            </article>
          )
        })}
      </div>
    </section>
  )
}

function createInitialHistoryWindow() {
  const to = new Date()
  const from = new Date(to.getTime() - LIVE_WINDOW_MS)
  return {
    from: from.toISOString(),
    to: to.toISOString(),
  }
}

function aggregatePointsToHistoryPoints(
  points: ReadonlyArray<MetricAggregatePoint>
): MetricHistoryPoint[] {
  return points.flatMap((point) => {
    if (point.metric_name === 'storage_insert_duration') {
      return aggregateLatencyHistoryPoints(point)
    }

    const bucketSeconds = Math.max(1, point.bucket_width_seconds)
    const delta = isDashboardCounter(point.metric_name)
      ? ((point.delta ?? 0) / bucketSeconds) * LIVE_BUCKET_SECONDS
      : (point.delta ?? 0)

    return [
      {
        timestamp: point.bucket_start,
        name: point.metric_name,
        labels: point.labels ?? null,
        value: metricAggregateValue(point),
        delta,
      },
    ]
  })
}

function aggregateLatencyHistoryPoints(point: MetricAggregatePoint): MetricHistoryPoint[] {
  const points: MetricHistoryPoint[] = []
  if (point.avg != null) {
    points.push(
      metricAggregateHistoryPoint(point, 'storage_insert_duration_milliseconds', point.avg)
    )
  }
  if (point.p90 != null) {
    points.push(metricAggregateHistoryPoint(point, 'storage_insert_duration_p90', point.p90))
  }
  if (point.p95 != null) {
    points.push(metricAggregateHistoryPoint(point, 'storage_insert_duration_p95', point.p95))
  }
  if (point.p99 != null) {
    points.push(metricAggregateHistoryPoint(point, 'storage_insert_duration_p99', point.p99))
  }
  return points
}

function metricAggregateHistoryPoint(
  source: MetricAggregatePoint,
  name: string,
  value: number
): MetricHistoryPoint {
  return {
    timestamp: source.bucket_start,
    name,
    labels: source.labels ?? null,
    value,
    delta: 0,
  }
}

function metricAggregateValue(point: MetricAggregatePoint) {
  return point.avg ?? point.last ?? point.max ?? point.first ?? 0
}

function isDashboardCounter(metricName: string) {
  return (
    metricName === 'flow_records_normalized_total' ||
    metricName === 'flow_records_stored_total' ||
    metricName === 'flow_records_failed_total' ||
    metricName === 'rate_limit_rejections_total'
  )
}

interface LiveDashboardStats {
  dbConnectionsInUse?: number
  dbConnectionsOpen?: number
  dbConnectionsMaxOpen?: number
  kafkaLag: number
  durablePersistRate: number
  drainSeconds?: number
}

function primaryCardMetricValue(widget: MetricWidget, chart: DashboardChart) {
  const latest = chart.data.at(-1)
  if (!latest) {
    return 0
  }

  if (widget !== 'ingestion') {
    return latest.total
  }

  return chart.series
    .filter((series) => series.label !== 'Persisted')
    .reduce((sum, series) => {
      const value = latest[series.key]
      return sum + (typeof value === 'number' && Number.isFinite(value) ? value : 0)
    }, 0)
}

function deriveLiveStats(
  metrics: ReadonlyArray<MetricSnapshot>,
  livePoints: ReadonlyArray<MetricHistoryPoint>
): LiveDashboardStats {
  const dbConnectionsMaxOpen = metricValue(metrics, 'db_connections_max_open')
  const dbConnectionsInUse = metricValue(metrics, 'db_connections_in_use')
  const dbConnectionsOpen = metricValue(metrics, 'db_connections_open')
  const kafkaLag = metrics
    .filter((metric) => metric.name === 'kafka_consumer_lag')
    .reduce((sum, metric) => sum + metric.value, 0)
  const durablePersistRate =
    latestDeltaRate(livePoints, 'flow_records_stored_total') / LIVE_BUCKET_SECONDS
  const drainSeconds =
    kafkaLag > 0 && durablePersistRate > 0 ? kafkaLag / durablePersistRate : undefined

  const stats: LiveDashboardStats = {
    kafkaLag,
    durablePersistRate,
  }
  if (dbConnectionsInUse !== undefined) {
    stats.dbConnectionsInUse = dbConnectionsInUse
  }
  if (dbConnectionsOpen !== undefined) {
    stats.dbConnectionsOpen = dbConnectionsOpen
  }
  if (dbConnectionsMaxOpen !== undefined) {
    stats.dbConnectionsMaxOpen = dbConnectionsMaxOpen
  }
  if (drainSeconds !== undefined) {
    stats.drainSeconds = drainSeconds
  }
  return stats
}

function extraCardMetric(widget: MetricWidget, stats: LiveDashboardStats) {
  switch (widget) {
    case 'dbLatency':
      if (stats.dbConnectionsInUse === undefined) {
        return undefined
      }
      return `${formatNumber(stats.dbConnectionsInUse)} DB connections in use${
        stats.dbConnectionsMaxOpen !== undefined
          ? ` / ${formatNumber(stats.dbConnectionsMaxOpen)} max`
          : ''
      }`
    case 'kafkaLag':
      if (stats.drainSeconds === undefined) {
        return `${formatNumber(stats.kafkaLag)} queued records`
      }
      return `${formatNumber(stats.kafkaLag)} queued · ${formatNumber(stats.drainSeconds)}s drain estimate`
    case 'ingestion':
      return `${formatMetricValue('ingestion', stats.durablePersistRate)} persisted`
    default:
      return undefined
  }
}

function metricValue(metrics: ReadonlyArray<MetricSnapshot>, name: string) {
  return metrics.find((metric) => metric.name === name)?.value
}

function latestDeltaRate(livePoints: ReadonlyArray<MetricHistoryPoint>, metricName: string) {
  const latestTimestamp = livePoints
    .filter((point) => point.name === metricName)
    .map((point) => Date.parse(point.timestamp))
    .filter(Number.isFinite)
    .sort((a, b) => b - a)[0]
  if (latestTimestamp === undefined) {
    return 0
  }
  return livePoints
    .filter((point) => point.name === metricName && Date.parse(point.timestamp) === latestTimestamp)
    .reduce((sum, point) => sum + Math.max(0, point.delta), 0)
}
