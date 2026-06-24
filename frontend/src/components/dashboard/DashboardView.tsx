import { useEffect, useMemo, useRef, useState } from 'react'
import { MetricAreaChart } from '@/components/dashboard/MetricAreaChart'
import { MaterialIcon } from '@/components/shell/MaterialIcon'
import { Button } from '@/components/ui/button'
import { useLiveMetrics } from '@/hooks/useMetrics'
import { formatMetricValue, formatNumber } from '@/lib/format'
import {
  buildHistoryChart,
  liveSnapshotsToHistoryPoints,
  type MetricRange,
  type MetricWidget,
} from '@/lib/metrics-parser'
import type { MetricHistoryPoint, MetricSnapshot } from '@/types/api'

const LIVE_RANGE: MetricRange = '10m'
const LIVE_WINDOW_MS = 10 * 60_000

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
  const live = useLiveMetrics()

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
    const nextPoints = liveSnapshotsToHistoryPoints(
      metrics,
      previousLiveMetrics.current,
      now,
    )
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
        cards.map((card) => [
          card.widget,
          buildHistoryChart(livePoints, card.widget, LIVE_RANGE),
        ]),
      ) as Record<MetricWidget, DashboardChart>,
    [livePoints],
  )
  const liveStats = useMemo(
    () => deriveLiveStats(live.data?.metrics ?? [], livePoints),
    [live.data?.metrics, livePoints],
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
              className="min-h-[300px] rounded-lg border border-[var(--border)] bg-[var(--panel)] p-4 shadow-sm transition-all duration-200 ease-in-out hover:border-sky-500/40"
            >
              <div className="mb-4 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold tracking-normal text-[var(--text-primary)]">
                    {card.title}
                  </h2>
                  <p className="mt-1 text-xs text-[var(--text-secondary)]">
                    {formatMetricValue(
                      card.widget,
                      primaryCardMetricValue(card.widget, chart),
                    )}
                  </p>
                  {extraMetric ? (
                    <p className="mt-1 text-xs text-[var(--text-secondary)]">
                      {extraMetric}
                    </p>
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
                isLoading={live.isLoading}
                onRetry={() => void live.refetch()}
                scrollable
                {...(live.isError
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
  livePoints: ReadonlyArray<MetricHistoryPoint>,
): LiveDashboardStats {
  const dbConnectionsMaxOpen = metricValue(metrics, 'db_connections_max_open')
  const dbConnectionsInUse = metricValue(metrics, 'db_connections_in_use')
  const dbConnectionsOpen = metricValue(metrics, 'db_connections_open')
  const kafkaLag = metrics
    .filter((metric) => metric.name === 'kafka_consumer_lag')
    .reduce((sum, metric) => sum + metric.value, 0)
  const durablePersistRate = latestDeltaRate(
    livePoints,
    'flow_records_stored_total',
  )
  const drainSeconds =
    kafkaLag > 0 && durablePersistRate > 0
      ? kafkaLag / durablePersistRate
      : undefined

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

function latestDeltaRate(
  livePoints: ReadonlyArray<MetricHistoryPoint>,
  metricName: string,
) {
  const latestTimestamp = livePoints
    .filter((point) => point.name === metricName)
    .map((point) => Date.parse(point.timestamp))
    .filter(Number.isFinite)
    .sort((a, b) => b - a)[0]
  if (latestTimestamp === undefined) {
    return 0
  }
  return livePoints
    .filter(
      (point) =>
        point.name === metricName && Date.parse(point.timestamp) === latestTimestamp,
    )
    .reduce((sum, point) => sum + Math.max(0, point.delta), 0)
}
