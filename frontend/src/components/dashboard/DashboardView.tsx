import { MetricAreaChart } from '@/components/dashboard/MetricAreaChart'
import { MaterialIcon } from '@/components/shell/MaterialIcon'
import { Button } from '@/components/ui/button'
import { useLiveMetrics, useMetricAggregates } from '@/hooks/useMetrics'
import { formatMetricValue, formatNumber } from '@/lib/format'
import {
  buildAggregateChart,
  buildHistoryChart,
  liveSnapshotsToHistoryPoints,
  type MetricRange,
  type MetricWidget,
} from '@/lib/metrics-parser'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { MetricHistoryPoint, MetricSnapshot } from '@/types/api'

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

const ranges = [
  { value: '1m', label: '1 minute' },
  { value: '1h', label: '1 hour' },
  { value: '12h', label: '12 hours' },
  { value: '24h', label: '24 hours' },
  { value: '1w', label: '1 week' },
  { value: '30d', label: '30 days' },
] satisfies Array<{ value: MetricRange; label: string }>

type DashboardChart = ReturnType<typeof buildHistoryChart>

export function DashboardView() {
  const [range, setRange] = useState<MetricRange>('1h')
  const [livePoints, setLivePoints] = useState<MetricHistoryPoint[]>([])
  const previousLiveMetrics = useRef<MetricSnapshot[]>([])
  const live = useLiveMetrics()
  const aggregates = useMetricAggregates(range, range !== '1m')

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
    const cutoff = now.getTime() - 60_000
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
          range === '1m'
            ? buildHistoryChart(livePoints, card.widget, range)
            : buildAggregateChart(
                aggregates.data?.points ?? [],
                card.widget,
                range,
              ),
        ]),
      ) as Record<MetricWidget, DashboardChart>,
    [aggregates.data?.points, livePoints, range],
  )
  const liveStats = useMemo(
    () => deriveLiveStats(live.data?.metrics ?? [], livePoints),
    [live.data?.metrics, livePoints],
  )
  const chartIsLoading = range === '1m' ? live.isLoading : aggregates.isLoading
  const chartIsError = range === '1m' ? live.isError : aggregates.isError
  const refetchCharts = range === '1m' ? live.refetch : aggregates.refetch

  const liveStatus = live.isError
    ? 'Live metrics unavailable'
    : live.isLoading
      ? 'Loading live metrics'
      : !live.data
        ? 'Waiting for live metrics'
        : null

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        {liveStatus ? (
          <div className="text-xs text-[var(--text-secondary)]">
            {liveStatus}
          </div>
        ) : (
          <div />
        )}
        <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
          <span>Range</span>
          <select
            className="h-9 cursor-pointer rounded-md border border-[var(--border)] bg-[var(--panel)] px-3 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
            value={range}
            onChange={(event) => setRange(event.target.value as MetricRange)}
          >
            {ranges.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
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
                  {chartIsError ? (
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => void refetchCharts()}
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
                range={range}
                data={chart.data}
                series={chart.series}
                isLoading={chartIsLoading}
                onRetry={() => void refetchCharts()}
                {...(chartIsError
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
    .filter((series) => series.label !== 'Durable Persisted')
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

function metricValue(
  metrics: ReadonlyArray<MetricSnapshot>,
  name: string,
): number | undefined {
  return metrics.find((metric) => metric.name === name)?.value
}

function latestDeltaRate(
  points: ReadonlyArray<MetricHistoryPoint>,
  name: string,
) {
  const latestTimestamp = points
    .filter((point) => point.name === name)
    .map((point) => Date.parse(point.timestamp))
    .filter(Number.isFinite)
    .sort((a, b) => b - a)[0]
  if (latestTimestamp === undefined) {
    return 0
  }
  return points
    .filter(
      (point) =>
        point.name === name && Date.parse(point.timestamp) === latestTimestamp,
    )
    .reduce((sum, point) => sum + Math.max(0, point.delta), 0)
}

function extraCardMetric(widget: MetricWidget, stats: LiveDashboardStats) {
  if (widget === 'dbLatency' && stats.dbConnectionsOpen !== undefined) {
    const maxOpen =
      stats.dbConnectionsMaxOpen !== undefined && stats.dbConnectionsMaxOpen > 0
        ? stats.dbConnectionsMaxOpen
        : stats.dbConnectionsOpen

    return `Connections: ${formatNumber(stats.dbConnectionsOpen)}/${formatNumber(maxOpen)}`
  }
  if (
    widget === 'kafkaLag' &&
    stats.kafkaLag > 0 &&
    stats.drainSeconds !== undefined
  ) {
    return `Estimated Drain Time: ${formatDrainSeconds(stats.drainSeconds)}`
  }
  return undefined
}

function formatDrainSeconds(seconds: number) {
  if (!Number.isFinite(seconds)) {
    return '-'
  }
  if (seconds < 60) {
    return `${formatNumber(seconds)}s`
  }
  const minutes = seconds / 60
  if (minutes < 60) {
    return `${formatNumber(minutes)}m`
  }
  return `${formatNumber(minutes / 60)}h`
}
