import { MaterialIcon } from '@/components/shell/MaterialIcon'
import { Button } from '@/components/ui/button'
import { MetricAreaChart } from '@/components/dashboard/MetricAreaChart'
import { formatMetricValue } from '@/lib/format'
import {
  buildHistoryChart,
  liveSnapshotsToHistoryPoints,
  type MetricRange,
  type MetricWidget,
} from '@/lib/metrics-parser'
import { useLiveMetrics, useMetricsHistory } from '@/hooks/useMetrics'
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

export function DashboardView() {
  const [range, setRange] = useState<MetricRange>('1h')
  const [livePoints, setLivePoints] = useState<MetricHistoryPoint[]>([])
  const previousLiveMetrics = useRef<MetricSnapshot[]>([])
  const live = useLiveMetrics()
  const history = useMetricsHistory(range, range !== '1m')

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
    () => {
      const chartPoints = range === '1m'
        ? livePoints
        : (history.data?.points ?? [])
      return Object.fromEntries(
        cards.map((card) => [
          card.widget,
          buildHistoryChart(chartPoints, card.widget, range),
        ]),
      ) as Record<MetricWidget, ReturnType<typeof buildHistoryChart>>
    },
    [history.data?.points, livePoints, range],
  )
  const chartIsLoading = range === '1m'
    ? live.isLoading || livePoints.length === 0
    : history.isLoading
  const chartIsError = range === '1m' ? live.isError : history.isError
  const refetchCharts = range === '1m' ? live.refetch : history.refetch

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div className="text-xs text-[var(--text-secondary)]">
          {live.isError
            ? 'Live metrics unavailable'
            : live.isLoading
              ? 'Loading live metrics'
              : live.data
                ? 'Live metrics ready'
                : 'Waiting for live metrics'}
        </div>
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
                    {formatMetricValue(card.widget, chart.data.at(-1)?.total ?? 0)}
                  </p>
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
                    style={{ borderColor: `${card.accent}`, color: `${card.accent}` }}
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
