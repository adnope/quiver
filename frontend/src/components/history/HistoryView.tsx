import { useEffect, useMemo, useState } from 'react'
import { MetricAreaChart } from '@/components/dashboard/MetricAreaChart'
import { MaterialIcon } from '@/components/shell/MaterialIcon'
import { Button } from '@/components/ui/button'
import { useMetricAggregateWindow } from '@/hooks/useMetrics'
import { formatMetricValue, formatNumber, formatTimestamp } from '@/lib/format'
import {
  buildAggregateChartForWindow,
  summarizeMetricAggregates,
  type MetricWidget,
} from '@/lib/metrics-parser'

const METRIC_NAMES = [
  'flow_records_normalized_total',
  'flow_records_stored_total',
  'flow_records_failed_total',
  'rate_limit_rejections_total',
  'storage_insert_duration',
  'kafka_consumer_lag',
]

const PRESETS = [
  { label: '15m', durationMs: 15 * 60_000 },
  { label: '1h', durationMs: 60 * 60_000 },
  { label: '6h', durationMs: 6 * 60 * 60_000 },
  { label: '12h', durationMs: 12 * 60 * 60_000 },
  { label: '24h', durationMs: 24 * 60 * 60_000 },
  { label: '7d', durationMs: 7 * 24 * 60 * 60_000 },
  { label: '30d', durationMs: 30 * 24 * 60 * 60_000 },
]

const CHARTS = [
  {
    widget: 'ingestion',
    title: 'Ingest vs Persist Rate',
    description: 'Average flow rate per sampled bucket.',
    icon: 'timeline',
    accent: 'var(--metric-ingest)',
  },
  {
    widget: 'dbLatency',
    title: 'Storage Latency',
    description: 'Average and percentile insert latency.',
    icon: 'database',
    accent: 'var(--metric-db)',
  },
  {
    widget: 'kafkaLag',
    title: 'Kafka Queue Lag',
    description: 'Lag sampled from consumer state.',
    icon: 'queue',
    accent: 'var(--metric-kafka)',
  },
  {
    widget: 'deadLetter',
    title: 'Errors and Rejections',
    description: 'DLQ failures and rate-limit rejections.',
    icon: 'error',
    accent: 'var(--metric-error)',
  },
] satisfies Array<{
  widget: MetricWidget
  title: string
  description: string
  icon: string
  accent: string
}>

interface HistoryWindow {
  from: string
  to: string
  fromInput: string
  toInput: string
  presetLabel?: string
}

export function HistoryView() {
  const [windowState, setWindowState] = useState(createInitialWindow)
  const [draftFrom, setDraftFrom] = useState(windowState.fromInput)
  const [draftTo, setDraftTo] = useState(windowState.toInput)
  const timeError = useMemo(() => getTimeError(draftFrom, draftTo), [draftFrom, draftTo])
  const bucketSeconds = useMemo(
    () => resolveBucketSeconds(windowState.from, windowState.to),
    [windowState.from, windowState.to]
  )
  const query = useMetricAggregateWindow({
    from: windowState.from,
    to: windowState.to,
    step: `${bucketSeconds}s`,
    metric: METRIC_NAMES,
  })

  useEffect(() => {
    writeHistoryQuery(windowState)
  }, [windowState])

  const points = useMemo(() => query.data?.points ?? [], [query.data?.points])
  const summary = useMemo(
    () => summarizeMetricAggregates(points, windowState.from, windowState.to),
    [points, windowState.from, windowState.to]
  )
  const charts = useMemo(
    () =>
      Object.fromEntries(
        CHARTS.map((chart) => [
          chart.widget,
          buildAggregateChartForWindow(points, chart.widget, {
            from: windowState.from,
            to: windowState.to,
            bucketSeconds,
          }),
        ])
      ) as Record<MetricWidget, ReturnType<typeof buildAggregateChartForWindow>>,
    [bucketSeconds, points, windowState.from, windowState.to]
  )

  function applyWindow() {
    const parsed = parseWindowInputs(draftFrom, draftTo)
    if (!parsed) {
      return
    }
    setWindowState(parsed)
  }

  function applyPreset(preset: (typeof PRESETS)[number]) {
    const next = createWindow(preset.durationMs, preset.label)
    setDraftFrom(next.fromInput)
    setDraftTo(next.toInput)
    setWindowState(next)
  }

  function refreshWindow() {
    const durationMs = Math.max(60_000, Date.parse(windowState.to) - Date.parse(windowState.from))
    const next = createWindow(durationMs, windowState.presetLabel)
    setDraftFrom(next.fromInput)
    setDraftTo(next.toInput)
    setWindowState(next)
  }

  const isEmpty = !query.isLoading && !query.isError && points.length === 0

  return (
    <section className="space-y-4">
      <div className="rounded-lg border border-[var(--border)] bg-[var(--panel)] shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] px-4 py-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-sm font-semibold text-[var(--text-primary)]">
              <MaterialIcon name="manage_history" className="text-[19px] text-sky-400" />
              Metrics History Explorer
            </div>
            <p className="mt-1 text-xs text-[var(--text-secondary)]">
              Select any window, inspect aggregate charts, then hover sampled points for bucket
              details.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md border border-[var(--border)] bg-[var(--panel-alt)] px-2.5 py-1.5 font-mono text-xs text-[var(--text-secondary)]">
              auto step {formatDuration(bucketSeconds)}
            </span>
            <Button type="button" size="sm" onClick={refreshWindow}>
              <MaterialIcon name="refresh" className="text-[18px]" />
              Refresh
            </Button>
          </div>
        </div>

        <div className="space-y-3 border-b border-[var(--border)] bg-[var(--panel-alt)] p-3">
          <div className="flex flex-wrap items-center gap-2">
            {PRESETS.map((preset) => (
              <Button
                key={preset.label}
                type="button"
                size="sm"
                variant="secondary"
                onClick={() => applyPreset(preset)}
              >
                {preset.label}
              </Button>
            ))}
          </div>

          <div className="grid gap-3 lg:grid-cols-[1fr_1fr_auto]">
            <label className="grid gap-1.5 text-xs text-[var(--text-secondary)]">
              From
              <input
                type="datetime-local"
                step="1"
                className="h-9 min-w-0 rounded-md border border-[var(--border)] bg-[var(--input)] px-2 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
                value={draftFrom}
                onChange={(event) => setDraftFrom(event.target.value)}
              />
            </label>
            <label className="grid gap-1.5 text-xs text-[var(--text-secondary)]">
              To
              <input
                type="datetime-local"
                step="1"
                className="h-9 min-w-0 rounded-md border border-[var(--border)] bg-[var(--input)] px-2 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
                value={draftTo}
                onChange={(event) => setDraftTo(event.target.value)}
              />
            </label>
            <div className="flex items-end gap-2">
              <Button
                type="button"
                variant="primary"
                disabled={Boolean(timeError)}
                onClick={applyWindow}
              >
                Apply
              </Button>
            </div>
          </div>
          {timeError ? <p className="text-xs font-medium text-red-400">{timeError}</p> : null}
        </div>

        <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-4">
          <SummaryCard
            icon="input"
            label="Total ingested"
            value={formatNumber(summary.totalIngested)}
            detail={`${formatMetricValue('ingestion', summary.averageIngestRate)} avg`}
            accent="var(--metric-ingest)"
          />
          <SummaryCard
            icon="verified"
            label="Persisted"
            value={formatNumber(summary.totalPersisted)}
            detail={`${formatNumber(summary.persistSuccessRate)}% success`}
            accent="var(--metric-db)"
          />
          <SummaryCard
            icon="speed"
            label="Storage latency"
            value={formatMetricValue('dbLatency', summary.p95StorageLatencyMs)}
            detail={`p99 ${formatMetricValue('dbLatency', summary.p99StorageLatencyMs)}`}
            accent="var(--metric-db)"
          />
          <SummaryCard
            icon="warning"
            label="Failures / rejections"
            value={formatNumber(summary.totalFailed + summary.totalRateLimited)}
            detail={`${formatNumber(summary.totalFailed)} DLQ · ${formatNumber(summary.totalRateLimited)} limited`}
            accent="var(--metric-error)"
          />
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="grid gap-4 lg:grid-cols-2">
          {CHARTS.map((card) => {
            const chart = charts[card.widget]
            return (
              <article
                key={card.widget}
                className={`rounded-lg border border-[var(--border)] bg-[var(--panel)] p-4 shadow-sm transition-all duration-200 ease-in-out hover:border-sky-500/40 ${
                  card.widget === 'ingestion' ? 'min-h-[434px]' : 'min-h-[318px]'
                }`}
              >
                <div className="mb-4 flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <h2 className="text-sm font-semibold tracking-normal text-[var(--text-primary)]">
                      {card.title}
                    </h2>
                    <p className="mt-1 text-xs text-[var(--text-secondary)]">{card.description}</p>
                  </div>
                  <div
                    className="grid size-9 place-items-center rounded-md border"
                    style={{ borderColor: card.accent, color: card.accent }}
                  >
                    <MaterialIcon name={card.icon} />
                  </div>
                </div>
                <MetricAreaChart
                  widget={card.widget}
                  range="custom"
                  data={chart.data}
                  series={chart.series}
                  isLoading={query.isLoading}
                  onRetry={() => void query.refetch()}
                  heightClass={card.widget === 'ingestion' ? 'h-72' : 'h-44'}
                  {...(query.isError ? { error: 'Metric aggregates unavailable. Try again.' } : {})}
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

        <aside className="space-y-4">
          <WindowDetails
            from={windowState.from}
            to={windowState.to}
            bucketSeconds={bucketSeconds}
            pointCount={points.length}
            sampleCount={summary.sampleCount}
            isFetching={query.isFetching}
            presetLabel={windowState.presetLabel}
          />
          <article className="rounded-lg border border-[var(--border)] bg-[var(--panel)] p-4 shadow-sm">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Overall metrics</h2>
            <dl className="mt-3 space-y-3 text-xs">
              <DetailRow
                label="Avg ingest"
                value={formatMetricValue('ingestion', summary.averageIngestRate)}
              />
              <DetailRow
                label="Avg persist"
                value={formatMetricValue('ingestion', summary.averagePersistRate)}
              />
              <DetailRow
                label="Avg Kafka lag"
                value={formatMetricValue('kafkaLag', summary.avgKafkaLag)}
              />
              <DetailRow
                label="Max Kafka lag"
                value={formatMetricValue('kafkaLag', summary.maxKafkaLag)}
              />
              <DetailRow
                label="Avg DB latency"
                value={formatMetricValue('dbLatency', summary.avgStorageLatencyMs)}
              />
            </dl>
          </article>
          {isEmpty ? (
            <article className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-200 shadow-sm">
              No aggregate samples were returned for this window. Check that the metrics saver has
              run and the selected window overlaps collected telemetry.
            </article>
          ) : null}
        </aside>
      </div>
    </section>
  )
}

interface SummaryCardProps {
  icon: string
  label: string
  value: string
  detail: string
  accent: string
}

function SummaryCard({ icon, label, value, detail, accent }: SummaryCardProps) {
  return (
    <article className="rounded-lg border border-[var(--border)] bg-[var(--panel)] p-3 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs text-[var(--text-secondary)]">{label}</p>
          <p className="mt-1 truncate text-lg font-semibold text-[var(--text-primary)]">{value}</p>
          <p className="mt-1 truncate text-xs text-[var(--text-secondary)]">{detail}</p>
        </div>
        <div
          className="grid size-8 shrink-0 place-items-center rounded-md border"
          style={{ borderColor: accent, color: accent }}
        >
          <MaterialIcon name={icon} className="text-[18px]" />
        </div>
      </div>
    </article>
  )
}

interface WindowDetailsProps {
  from: string
  to: string
  bucketSeconds: number
  pointCount: number
  sampleCount: number
  isFetching: boolean
  presetLabel: string | undefined
}

function WindowDetails({
  from,
  to,
  bucketSeconds,
  pointCount,
  sampleCount,
  isFetching,
  presetLabel,
}: WindowDetailsProps) {
  return (
    <article className="rounded-lg border border-[var(--border)] bg-[var(--panel)] p-4 shadow-sm">
      <div className="flex items-center justify-between gap-3">
        <h2 className="text-sm font-semibold text-[var(--text-primary)]">Query window</h2>
        <span className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
          <span
            className={
              isFetching ? 'size-2 rounded-full bg-sky-400' : 'size-2 rounded-full bg-emerald-400'
            }
          />
          {isFetching ? 'Fetching' : presetLabel ? `Last ${presetLabel}` : 'Custom window'}
        </span>
      </div>
      <dl className="mt-3 space-y-3 text-xs">
        <DetailRow label="From" value={formatTimestamp(from, 'custom')} />
        <DetailRow label="To" value={formatTimestamp(to, 'custom')} />
        <DetailRow label="Bucket step" value={formatDuration(bucketSeconds)} />
        <DetailRow label="Aggregate rows" value={formatNumber(pointCount)} />
        <DetailRow label="Samples" value={formatNumber(sampleCount)} />
      </dl>
    </article>
  )
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <dt className="text-[var(--text-secondary)]">{label}</dt>
      <dd className="max-w-[12rem] truncate text-right font-mono text-[var(--text-primary)]">
        {value}
      </dd>
    </div>
  )
}

function createInitialWindow(): HistoryWindow {
  const params = new URLSearchParams(window.location.search)
  const fromParam = params.get('from')
  const toParam = params.get('to')
  if (fromParam && toParam) {
    const parsed = parseWindowInputs(
      toLocalInputValue(new Date(fromParam)),
      toLocalInputValue(new Date(toParam))
    )
    if (parsed) {
      return parsed
    }
  }
  return createWindow(60 * 60_000, '1h')
}

function createWindow(durationMs: number, presetLabel?: string): HistoryWindow {
  const to = new Date()
  const from = new Date(to.getTime() - durationMs)
  return {
    from: from.toISOString(),
    to: to.toISOString(),
    fromInput: toLocalInputValue(from),
    toInput: toLocalInputValue(to),
    ...(presetLabel ? { presetLabel } : {}),
  }
}

function parseWindowInputs(fromInput: string, toInput: string): HistoryWindow | undefined {
  const from = new Date(fromInput)
  const to = new Date(toInput)
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime())) {
    return undefined
  }
  if (from >= to) {
    return undefined
  }
  return {
    from: from.toISOString(),
    to: to.toISOString(),
    fromInput,
    toInput,
  }
}

function getTimeError(fromInput: string, toInput: string) {
  const from = new Date(fromInput)
  const to = new Date(toInput)
  if (!fromInput || !toInput) {
    return 'Both from and to are required.'
  }
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime())) {
    return 'Enter a valid time window.'
  }
  if (from >= to) {
    return 'From must be before to.'
  }
  return undefined
}

function resolveBucketSeconds(from: string, to: string) {
  const durationSeconds = Math.max(1, (Date.parse(to) - Date.parse(from)) / 1000)
  const targetPoints = 90
  const raw = durationSeconds / targetPoints
  const candidates = [5, 10, 20, 30, 60, 300, 600, 1200, 3600, 8 * 3600, 24 * 3600]
  return candidates.find((candidate) => candidate >= raw) ?? candidates.at(-1) ?? 3600
}

function formatDuration(seconds: number) {
  if (seconds < 60) {
    return `${seconds}s`
  }
  if (seconds < 3600) {
    return `${formatNumber(seconds / 60)}m`
  }
  return `${formatNumber(seconds / 3600)}h`
}

function toLocalInputValue(date: Date) {
  if (!Number.isFinite(date.getTime())) {
    return ''
  }
  const offsetMs = date.getTimezoneOffset() * 60_000
  return new Date(date.getTime() - offsetMs).toISOString().slice(0, 19)
}

function writeHistoryQuery(windowState: HistoryWindow) {
  const search = new URLSearchParams(window.location.search)
  search.set('from', windowState.from)
  search.set('to', windowState.to)
  search.delete('step')
  const nextUrl = `${window.location.pathname}?${search.toString()}${window.location.hash}`
  window.history.replaceState(null, '', nextUrl)
}
