import { useEffect, useRef } from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { formatMetricValue, formatNumber, formatTimestamp } from '@/lib/format'
import type {
  AggregateTooltipStats,
  ChartDatum,
  ChartSeries,
  MetricChartRange,
  MetricWidget,
} from '@/lib/metrics-parser'

const EMPTY_CHART_DATA: ChartDatum[] = [
  { timestamp: new Date().toISOString(), total: 0 },
]

interface MetricAreaChartProps {
  widget: MetricWidget
  range: MetricChartRange
  data: ChartDatum[]
  series: ChartSeries[]
  isLoading: boolean
  error?: string
  onRetry: () => void
  scrollable?: boolean
}

export function MetricAreaChart({
  widget,
  range,
  data,
  series,
  isLoading,
  error,
  onRetry,
  scrollable = false,
}: MetricAreaChartProps) {
  const visibleData = data.length > 0 ? data : EMPTY_CHART_DATA
  const chartWidth = scrollable ? Math.max(1_800, visibleData.length * 4) : undefined
  const scrollRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!scrollable || !scrollRef.current) {
      return
    }
    const container = scrollRef.current
    container.scrollLeft = container.scrollWidth
  }, [scrollable, data.length])

  if (isLoading) {
    return <ChartSkeleton />
  }

  if (error) {
    return (
      <div className="grid h-44 place-items-center rounded-md border border-red-500/30 bg-red-500/10 text-sm text-red-200">
        <button type="button" className="cursor-pointer" onClick={onRetry}>
          {error}
        </button>
      </div>
    )
  }

  return (
    <div
      ref={scrollRef}
      className={
        scrollable
          ? 'relative h-44 overflow-x-auto overflow-y-visible pb-2'
          : 'relative h-44 overflow-visible'
      }
    >
      <div className="h-full" style={chartWidth ? { width: chartWidth } : undefined}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={visibleData} margin={{ top: 10, right: 8, left: -18, bottom: 0 }}>
          <defs>
            {series.map((item) => (
              <linearGradient key={item.key} id={gradientId(widget, item.key)} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={item.color} stopOpacity={0.15} />
                <stop offset="95%" stopColor={item.color} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid
            vertical={false}
            stroke="var(--chart-grid)"
            strokeDasharray="3 3"
          />
          <XAxis
            dataKey="timestamp"
            minTickGap={32}
            tickLine={false}
            axisLine={false}
            tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
            tickFormatter={(value: string) => formatTimestamp(value, range)}
          />
          <YAxis
            tickLine={false}
            axisLine={false}
            width={54}
            tick={{ fill: 'var(--text-secondary)', fontSize: 11 }}
            tickFormatter={(value: number) => formatShortAxis(value)}
          />
          <Tooltip
            content={<MetricTooltip widget={widget} range={range} series={series} />}
            cursor={{ stroke: 'var(--border)', strokeDasharray: '3 3' }}
            allowEscapeViewBox={{ x: false, y: false }}
            wrapperStyle={{ zIndex: 20 }}
            position={{ y: 0 }}
          />
          {series.length > 0 ? (
            series.map((item) => (
              <Area
                key={item.key}
                type="monotone"
                dataKey={item.key}
                stroke={item.color}
                strokeWidth={1.5}
                fill={`url(#${gradientId(widget, item.key)})`}
                isAnimationActive
                animationDuration={300}
                dot={false}
                activeDot={{ r: 3, strokeWidth: 0 }}
              />
            ))
          ) : (
            <Area
              type="monotone"
              dataKey="total"
              stroke="var(--border)"
              strokeWidth={1.5}
              fill="transparent"
              dot={false}
              isAnimationActive={false}
            />
          )}
        </AreaChart>
      </ResponsiveContainer>
      </div>
    </div>
  )
}

interface MetricTooltipPayload {
  dataKey?: string | number
  value?: number | string
  payload?: ChartDatum
}

interface MetricTooltipProps {
  active?: boolean
  payload?: MetricTooltipPayload[]
  label?: string | number
  widget: MetricWidget
  range: MetricChartRange
  series: ChartSeries[]
}

function MetricTooltip({
  active,
  payload,
  label,
  widget,
  range,
  series,
}: MetricTooltipProps) {
  if (!active || !payload || payload.length === 0) {
    return null
  }

  const byKey = new Map(series.map((item) => [item.key, item]))
  const rows = payload
    .filter((item): item is MetricTooltipPayload & { dataKey: string | number } =>
      Boolean(item.dataKey) && item.dataKey !== 'total',
    )
    .map((item) => {
      const key = String(item.dataKey)
      const seriesItem = byKey.get(key)
      return {
        key,
        label: seriesItem?.label ?? key,
        color: seriesItem?.color ?? '#3B82F6',
        value: typeof item.value === 'number' ? item.value : 0,
        stats: item.payload?.aggregateStats?.[key],
      }
    })
  const latencyStats = widget === 'dbLatency' ? firstStats(rows) : undefined
  const total = rows
    .filter((row) => widget !== 'ingestion' || row.label !== 'Persisted')
    .reduce((sum: number, row) => sum + row.value, 0)

  return (
    <div className="min-w-48 rounded-lg border border-[var(--tooltip-border)] bg-[var(--tooltip-bg)] p-3 text-xs text-[var(--text-primary)] shadow-md backdrop-blur">
      <div className="mb-2 font-mono text-[11px] text-[var(--text-secondary)]">
        {formatTimestamp(String(label), range)}
      </div>
      {latencyStats ? (
        <div className="grid min-w-52 grid-cols-2 gap-x-4 gap-y-1">
          {dbLatencyStatRows(latencyStats).map((stat) => (
            <div key={stat.label} className="flex justify-between gap-3">
              <span className="text-[var(--text-secondary)]">{stat.label}</span>
              <span className="font-mono font-semibold">{stat.value}</span>
            </div>
          ))}
        </div>
      ) : (
        <>
          <div className="space-y-1.5">
            {rows.map((row) => (
              <div key={row.key} className="space-y-1">
                <div className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2">
                  <span className="h-4 w-1.5 rounded-full" style={{ background: row.color }} />
                  <span className="truncate">{row.label}</span>
                  <span className="font-semibold">{formatMetricValue(widget, row.value)}</span>
                </div>
                {row.stats ? (
                  <div className="ml-3 grid grid-cols-2 gap-x-3 gap-y-0.5 text-[10px] text-[var(--text-secondary)]">
                    {tooltipStatRows(row.stats, widget).map((stat) => (
                      <div key={stat.label} className="flex justify-between gap-2">
                        <span>{stat.label}</span>
                        <span className="font-mono">{stat.value}</span>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
          {widget !== 'dbLatency' ? (
            <>
              <hr className="my-2 border-t border-[var(--tooltip-border)]" />
              <div className="flex items-center justify-between gap-4 font-semibold">
                <span>{widget === 'ingestion' ? 'Ingest rate' : 'Total'}</span>
                <span>{formatMetricValue(widget, total)}</span>
              </div>
            </>
          ) : null}
        </>
      )}
    </div>
  )
}


function firstStats(
  rows: ReadonlyArray<{ stats: AggregateTooltipStats | undefined }>,
): AggregateTooltipStats | undefined {
  return rows.find((row) => row.stats)?.stats
}

function dbLatencyStatRows(stats: AggregateTooltipStats) {
  const rows: Array<{ label: string; value: string }> = []
  rows.push({ label: 'Count', value: formatNumber(stats.count ?? 0) })
  rows.push({ label: 'min', value: formatMetricValue('dbLatency', stats.min ?? 0) })
  rows.push({ label: 'max', value: formatMetricValue('dbLatency', stats.max ?? 0) })
  rows.push({ label: 'Average', value: formatMetricValue('dbLatency', stats.avg ?? 0) })
  rows.push({ label: 'p90', value: formatMetricValue('dbLatency', stats.p90 ?? 0) })
  rows.push({ label: 'p95', value: formatMetricValue('dbLatency', stats.p95 ?? 0) })
  rows.push({ label: 'p99', value: formatMetricValue('dbLatency', stats.p99 ?? 0) })
  return rows
}

function tooltipStatRows(stats: AggregateTooltipStats, widget: MetricWidget) {
  const rows: Array<{ label: string; value: string }> = []
  if (stats.count !== undefined) {
    rows.push({ label: 'count', value: formatNumber(stats.count) })
  }

  if (widget === 'ingestion' || widget === 'deadLetter') {
    if (stats.delta !== undefined) {
      rows.push({ label: 'delta', value: formatNumber(stats.delta) })
    }
    return rows
  }

  const metricFields: Array<[string, number | undefined]> =
    widget === 'dbLatency'
      ? [
          ['avg', stats.avg],
          ['min', stats.min],
          ['max', stats.max],
          ['p90', stats.p90],
          ['p95', stats.p95],
          ['p99', stats.p99],
        ]
      : [
          ['avg', stats.avg],
          ['min', stats.min],
          ['max', stats.max],
          ['last', stats.last],
        ]

  for (const [label, value] of metricFields) {
    if (value !== undefined) {
      rows.push({ label, value: formatMetricValue(widget, value) })
    }
  }
  return rows
}

function ChartSkeleton() {
  return (
    <div className="h-44 animate-pulse rounded-md border border-[var(--border)] bg-[var(--chart-surface)]">
      <div className="mt-8 h-px bg-[var(--border)]" />
      <div className="mt-10 h-px bg-[var(--border)]" />
      <div className="mt-10 h-px bg-[var(--border)]" />
    </div>
  )
}

function formatShortAxis(value: number) {
  if (value >= 1_000_000) {
    return `${Math.round(value / 1_000_000)}M`
  }
  if (value >= 1_000) {
    return `${Math.round(value / 1_000)}k`
  }
  return String(Math.round(value))
}
function gradientId(widget: MetricWidget, key: string) {
  return `fill-${widget}-${key.replace(/[^a-zA-Z0-9_-]/g, '_')}`
}
