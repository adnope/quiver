import type { MetricRange, MetricWidget } from '@/lib/metrics-parser'

export function formatNumber(value: number) {
  return new Intl.NumberFormat('en-US', {
    maximumFractionDigits: value >= 100 ? 0 : 2,
  }).format(value)
}

export function formatMetricValue(widget: MetricWidget, value: number) {
  switch (widget) {
    case 'ingestion':
      return `${formatNumber(value)} flows/sec`
    case 'deadLetter':
      return `${formatNumber(value)} errors/sec`
    case 'dbLatency':
      return `${formatNumber(value)} ms`
    case 'kafkaLag':
      return `${formatNumber(value)} lag`
  }
}

export function formatBytes(value: number | undefined) {
  if (value === undefined) {
    return '-'
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let unitIndex = 0
  let scaled = value
  while (scaled >= 1024 && unitIndex < units.length - 1) {
    scaled /= 1024
    unitIndex += 1
  }
  return `${formatNumber(scaled)} ${units[unitIndex]}`
}

export function formatOptionalNumber(value: number | undefined) {
  return value === undefined ? '-' : formatNumber(value)
}

export function formatTimestamp(value: string, range?: MetricRange) {
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) {
    return value
  }
  if (range === '1m') {
    return new Intl.DateTimeFormat('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(date)
  }
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(date)
}

export function formatPort(value: number | undefined) {
  return value === undefined ? '-' : String(value)
}
