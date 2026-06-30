import { useQuery } from '@tanstack/react-query'
import { getLiveMetrics, getMetricAggregates, getMetricsHistory } from '@/lib/api-client'
import {
  buildAggregateChart,
  buildHistoryChart,
  buildLiveWidgetSnapshot,
  metricAggregateParamsForRange,
} from '@/lib/metrics-parser'
import { useAppStore } from '@/store/app-store'
import type { MetricRange, MetricWidget } from '@/lib/metrics-parser'
import type { MetricAggregatePoint, MetricAggregatesParams, MetricSnapshot } from '@/types/api'

export function useLiveMetrics() {
  const apiBaseUrl = useAppStore((state) => state.apiBaseUrl)
  const apiKey = useAppStore((state) => state.apiKey)

  return useQuery({
    queryKey: ['metrics', 'live', apiBaseUrl, Boolean(apiKey)],
    queryFn: ({ signal }) => getLiveMetrics({ baseUrl: apiBaseUrl, apiKey, signal }),
    refetchInterval: 5_000,
    retry: 2,
    staleTime: 4_500,
  })
}

export function useMetricsHistory(range: MetricRange, enabled = true) {
  const apiBaseUrl = useAppStore((state) => state.apiBaseUrl)
  const apiKey = useAppStore((state) => state.apiKey)

  return useQuery({
    queryKey: ['metrics', 'history', range, apiBaseUrl, Boolean(apiKey)],
    enabled,
    queryFn: ({ signal }) => getMetricsHistory(range, { baseUrl: apiBaseUrl, apiKey, signal }),
    retry: 2,
    staleTime: 10_000,
    refetchInterval: 10_000,
    gcTime: 5 * 60_000,
  })
}

export function useMetricAggregates(range: MetricRange, enabled = true) {
  const apiBaseUrl = useAppStore((state) => state.apiBaseUrl)
  const apiKey = useAppStore((state) => state.apiKey)

  return useQuery({
    queryKey: ['metrics', 'aggregates', range, apiBaseUrl, Boolean(apiKey)],
    enabled,
    queryFn: ({ signal }) =>
      getMetricAggregates(metricAggregateParamsForRange(range), {
        baseUrl: apiBaseUrl,
        apiKey,
        signal,
      }),
    retry: 2,
    staleTime: 10_000,
    refetchInterval: 10_000,
    gcTime: 5 * 60_000,
  })
}

export function useMetricAggregateWindow(params: MetricAggregatesParams, enabled = true) {
  const apiBaseUrl = useAppStore((state) => state.apiBaseUrl)
  const apiKey = useAppStore((state) => state.apiKey)

  return useQuery({
    queryKey: ['metrics', 'aggregates', 'window', params, apiBaseUrl, Boolean(apiKey)],
    enabled,
    queryFn: ({ signal }) =>
      getMetricAggregates(params, {
        baseUrl: apiBaseUrl,
        apiKey,
        signal,
      }),
    retry: 2,
    staleTime: 30_000,
    gcTime: 5 * 60_000,
  })
}

export function selectHistoryWidget(
  points: ReadonlyArray<{
    timestamp: string
    name: string
    labels?: Record<string, string> | null
    value: number
    delta: number
  }>,
  widget: MetricWidget,
  range: MetricRange,
  now = new Date()
) {
  return buildHistoryChart(points, widget, range, now)
}

export function selectAggregateWidget(
  points: ReadonlyArray<MetricAggregatePoint>,
  widget: MetricWidget,
  range: MetricRange,
  now = new Date()
) {
  return buildAggregateChart(points, widget, range, now)
}

export function selectLiveWidget(
  current: ReadonlyArray<MetricSnapshot>,
  previous: ReadonlyArray<MetricSnapshot> | undefined,
  widget: MetricWidget
) {
  return buildLiveWidgetSnapshot(current, previous ?? [], widget)
}
