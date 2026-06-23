import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import {
  getFlowById,
  getProtocols,
  getTopPorts,
  getTopTalkers,
  searchFlows,
} from '@/lib/api-client'
import { useAppStore } from '@/store/app-store'
import type {
  AggregationMetric,
  AggregationParams,
  DirectedAggregationParams,
  FlowSearchParams,
} from '@/types/api'

export function useFlows(params: Omit<FlowSearchParams, 'cursor'>, options?: { enabled?: boolean }) {
  const apiBaseUrl = useAppStore((state) => state.apiBaseUrl)
  const apiKey = useAppStore((state) => state.apiKey)
  const setLastApiLatency = useAppStore((state) => state.setLastApiLatency)

  return useInfiniteQuery({
    queryKey: ['flows', params, apiBaseUrl, Boolean(apiKey)],
    initialPageParam: undefined as string | undefined,
    enabled: options?.enabled !== false,
    queryFn: async ({ pageParam, signal }) => {
      const queryParams: FlowSearchParams = pageParam
        ? { ...params, cursor: pageParam }
        : params
      const startTime = performance.now()
      try {
        const res = await searchFlows(queryParams, { baseUrl: apiBaseUrl, apiKey, signal })
        setLastApiLatency(Math.round(performance.now() - startTime))
        return res
      } catch (err) {
        setLastApiLatency(Math.round(performance.now() - startTime))
        throw err
      }
    },
    getNextPageParam: (lastPage) => lastPage.next_cursor,
    staleTime: 0,
    gcTime: 2 * 60_000,
    retry: 2,
  })
}

export function useFlowById(id: string | undefined, startTime: string | undefined, includeAttributes = true) {
  const apiBaseUrl = useAppStore((state) => state.apiBaseUrl)
  const apiKey = useAppStore((state) => state.apiKey)
  const setLastApiLatency = useAppStore((state) => state.setLastApiLatency)

  return useQuery({
    queryKey: ['flow', id, startTime, includeAttributes, apiBaseUrl, Boolean(apiKey)],
    enabled: Boolean(id),
    queryFn: async ({ signal }) => {
      const startPerf = performance.now()
      try {
        const res = await getFlowById(id ?? '', startTime, includeAttributes, {
          baseUrl: apiBaseUrl,
          apiKey,
          signal,
        })
        setLastApiLatency(Math.round(performance.now() - startPerf))
        return res
      } catch (err) {
        setLastApiLatency(Math.round(performance.now() - startPerf))
        throw err
      }
    },
    staleTime: 30_000,
  })
}

export function useAggregations(params: {
  from: string
  to: string
  metric?: AggregationMetric
  limit?: number
  direction?: 'src' | 'dst'
}) {
  const apiBaseUrl = useAppStore((state) => state.apiBaseUrl)
  const apiKey = useAppStore((state) => state.apiKey)
  const setLastApiLatency = useAppStore((state) => state.setLastApiLatency)
  const client = { baseUrl: apiBaseUrl, apiKey }
  const aggregationParams: AggregationParams = {
    from: params.from,
    to: params.to,
    ...(params.metric ? { metric: params.metric } : {}),
    ...(params.limit !== undefined ? { limit: params.limit } : {}),
  }
  const directedAggregationParams: DirectedAggregationParams | undefined = params.direction
    ? { ...aggregationParams, direction: params.direction }
    : undefined

  const topTalkers = useQuery({
    queryKey: ['aggregations', 'top-talkers', params, apiBaseUrl, Boolean(apiKey)],
    enabled: Boolean(params.direction),
    queryFn: async ({ signal }) => {
      const startTime = performance.now()
      try {
        if (!directedAggregationParams) {
          throw new Error('direction is required for top talkers aggregation.')
        }
        const res = await getTopTalkers(directedAggregationParams, { ...client, signal })
        setLastApiLatency(Math.round(performance.now() - startTime))
        return res
      } catch (err) {
        setLastApiLatency(Math.round(performance.now() - startTime))
        throw err
      }
    },
    retry: 2,
    staleTime: 10_000,
  })

  const topPorts = useQuery({
    queryKey: ['aggregations', 'top-ports', params, apiBaseUrl, Boolean(apiKey)],
    enabled: Boolean(params.direction),
    queryFn: async ({ signal }) => {
      const startTime = performance.now()
      try {
        if (!directedAggregationParams) {
          throw new Error('direction is required for top ports aggregation.')
        }
        const res = await getTopPorts(directedAggregationParams, { ...client, signal })
        setLastApiLatency(Math.round(performance.now() - startTime))
        return res
      } catch (err) {
        setLastApiLatency(Math.round(performance.now() - startTime))
        throw err
      }
    },
    retry: 2,
    staleTime: 10_000,
  })

  const protocols = useQuery({
    queryKey: ['aggregations', 'protocols', params, apiBaseUrl, Boolean(apiKey)],
    queryFn: async ({ signal }) => {
      const startTime = performance.now()
      try {
        const res = await getProtocols(aggregationParams, { ...client, signal })
        setLastApiLatency(Math.round(performance.now() - startTime))
        return res
      } catch (err) {
        setLastApiLatency(Math.round(performance.now() - startTime))
        throw err
      }
    },
    retry: 2,
    staleTime: 10_000,
  })

  return { topTalkers, topPorts, protocols }
}

