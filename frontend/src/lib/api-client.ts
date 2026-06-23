import type {
  AggregationParams,
  ApiErrorBody,
  DetailedHealthResponse,
  DirectedAggregationParams,
  FlowResponse,
  FlowSearchParams,
  FlowSearchResponse,
  HealthResponse,
  LiveMetricsResponse,
  MetricHistoryResponse,
  ProtocolsResponse,
  TopPortsResponse,
  TopTalkersResponse,
} from '@/types/api'
import { parsePrometheusMetrics } from '@/lib/metrics-parser'

export class ApiClientError extends Error {
  readonly status: number
  readonly code: string | undefined
  readonly requestId: string | undefined
  readonly details?: unknown

  constructor(params: {
    status: number
    message: string
    code?: string | undefined
    requestId?: string | undefined
    details?: unknown
  }) {
    super(params.message)
    this.name = 'ApiClientError'
    this.status = params.status
    this.code = params.code
    this.requestId = params.requestId
    this.details = params.details
  }
}

export interface ApiClientOptions {
  baseUrl?: string
  apiKey?: string
  signal?: AbortSignal
}

export function validateApiBaseUrl(value: string): string {
  const trimmed = value.trim()
  if (trimmed === '') {
    return ''
  }

  let parsed: URL
  try {
    parsed = new URL(trimmed)
  } catch {
    throw new Error('API URL must be a valid absolute URL.')
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('API URL must use http or https.')
  }

  parsed.pathname = parsed.pathname.replace(/\/+$/, '')
  parsed.search = ''
  parsed.hash = ''
  return parsed.toString().replace(/\/$/, '')
}

export function buildApiUrl(path: string, baseUrl?: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  if (!baseUrl || baseUrl.trim() === '') {
    return normalizedPath
  }
  if (shouldUseViteProxy(baseUrl)) {
    return normalizedPath
  }
  return `${validateApiBaseUrl(baseUrl)}${normalizedPath}`
}

function shouldUseViteProxy(baseUrl: string) {
  if (!import.meta.env.DEV) {
    return false
  }
  const parsed = new URL(validateApiBaseUrl(baseUrl))
  return (
    (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') &&
    parsed.port === '8236'
  )
}

export function toQueryString(params: object) {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params) as Array<[string, unknown]>) {
    if (
      (typeof value === 'string' && value !== '') ||
      typeof value === 'number'
    ) {
      search.set(key, String(value))
    }
  }
  const encoded = search.toString()
  return encoded === '' ? '' : `?${encoded}`
}

async function parseError(response: Response): Promise<ApiClientError> {
  let body: ApiErrorBody | undefined
  try {
    body = (await response.json()) as ApiErrorBody
  } catch {
    body = undefined
  }

  return new ApiClientError({
    status: response.status,
    code: body?.error?.code,
    message: body?.error?.message ?? response.statusText,
    requestId: body?.request_id,
    details: body?.error?.details,
  })
}

async function requestText(
  path: string,
  options: ApiClientOptions = {},
): Promise<string> {
  const headers = new Headers({ Accept: 'text/plain' })
  if (options.apiKey && options.apiKey.trim() !== '') {
    headers.set('X-API-Key', options.apiKey.trim())
  }

  const requestInit: RequestInit = {
    method: 'GET',
    headers,
  }
  if (options.signal) {
    requestInit.signal = options.signal
  }

  const response = await fetch(buildApiUrl(path, options.baseUrl), requestInit)

  if (!response.ok) {
    throw await parseError(response)
  }

  return response.text()
}

export async function requestJson<T>(
  path: string,
  options: ApiClientOptions = {},
): Promise<T> {
  const headers = new Headers({ Accept: 'application/json' })
  if (options.apiKey && options.apiKey.trim() !== '') {
    headers.set('X-API-Key', options.apiKey.trim())
  }

  const requestInit: RequestInit = {
    method: 'GET',
    headers,
  }
  if (options.signal) {
    requestInit.signal = options.signal
  }

  const response = await fetch(buildApiUrl(path, options.baseUrl), requestInit)

  if (!response.ok) {
    throw await parseError(response)
  }

  return (await response.json()) as T
}

export function getHealth(options?: ApiClientOptions) {
  return requestJson<HealthResponse | DetailedHealthResponse>('/health', options)
}

export function getLiveMetrics(options?: ApiClientOptions) {
  return requestJson<LiveMetricsResponse>('/api/v1/metrics/live', options).catch(
    async (error: unknown) => {
      if (isNotFound(error)) {
        return getPrometheusLiveMetrics(options)
      }
      throw error
    },
  )
}

export async function getPrometheusLiveMetrics(options?: ApiClientOptions) {
  const body = await requestText('/metrics', options)
  return { metrics: parsePrometheusMetrics(body) } satisfies LiveMetricsResponse
}

export async function validateBackendSettings(options: {
  baseUrl: string
  apiKey: string
}) {
  const baseUrl = validateApiBaseUrl(options.baseUrl)
  const apiKey = options.apiKey.trim()
  if (apiKey === '') {
    throw new Error('API key is required.')
  }

  try {
    await getHealth({ baseUrl, apiKey })
  } catch (error) {
    throw normalizeValidationError(error, 'Cannot reach Quiver backend health endpoint.')
  }

  try {
    await getLiveMetrics({ baseUrl, apiKey })
  } catch (error) {
    throw normalizeValidationError(error, 'API key must have metrics scope.')
  }

  return { baseUrl, apiKey }
}

function normalizeValidationError(error: unknown, fallback: string) {
  if (error instanceof ApiClientError) {
    if (error.status === 401) {
      return new Error('API key is missing or invalid.')
    }
    if (error.status === 403) {
      return new Error('API key does not have the required metrics scope.')
    }
    return new Error(`${fallback} ${error.message}`)
  }
  if (error instanceof TypeError) {
    return new Error(
      `${fallback} In local dev, use http://localhost:8236 and keep the Vite dev server proxy running.`,
    )
  }
  return error instanceof Error ? error : new Error(fallback)
}

export function getMetricsHistory(
  range: string,
  options?: ApiClientOptions,
) {
  return requestJson<MetricHistoryResponse>(
    `/api/v1/metrics/history${toQueryString({ range })}`,
    options,
  ).catch(async (error: unknown) => {
    if (isNotFound(error)) {
      return liveMetricsToCurrentHistory(await getPrometheusLiveMetrics(options))
    }
    throw error
  })
}

function liveMetricsToCurrentHistory(
  liveMetrics: LiveMetricsResponse,
): MetricHistoryResponse {
  const timestamp = new Date().toISOString()
  return {
    points: liveMetrics.metrics.map((metric) => ({
      timestamp,
      name: metric.name,
      labels: metric.labels ?? null,
      value: metric.value,
      delta: 0,
    })),
  }
}

function isNotFound(error: unknown) {
  return error instanceof ApiClientError && error.status === 404
}

export function searchFlows(
  params: FlowSearchParams,
  options?: ApiClientOptions,
) {
  return requestJson<FlowSearchResponse>(
    `/api/v1/flows${toQueryString(params)}`,
    options,
  )
}

export function getFlowById(
  id: string,
  startTime: string | undefined,
  includeAttributes: boolean,
  options?: ApiClientOptions,
) {
  return requestJson<FlowResponse>(
    `/api/v1/flows/${encodeURIComponent(id)}${toQueryString({
      start_time: startTime,
      include: includeAttributes ? 'attributes' : undefined,
    })}`,
    options,
  )
}

export function getTopTalkers(
  params: DirectedAggregationParams,
  options?: ApiClientOptions,
) {
  return requestJson<TopTalkersResponse>(
    `/api/v1/aggregations/top-talkers${toQueryString(params)}`,
    options,
  )
}

export function getTopPorts(
  params: DirectedAggregationParams,
  options?: ApiClientOptions,
) {
  return requestJson<TopPortsResponse>(
    `/api/v1/aggregations/top-ports${toQueryString(params)}`,
    options,
  )
}

export function getProtocols(
  params: AggregationParams,
  options?: ApiClientOptions,
) {
  return requestJson<ProtocolsResponse>(
    `/api/v1/aggregations/protocols${toQueryString(params)}`,
    options,
  )
}
