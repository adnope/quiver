export type ActiveTab = 'dashboard' | 'explorer'

export type ThemePreference = 'dark' | 'light' | 'system'

export type HealthStatus = 'ok' | 'degraded' | 'fail'

export interface HealthResponse {
  status: HealthStatus
}

export interface DetailedHealthResponse extends HealthResponse {
  database: HealthStatus
  kafka: HealthStatus
  collectors: Record<string, HealthStatus>
}

export interface MetricSnapshot {
  name: string
  labels?: Record<string, string> | null
  value: number
}

export interface LiveMetricsResponse {
  metrics: MetricSnapshot[]
}

export interface MetricHistoryPoint {
  timestamp: string
  name: string
  labels?: Record<string, string> | null
  value: number
  delta: number
}

export interface MetricHistoryResponse {
  points: MetricHistoryPoint[]
}

export type SourceType =
  | 'netflow_v5'
  | 'netflow_v9'
  | 'zeek_conn_json'
  | 'suricata_eve_json'
  | 'rest_json'
  | 'syslog_cef'
  | 'syslog_leef'

export type TransportProtocol =
  | 'unknown'
  | 'tcp'
  | 'udp'
  | 'icmp'
  | 'gre'
  | 'esp'
  | 'other'

export type FlowDirection =
  | 'unknown'
  | 'inbound'
  | 'outbound'
  | 'internal'
  | 'external'

export interface FlowResponse {
  id: string
  schema_version: string
  idempotency_key: string
  raw_event_id: string
  source_type: SourceType
  collector_id: string
  source_host: string
  source_ip?: string
  event_start_time: string
  event_end_time?: string
  duration_ms?: number
  src_ip: string
  dst_ip: string
  src_port?: number
  dst_port?: number
  transport_protocol: TransportProtocol
  protocol_number: number
  bytes?: number
  packets?: number
  direction: FlowDirection
  application_protocol?: string
  normalization_status: 'ok' | 'partial'
  attributes?: Record<string, unknown>
}

export interface FlowSearchResponse {
  items: FlowResponse[]
  next_cursor?: string
  limit: number
}

export interface FlowSearchParams {
  from: string
  to: string
  limit?: number
  cursor?: string
  include?: 'attributes'
  collector_id?: string
  source_type?: SourceType
  source_host?: string
  src_ip?: string
  dst_ip?: string
  src_cidr?: string
  dst_cidr?: string
  src_port?: number
  dst_port?: number
  src_port_from?: number
  src_port_to?: number
  dst_port_from?: number
  dst_port_to?: number
  protocol?: TransportProtocol
  protocol_number?: number
  direction?: FlowDirection
  application_protocol?: string
  sort?: string
  order?: string
}

export type AggregationMetric = 'bytes' | 'packets' | 'flows'

export interface TopTalkerResponse {
  ip: string
  metric: AggregationMetric
  value: number
  flow_count: number
}

export interface TopTalkersResponse {
  items: TopTalkerResponse[]
  from: string
  to: string
  limit: number
}

export interface TopPortResponse {
  port: number
  metric: AggregationMetric
  value: number
  flow_count: number
}

export interface TopPortsResponse {
  items: TopPortResponse[]
  from: string
  to: string
  limit: number
}

export interface ProtocolResponse {
  protocol_number: number
  transport_protocol: TransportProtocol
  metric: AggregationMetric
  value: number
  flow_count: number
}

export interface ProtocolsResponse {
  items: ProtocolResponse[]
  from: string
  to: string
  limit: number
}

export interface ApiErrorBody {
  error?: {
    code?: string
    message?: string
    details?: unknown
  }
  request_id?: string
}
