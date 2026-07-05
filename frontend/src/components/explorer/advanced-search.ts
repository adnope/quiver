import type { FlowSearchParams } from '@/types/api'

export interface AdvancedFilters {
  attributesContains: string
  sourceHost: string
  sourceIp: string
  nextHopIp: string
  bytesFrom: string
  bytesTo: string
  packetsFrom: string
  packetsTo: string
  durationMsFrom: string
  durationMsTo: string
  flowState: string
  tcpFlags: string
  inputInterface: string
  outputInterface: string
  samplingRate: string
  normalizationStatus: '' | 'ok' | 'partial'
  normalizationErrorContains: string
  ipVersion: '' | '4' | '6'
}

export const EMPTY_ADVANCED_FILTERS: AdvancedFilters = {
  attributesContains: '',
  sourceHost: '',
  sourceIp: '',
  nextHopIp: '',
  bytesFrom: '',
  bytesTo: '',
  packetsFrom: '',
  packetsTo: '',
  durationMsFrom: '',
  durationMsTo: '',
  flowState: '',
  tcpFlags: '',
  inputInterface: '',
  outputInterface: '',
  samplingRate: '',
  normalizationStatus: '',
  normalizationErrorContains: '',
  ipVersion: '',
}

const MAX_SEARCH_TEXT_LENGTH = 256
const MAX_UINT16 = 65_535
const MAX_UINT32 = 4_294_967_295

const integerFields: Array<{
  key: keyof AdvancedFilters
  label: string
  min: number
  max: number
}> = [
  { key: 'bytesFrom', label: 'Minimum bytes', min: 0, max: Number.MAX_SAFE_INTEGER },
  { key: 'bytesTo', label: 'Maximum bytes', min: 0, max: Number.MAX_SAFE_INTEGER },
  { key: 'packetsFrom', label: 'Minimum packets', min: 0, max: Number.MAX_SAFE_INTEGER },
  { key: 'packetsTo', label: 'Maximum packets', min: 0, max: Number.MAX_SAFE_INTEGER },
  { key: 'durationMsFrom', label: 'Minimum duration', min: 0, max: Number.MAX_SAFE_INTEGER },
  { key: 'durationMsTo', label: 'Maximum duration', min: 0, max: Number.MAX_SAFE_INTEGER },
  { key: 'tcpFlags', label: 'TCP flags', min: 0, max: MAX_UINT16 },
  { key: 'inputInterface', label: 'Input interface', min: 0, max: MAX_UINT32 },
  { key: 'outputInterface', label: 'Output interface', min: 0, max: MAX_UINT32 },
  { key: 'samplingRate', label: 'Sampling rate', min: 1, max: MAX_UINT32 },
]

export function getAdvancedSearchError(filters: AdvancedFilters) {
  for (const field of integerFields) {
    const value = filters[field.key].trim()
    if (value !== '' && !isIntegerInRange(value, field.min, field.max)) {
      return `${field.label} must be an integer from ${field.min} to ${field.max}.`
    }
  }
  for (const [fromKey, toKey, label] of [
    ['bytesFrom', 'bytesTo', 'Bytes'],
    ['packetsFrom', 'packetsTo', 'Packets'],
    ['durationMsFrom', 'durationMsTo', 'Duration'],
  ] as const) {
    const from = parseOptionalInteger(filters[fromKey])
    const to = parseOptionalInteger(filters[toKey])
    if (from !== undefined && to !== undefined && from > to) {
      return `${label} minimum must not exceed its maximum.`
    }
  }
  if (filters.attributesContains.trim().length > MAX_SEARCH_TEXT_LENGTH) {
    return `Attributes search must be at most ${MAX_SEARCH_TEXT_LENGTH} characters.`
  }
  if (filters.normalizationErrorContains.trim().length > MAX_SEARCH_TEXT_LENGTH) {
    return `Normalization error search must be at most ${MAX_SEARCH_TEXT_LENGTH} characters.`
  }
  return ''
}

export function buildAdvancedSearchParams(filters: AdvancedFilters): Partial<FlowSearchParams> {
  const params: Partial<FlowSearchParams> = {}
  assignTrimmed(params, 'attributes_contains', filters.attributesContains)
  assignTrimmed(params, 'source_host', filters.sourceHost)
  assignTrimmed(params, 'source_ip', filters.sourceIp)
  assignTrimmed(params, 'next_hop_ip', filters.nextHopIp)
  assignTrimmed(params, 'flow_state', filters.flowState)
  assignTrimmed(params, 'normalization_error_contains', filters.normalizationErrorContains)
  assignInteger(params, 'bytes_from', filters.bytesFrom)
  assignInteger(params, 'bytes_to', filters.bytesTo)
  assignInteger(params, 'packets_from', filters.packetsFrom)
  assignInteger(params, 'packets_to', filters.packetsTo)
  assignInteger(params, 'duration_ms_from', filters.durationMsFrom)
  assignInteger(params, 'duration_ms_to', filters.durationMsTo)
  assignInteger(params, 'tcp_flags', filters.tcpFlags)
  assignInteger(params, 'input_interface', filters.inputInterface)
  assignInteger(params, 'output_interface', filters.outputInterface)
  assignInteger(params, 'sampling_rate', filters.samplingRate)
  if (filters.normalizationStatus) {
    params.normalization_status = filters.normalizationStatus
  }
  if (filters.ipVersion) {
    params.ip_version = Number(filters.ipVersion) as 4 | 6
  }
  return params
}

export function countAdvancedFilters(filters: AdvancedFilters) {
  return Object.values(filters).filter((value) => value.trim() !== '').length
}

function assignTrimmed<K extends keyof FlowSearchParams>(
  params: Partial<FlowSearchParams>,
  key: K,
  rawValue: string
) {
  const value = rawValue.trim()
  if (value !== '') {
    Object.assign(params, { [key]: value })
  }
}

function assignInteger<K extends keyof FlowSearchParams>(
  params: Partial<FlowSearchParams>,
  key: K,
  rawValue: string
) {
  const value = parseOptionalInteger(rawValue)
  if (value !== undefined) {
    Object.assign(params, { [key]: value })
  }
}

function parseOptionalInteger(value: string) {
  const trimmed = value.trim()
  return trimmed === '' ? undefined : Number(trimmed)
}

function isIntegerInRange(value: string, min: number, max: number) {
  if (!/^\d+$/.test(value)) {
    return false
  }
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max
}
