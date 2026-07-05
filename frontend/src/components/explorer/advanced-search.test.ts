import { describe, expect, it } from 'vitest'
import {
  buildAdvancedSearchParams,
  countAdvancedFilters,
  EMPTY_ADVANCED_FILTERS,
  getAdvancedSearchError,
  type AdvancedFilters,
} from './advanced-search'

function filters(overrides: Partial<AdvancedFilters> = {}): AdvancedFilters {
  return { ...EMPTY_ADVANCED_FILTERS, ...overrides }
}

describe('advanced search', () => {
  it('builds trimmed API parameters without empty fields', () => {
    expect(
      buildAdvancedSearchParams(
        filters({
          attributesContains: '  branch-router  ',
          bytesFrom: '10',
          bytesTo: '20',
          packetsFrom: '2',
          durationMsTo: '5000',
          sourceIp: '203.0.113.10',
          nextHopIp: '2001:db8::1',
          normalizationStatus: 'partial',
          ipVersion: '6',
        })
      )
    ).toEqual({
      attributes_contains: 'branch-router',
      bytes_from: 10,
      bytes_to: 20,
      packets_from: 2,
      duration_ms_to: 5000,
      source_ip: '203.0.113.10',
      next_hop_ip: '2001:db8::1',
      normalization_status: 'partial',
      ip_version: 6,
    })
  })

  it('validates integer fields and range ordering', () => {
    expect(getAdvancedSearchError(filters({ tcpFlags: '65536' }))).toContain('TCP flags')
    expect(getAdvancedSearchError(filters({ samplingRate: '0' }))).toContain('Sampling rate')
    expect(getAdvancedSearchError(filters({ bytesFrom: '20', bytesTo: '10' }))).toContain(
      'Bytes minimum'
    )
    expect(getAdvancedSearchError(filters({ packetsFrom: '1.5' }))).toContain('Minimum packets')
  })

  it('counts only applied non-empty filters', () => {
    expect(
      countAdvancedFilters(filters({ attributesContains: 'demo', bytesFrom: '10', flowState: ' ' }))
    ).toBe(2)
  })
})
