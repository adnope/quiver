import { useEffect, useMemo, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
import { MaterialIcon } from '@/components/shell/MaterialIcon'
import { formatBytes, formatOptionalNumber, formatPort } from '@/lib/format'
import { cn } from '@/lib/utils'
import { useFlowById, useFlows } from '@/hooks/useFlows'
import { useAppStore } from '@/store/app-store'
import type {
  FlowDirection,
  FlowResponse,
  FlowSearchParams,
  SourceType,
  TransportProtocol,
} from '@/types/api'

type SortKey = 'event_start_time' | 'bytes' | 'packets' | 'src_ip' | 'dst_ip'
type SortDirection = 'asc' | 'desc'

interface ExplorerFilters {
  search: string
  sourceType: '' | SourceType
  protocol: '' | TransportProtocol
  direction: '' | FlowDirection
  srcIp: string
  dstIp: string
  srcCidr: string
  dstCidr: string
  srcPort: string
  dstPort: string
}

const sourceTypes: SourceType[] = ['rest_json', 'zeek_conn_json', 'netflow_v5', 'netflow_v9']
const protocols: TransportProtocol[] = ['tcp', 'udp', 'icmp', 'gre', 'esp', 'other', 'unknown']
const directions: FlowDirection[] = ['inbound', 'outbound', 'internal', 'external', 'unknown']

export function ExplorerView() {
  const lastApiLatency = useAppStore((state) => state.lastApiLatency)
  const [filters, setFilters] = useState<ExplorerFilters>({

    search: '',
    sourceType: '',
    protocol: '',
    direction: '',
    srcIp: '',
    dstIp: '',
    srcCidr: '',
    dstCidr: '',
    srcPort: '',
    dstPort: '',
  })
  const [selectedId, setSelectedId] = useState<string | undefined>()
  const [selectedStartTime, setSelectedStartTime] = useState<string | undefined>()
  const [sortKey, setSortKey] = useState<SortKey>('event_start_time')
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc')
  const [timePreset, setTimePreset] = useState<1 | 24 | 168>(1)
  const [timeWindow, setTimeWindow] = useState(() => lastHoursWindow(1))

  const [searchInput, setSearchInput] = useState('')
  const [srcIpInput, setSrcIpInput] = useState('')
  const [dstIpInput, setDstIpInput] = useState('')

  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters((current) => ({
        ...current,
        search: searchInput,
        srcIp: srcIpInput,
        dstIp: dstIpInput,
      }))
    }, 500)
    return () => clearTimeout(timer)
  }, [searchInput, srcIpInput, dstIpInput])

  const sentinelRef = useRef<HTMLDivElement | null>(null)
  const scrollContainerRef = useRef<HTMLDivElement | null>(null)

  const queryParams = useMemo(
    () => ({
      ...buildFlowSearchParams(filters, timeWindow.from, timeWindow.to),
      sort: sortKey,
      order: sortDirection,
    }),
    [filters, timeWindow, sortKey, sortDirection],
  )
  const flows = useFlows(queryParams)
  const isFirstPageLoading = flows.isFetching && !flows.isFetchingNextPage
  const rows = useMemo(
    () => {
      if (isFirstPageLoading) {
        return []
      }
      return sortRows(
        flows.data?.pages.flatMap((page) => page.items) ?? [],
        sortKey,
        sortDirection,
      )
    },
    [flows.data?.pages, isFirstPageLoading, sortDirection, sortKey],
  )
  const selectedFlow = useFlowById(selectedId, selectedStartTime, true)

  useEffect(() => {
    const sentinel = sentinelRef.current
    const scrollContainer = scrollContainerRef.current
    if (!sentinel || !scrollContainer) {
      return
    }
    const observer = new IntersectionObserver((entries) => {
      const first = entries[0]
      if (first?.isIntersecting && flows.hasNextPage && !flows.isFetchingNextPage) {
        void flows.fetchNextPage()
      }
    }, { root: scrollContainer })
    observer.observe(sentinel)
    return () => observer.disconnect()
  }, [flows])

  function updateFilter<K extends keyof ExplorerFilters>(
    key: K,
    value: ExplorerFilters[K],
  ) {
    setFilters((current) => ({ ...current, [key]: value }))
  }

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDirection((current) => (current === 'asc' ? 'desc' : 'asc'))
      return
    }
    setSortKey(key)
    setSortDirection(key === 'event_start_time' ? 'desc' : 'asc')
  }

  return (
    <section className="grid h-[calc(100svh-6rem)] overflow-hidden rounded-lg border border-[var(--border)] bg-[var(--panel)] lg:grid-cols-[minmax(0,1fr)_400px]">
      <div className="flex min-h-0 min-w-0 flex-col border-b border-[var(--border)] lg:border-b-0 lg:border-r">
        <div className="flex min-h-12 flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] px-4 py-2">
          <div>
            <h2 className="text-sm font-semibold tracking-normal text-[var(--text-primary)]">
              Flow Records
            </h2>
            <p className="mt-0.5 text-xs text-[var(--text-secondary)] flex items-center gap-1.5">
              <span>{rows.length} loaded</span>
              {lastApiLatency !== null && (
                <>
                  <span className="text-[var(--border)]">•</span>
                  <span className="text-sky-400 font-mono">{lastApiLatency}ms latency</span>
                </>
              )}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="button"
              size="sm"
              variant={timePreset === 1 ? 'primary' : 'secondary'}
              onClick={() => {
                setTimePreset(1)
                setTimeWindow(lastHoursWindow(1))
              }}
            >
              Last hour
            </Button>
            <Button
              type="button"
              size="sm"
              variant={timePreset === 24 ? 'primary' : 'secondary'}
              onClick={() => {
                setTimePreset(24)
                setTimeWindow(lastHoursWindow(24))
              }}
            >
              Last day
            </Button>
            <Button
              type="button"
              size="sm"
              variant={timePreset === 168 ? 'primary' : 'secondary'}
              onClick={() => {
                setTimePreset(168)
                setTimeWindow(lastHoursWindow(168))
              }}
            >
              Last week
            </Button>

            <Button
              type="button"
              size="sm"
              onClick={() => {
                setTimeWindow(lastHoursWindow(timePreset))
                void flows.refetch()
              }}
            >
              <MaterialIcon name="refresh" className="text-[18px]" />
              Refresh
            </Button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--border)] bg-[var(--panel-alt)] p-3">
          <input
            className="h-9 min-w-[180px] flex-1 rounded-md border border-[var(--border)] bg-[var(--input)] px-3 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
            placeholder="Search IP, CIDR, port, protocol, source"
            value={searchInput}
            onChange={(event) => setSearchInput(event.target.value)}
          />
          <select
            className="h-9 w-fit cursor-pointer rounded-md border border-[var(--border)] bg-[var(--input)] px-3 pr-8 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
            value={filters.sourceType}
            onChange={(event) => updateFilter('sourceType', event.target.value as ExplorerFilters['sourceType'])}
          >
            <option value="">All sources</option>
            {sourceTypes.map((sourceType) => (
              <option key={sourceType} value={sourceType}>
                {sourceType}
              </option>
            ))}
          </select>
          <select
            className="h-9 w-fit cursor-pointer rounded-md border border-[var(--border)] bg-[var(--input)] px-3 pr-8 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
            value={filters.protocol}
            onChange={(event) => updateFilter('protocol', event.target.value as ExplorerFilters['protocol'])}
          >
            <option value="">All protocols</option>
            {protocols.map((protocol) => (
              <option key={protocol} value={protocol}>
                {protocol}
              </option>
            ))}
          </select>
          <select
            className="h-9 w-fit cursor-pointer rounded-md border border-[var(--border)] bg-[var(--input)] px-3 pr-8 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
            value={filters.direction}
            onChange={(event) => updateFilter('direction', event.target.value as ExplorerFilters['direction'])}
          >
            <option value="">All directions</option>
            {directions.map((direction) => (
              <option key={direction} value={direction}>
                {direction}
              </option>
            ))}
          </select>
          <div className="flex w-[320px] shrink-0 gap-2">
            <input
              className="h-9 w-1/2 min-w-0 rounded-md border border-[var(--border)] bg-[var(--input)] px-3 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
              placeholder="src IP"
              value={srcIpInput}
              onChange={(event) => setSrcIpInput(event.target.value)}
            />
            <input
              className="h-9 w-1/2 min-w-0 rounded-md border border-[var(--border)] bg-[var(--input)] px-3 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
              placeholder="dst IP"
              value={dstIpInput}
              onChange={(event) => setDstIpInput(event.target.value)}
            />
          </div>
        </div>

        <div ref={scrollContainerRef} className="min-h-0 flex-1 overflow-auto">
          <table className="w-full border-collapse text-left text-xs whitespace-nowrap">
            <thead className="sticky top-0 z-10 bg-[var(--table-header)] text-[var(--text-secondary)]">
              <tr>
                <th className="w-14 border-b border-r border-[var(--border)] px-3 py-2 text-right font-medium">#</th>
                <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">ID</th>
                <SortableHeader label="Time" sortKey="event_start_time" activeKey={sortKey} direction={sortDirection} onSort={toggleSort} />
                <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Source</th>
                <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Collector ID</th>
                <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Source Host</th>
                <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Source IP</th>
                <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Protocol</th>
                <SortableHeader label="Src IP" sortKey="src_ip" activeKey={sortKey} direction={sortDirection} onSort={toggleSort} />
                <SortableHeader label="Dst IP" sortKey="dst_ip" activeKey={sortKey} direction={sortDirection} onSort={toggleSort} />
                <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Ports</th>
                <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Direction</th>
                <SortableHeader label="Bytes" sortKey="bytes" activeKey={sortKey} direction={sortDirection} onSort={toggleSort} />
                <SortableHeader label="Packets" sortKey="packets" activeKey={sortKey} direction={sortDirection} onSort={toggleSort} />
                <th className="border-b border-[var(--border)] px-3 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr
                  key={row.id}
                  className={cn(
                    'cursor-pointer border-b border-[var(--border)] text-[var(--text-primary)] transition hover:bg-[var(--panel-hover)]',
                    selectedId === row.id && 'bg-sky-500/10',
                  )}
                  onClick={() => {
                    setSelectedId(row.id)
                    setSelectedStartTime(row.event_start_time)
                  }}
                >
                  <td className="border-r border-[var(--border)] px-3 py-2 text-right font-mono text-[11px] text-[var(--text-secondary)]">
                    {index + 1}
                  </td>
                  <td className="border-r border-[var(--border)] px-3 py-2 font-mono text-[11px] text-[var(--text-secondary)]">
                    {row.id}
                  </td>
                  <td className="border-r border-[var(--border)] px-3 py-2 font-mono text-[11px] text-[var(--text-secondary)]">
                    {row.event_start_time}
                  </td>
                  <td className="border-r border-[var(--border)] px-3 py-2">{row.source_type}</td>
                  <td className="border-r border-[var(--border)] px-3 py-2 font-mono text-[11px] text-[var(--text-secondary)]">
                    {row.collector_id}
                  </td>
                  <td className="border-r border-[var(--border)] px-3 py-2">{row.source_host}</td>
                  <td className="border-r border-[var(--border)] px-3 py-2 font-mono">{row.source_ip ?? '-'}</td>
                  <td className="border-r border-[var(--border)] px-3 py-2">{row.transport_protocol}</td>
                  <td className="border-r border-[var(--border)] px-3 py-2 font-mono">{row.src_ip}</td>
                  <td className="border-r border-[var(--border)] px-3 py-2 font-mono">{row.dst_ip}</td>
                  <td className="border-r border-[var(--border)] px-3 py-2 font-mono">
                    {formatPort(row.src_port)} {'->'} {formatPort(row.dst_port)}
                  </td>
                  <td className="border-r border-[var(--border)] px-3 py-2">{row.direction}</td>
                  <td className="border-r border-[var(--border)] px-3 py-2">{formatBytes(row.bytes)}</td>
                  <td className="border-r border-[var(--border)] px-3 py-2">{formatOptionalNumber(row.packets)}</td>
                  <td className="px-3 py-2">{row.normalization_status}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div ref={sentinelRef} className="grid min-h-20 place-items-center text-sm text-[var(--text-secondary)]">
            {isFirstPageLoading ? 'Loading flows...' : null}
            {flows.isError && !isFirstPageLoading ? (
              <Button type="button" variant="danger" onClick={() => void flows.refetch()}>
                Flow query failed. Try again.
              </Button>
            ) : null}
            {!isFirstPageLoading && !flows.isError && rows.length === 0 ? 'No flow records in this window.' : null}
            {flows.isFetchingNextPage ? 'Loading more...' : null}
            {!isFirstPageLoading && !flows.hasNextPage && rows.length > 0 ? 'End of result set' : null}
          </div>
        </div>
      </div>

      <aside className="flex min-h-0 min-w-0 flex-col bg-[var(--panel-alt)]">
        <div className="flex h-12 items-center border-b border-[var(--border)] px-4">
          <h2 className="text-sm font-semibold tracking-normal text-[var(--text-primary)]">
            Cell Data
          </h2>
        </div>
        <div className="min-h-0 flex-1 overflow-auto p-4">
          {selectedId ? (
            selectedFlow.isLoading ? (
              <div className="text-sm text-[var(--text-secondary)]">Loading selected flow...</div>
            ) : selectedFlow.isError ? (
              <Button type="button" variant="danger" onClick={() => void selectedFlow.refetch()}>
                Detail query failed. Try again.
              </Button>
            ) : selectedFlow.data ? (
              <JsonTree value={selectedFlow.data} />
            ) : null
          ) : (
            <pre className="m-0 font-mono text-xs leading-6 text-[var(--text-secondary)]">
              {'{\n  "selected": null\n}'}
            </pre>
          )}
        </div>
      </aside>
    </section>
  )
}

function SortableHeader({
  label,
  sortKey,
  activeKey,
  direction,
  onSort,
}: {
  label: string
  sortKey: SortKey
  activeKey: SortKey
  direction: SortDirection
  onSort: (key: SortKey) => void
}) {
  const active = activeKey === sortKey
  return (
    <th className="border-b border-r border-[var(--border)] p-0 font-medium">
      <button
        type="button"
        className="flex h-9 w-full cursor-pointer items-center justify-between gap-2 px-3 text-left text-[var(--text-secondary)]"
        onClick={() => onSort(sortKey)}
      >
        <span>{label}</span>
        <MaterialIcon
          name={active && direction === 'asc' ? 'arrow_upward' : 'arrow_downward'}
          className={cn('text-[16px]', active ? 'text-sky-400' : 'text-[var(--text-secondary)]')}
        />
      </button>
    </th>
  )
}

function buildFlowSearchParams(
  filters: ExplorerFilters,
  from: string,
  to: string,
): Omit<FlowSearchParams, 'cursor'> {
  const params: Omit<FlowSearchParams, 'cursor'> = {
    from,
    to,
    limit: 100,
  }

  assignSearchFilter(params, filters.search)
  if (filters.sourceType) {
    params.source_type = filters.sourceType
  }
  if (filters.protocol) {
    params.protocol = filters.protocol
  }
  if (filters.direction) {
    params.direction = filters.direction
  }
  if (filters.srcIp.trim() !== '') {
    params.src_ip = filters.srcIp.trim()
  }
  if (filters.dstIp.trim() !== '') {
    params.dst_ip = filters.dstIp.trim()
  }
  if (filters.srcCidr.trim() !== '') {
    params.src_cidr = filters.srcCidr.trim()
  }
  if (filters.dstCidr.trim() !== '') {
    params.dst_cidr = filters.dstCidr.trim()
  }
  const srcPort = parsePort(filters.srcPort)
  if (srcPort !== undefined) {
    params.src_port = srcPort
  }
  const dstPort = parsePort(filters.dstPort)
  if (dstPort !== undefined) {
    params.dst_port = dstPort
  }
  return params
}

function assignSearchFilter(params: Omit<FlowSearchParams, 'cursor'>, rawSearch: string) {
  const search = rawSearch.trim()
  if (search === '') {
    return
  }
  if (sourceTypes.includes(search as SourceType)) {
    params.source_type = search as SourceType
    return
  }
  if (protocols.includes(search as TransportProtocol)) {
    params.protocol = search as TransportProtocol
    return
  }
  if (search.includes('/')) {
    params.src_cidr = search
    return
  }
  const port = parsePort(search)
  if (port !== undefined) {
    params.dst_port = port
    return
  }
  if (/^[0-9a-fA-F:.]+$/.test(search)) {
    params.src_ip = search
  }
}

function parsePort(value: string) {
  const trimmed = value.trim()
  if (!/^\d+$/.test(trimmed)) {
    return undefined
  }
  const parsed = Number(trimmed)
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 65535 ? parsed : undefined
}

function sortRows(rows: FlowResponse[], key: SortKey, direction: SortDirection) {
  const multiplier = direction === 'asc' ? 1 : -1
  return [...rows].sort((a, b) => compareFlow(a, b, key) * multiplier)
}

function compareFlow(a: FlowResponse, b: FlowResponse, key: SortKey) {
  switch (key) {
    case 'event_start_time':
      return Date.parse(a.event_start_time) - Date.parse(b.event_start_time)
    case 'bytes':
      return (a.bytes ?? 0) - (b.bytes ?? 0)
    case 'packets':
      return (a.packets ?? 0) - (b.packets ?? 0)
    case 'src_ip':
      return a.src_ip.localeCompare(b.src_ip)
    case 'dst_ip':
      return a.dst_ip.localeCompare(b.dst_ip)
  }
}

function lastHoursWindow(hours: number) {
  const to = new Date()
  const from = new Date(to.getTime() - hours * 60 * 60_000)
  return {
    from: from.toISOString(),
    to: to.toISOString(),
  }
}

function JsonTree({ value, name }: { value: unknown; name?: string }) {
  if (value === null || typeof value !== 'object') {
    return (
      <div className="font-mono text-xs leading-6">
        {name ? <span className="text-[var(--text-secondary)]">{name}: </span> : null}
        <span className="text-sky-300">{JSON.stringify(value)}</span>
      </div>
    )
  }

  if (Array.isArray(value)) {
    return (
      <details open className="font-mono text-xs leading-6">
        <summary className="cursor-pointer text-[var(--text-primary)]">
          {name ? `${name}: ` : ''}[{value.length}]
        </summary>
        <div className="ml-4 border-l border-[var(--border)] pl-3">
          {value.map((item, index) => (
            <JsonTree key={index} name={String(index)} value={item} />
          ))}
        </div>
      </details>
    )
  }

  const entries = Object.entries(value as Record<string, unknown>)
  return (
    <details open className="font-mono text-xs leading-6">
      <summary className="cursor-pointer text-[var(--text-primary)]">
        {name ? `${name}: ` : ''}{'{'}
        {entries.length}
        {'}'}
      </summary>
      <div className="ml-4 border-l border-[var(--border)] pl-3">
        {entries.map(([key, child]) => (
          <JsonTree key={key} name={key} value={child} />
        ))}
      </div>
    </details>
  )
}
