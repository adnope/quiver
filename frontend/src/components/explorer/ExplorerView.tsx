import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type PointerEvent as ReactPointerEvent,
  type UIEvent as ReactUIEvent,
} from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
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

const MAX_QUERY_WINDOW_MS = 7 * 24 * 60 * 60_000 // 7 days
const MAX_PORT_RANGE_VALUE = 65_525
const DEBOUNCE_MS = 1_000
const TABLE_ROW_HEIGHT = 33
const LIMIT_OPTIONS = [25, 50, 100, 250, 500, 1000] as const
const PORT_RANGE_FIELDS = [
  'srcPortFrom',
  'srcPortTo',
  'dstPortFrom',
  'dstPortTo',
] as const

type PortRangeField = (typeof PORT_RANGE_FIELDS)[number]
type PortRangeInputs = Record<PortRangeField, string>

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
  srcPortFrom: string
  srcPortTo: string
  dstPortFrom: string
  dstPortTo: string
}

const sourceTypes: SourceType[] = ['rest_json', 'zeek_conn_json', 'netflow_v5', 'netflow_v9']
const protocols: TransportProtocol[] = ['tcp', 'udp', 'icmp', 'gre', 'esp', 'other', 'unknown']
const directions: FlowDirection[] = ['inbound', 'outbound', 'internal', 'external', 'unknown']

export function ExplorerView() {
  const lastApiLatency = useAppStore((state) => state.lastApiLatency)
  const [initialTimeWindow] = useState(createInitialTimeWindow)
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
    srcPortFrom: '',
    srcPortTo: '',
    dstPortFrom: '',
    dstPortTo: '',
  })
  const [selectedId, setSelectedId] = useState<string | undefined>()
  const [selectedStartTime, setSelectedStartTime] = useState<string | undefined>()
  const [sortKey, setSortKey] = useState<SortKey>('event_start_time')
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc')
  const [limit, setLimit] = useState(1000)
  const [includeAttributes, setIncludeAttributes] = useState(false)
  const [fromInput, setFromInput] = useState(initialTimeWindow.fromInput)
  const [toInput, setToInput] = useState(initialTimeWindow.toInput)
  const [timeWindow, setTimeWindow] = useState(initialTimeWindow.query)

  const [searchInput, setSearchInput] = useState('')
  const [srcIpInput, setSrcIpInput] = useState('')
  const [dstIpInput, setDstIpInput] = useState('')
  const [portInputs, setPortInputs] = useState<PortRangeInputs>({
    srcPortFrom: '',
    srcPortTo: '',
    dstPortFrom: '',
    dstPortTo: '',
  })
  const [detailWidth, setDetailWidth] = useState(400)
  const timeError = getTimeWindowError(fromInput, toInput)
  const portError = getPortRangeError(portInputs)

  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters((current) => ({
        ...current,
        search: searchInput,
        srcIp: srcIpInput,
        dstIp: dstIpInput,
      }))
    }, DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [searchInput, srcIpInput, dstIpInput])

  useEffect(() => {
    if (portError) {
      return
    }
    const timer = setTimeout(() => {
      setFilters((current) => ({ ...current, ...portInputs }))
    }, DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [portError, portInputs])

  const sentinelRef = useRef<HTMLDivElement | null>(null)
  const scrollContainerRef = useRef<HTMLDivElement | null>(null)
  const explorerRef = useRef<HTMLElement | null>(null)
  const timeRangeMenuRef = useRef<HTMLDetailsElement | null>(null)

  const queryParams = useMemo(
    () => {
      return {
        ...buildFlowSearchParams(filters, timeWindow.from, timeWindow.to),
        limit,
        ...(includeAttributes ? { include: 'attributes' as const } : {}),
      }
    },
    [filters, timeWindow, limit, includeAttributes],
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
  // TanStack Virtual manages mutable scroll measurements outside React Compiler memoization.
  // eslint-disable-next-line react-hooks/incompatible-library
  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollContainerRef.current,
    estimateSize: () => TABLE_ROW_HEIGHT,
    overscan: 15,
  })
  const virtualRows = rowVirtualizer.getVirtualItems()
  const paddingTop = virtualRows[0]?.start ?? 0
  const paddingBottom =
    rowVirtualizer.getTotalSize() - (virtualRows.at(-1)?.end ?? 0)
  const columnCount = includeAttributes ? 16 : 15
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

  function submitTimeWindow() {
    const nextWindow = parseTimeWindow(fromInput, toInput)
    if (nextWindow) {
      setTimeWindow(nextWindow)
      timeRangeMenuRef.current?.removeAttribute('open')
    }
  }

  function applyTimePreset(hours: number) {
    applyTimeWindow(createTimeWindow(hours * 60 * 60_000))
  }

  function refreshFlows() {
    const duration = Date.parse(timeWindow.to) - Date.parse(timeWindow.from)
    applyTimeWindow(createTimeWindow(duration))
  }

  function applyTimeWindow(nextWindow: ReturnType<typeof createTimeWindow>) {
    setFromInput(nextWindow.fromInput)
    setToInput(nextWindow.toInput)
    setTimeWindow(nextWindow.query)
    timeRangeMenuRef.current?.removeAttribute('open')
  }

  function loadMoreOnVerticalScroll(event: ReactUIEvent<HTMLDivElement>) {
    const container = event.currentTarget
    const distanceFromBottom =
      container.scrollHeight - container.scrollTop - container.clientHeight
    if (
      distanceFromBottom <= 160 &&
      flows.hasNextPage &&
      !flows.isFetchingNextPage
    ) {
      void flows.fetchNextPage()
    }
  }

  function updatePortInput(field: PortRangeField, value: string) {
    setPortInputs((current) => ({ ...current, [field]: value }))
  }

  function resizeDetailPane(event: ReactPointerEvent<HTMLButtonElement>) {
    if (!event.currentTarget.hasPointerCapture(event.pointerId)) {
      return
    }
    const bounds = explorerRef.current?.getBoundingClientRect()
    if (!bounds) {
      return
    }
    const maxWidth = Math.max(280, Math.min(720, bounds.width - 480))
    setDetailWidth(Math.min(maxWidth, Math.max(280, bounds.right - event.clientX)))
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
    <section
      ref={explorerRef}
      className="grid h-[calc(100svh-6rem)] overflow-hidden rounded-lg border border-[var(--border)] bg-[var(--panel)] lg:grid-cols-[minmax(0,1fr)_var(--detail-width)]"
      style={{ '--detail-width': `${detailWidth}px` } as CSSProperties}
    >
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
              onClick={refreshFlows}
            >
              <MaterialIcon name="refresh" className="text-[18px]" />
              Refresh
            </Button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--border)] bg-[var(--panel-alt)] p-3">
          {/* Row 1: Time range, limit, include */}
          <div className="flex w-full flex-wrap items-center gap-2">
            <details ref={timeRangeMenuRef} className="relative">
              <summary className="flex h-9 cursor-pointer list-none items-center gap-2 rounded-md border border-[var(--border)] bg-[var(--input)] px-3 text-xs text-[var(--text-primary)] hover:border-sky-500/60">
                <MaterialIcon name="schedule" className="text-[18px] text-[var(--text-secondary)]" />
                <span>{formatTimeRange(timeWindow.from, timeWindow.to)}</span>
              </summary>
              <div className="absolute left-0 top-full z-30 mt-2 w-[min(92vw,25rem)] space-y-3 rounded-md border border-[var(--border)] bg-[var(--panel)] p-3 shadow-xl">
                <div className="grid grid-cols-3 gap-2">
                  <Button
                    type="button"
                    size="sm"
                    variant="secondary"
                    onClick={() => applyTimePreset(1)}
                  >
                    Last hour
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="secondary"
                    onClick={() => applyTimePreset(24)}
                  >
                    Last day
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="secondary"
                    onClick={() => applyTimePreset(7 * 24)}
                  >
                    Last week
                  </Button>
                </div>
                <label className="grid grid-cols-[3rem_1fr] items-center gap-2 text-xs text-[var(--text-secondary)]">
                  From
                  <input
                    type="datetime-local"
                    className={cn('h-9 min-w-0 rounded-md border bg-[var(--input)] px-2 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500', timeError ? 'border-red-500' : 'border-[var(--border)]')}
                    value={fromInput}
                    onChange={(event) => setFromInput(event.target.value)}
                  />
                </label>
                <label className="grid grid-cols-[3rem_1fr] items-center gap-2 text-xs text-[var(--text-secondary)]">
                  To
                  <input
                    type="datetime-local"
                    className={cn('h-9 min-w-0 rounded-md border bg-[var(--input)] px-2 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500', timeError ? 'border-red-500' : 'border-[var(--border)]')}
                    value={toInput}
                    onChange={(event) => setToInput(event.target.value)}
                  />
                </label>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs font-medium text-red-400">{timeError}</span>
                  <Button
                    type="button"
                    size="sm"
                    variant="primary"
                    disabled={Boolean(timeError)}
                    onClick={submitTimeWindow}
                  >
                    Submit
                  </Button>
                </div>
              </div>
            </details>
            <label className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
              Limit
              <select
                className="h-9 cursor-pointer rounded-md border border-[var(--border)] bg-[var(--input)] px-2 pr-6 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
              >
                {LIMIT_OPTIONS.map((v) => <option key={v} value={v}>{v}</option>)}
              </select>
            </label>
            <label className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)] cursor-pointer select-none">
              <input
                type="checkbox"
                className="accent-sky-500"
                checked={includeAttributes}
                onChange={(e) => setIncludeAttributes(e.target.checked)}
              />
              Include attributes
            </label>
          </div>
          {/* Row 2: Search and enum filters */}
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
          {/* Row 3: IPs and port ranges */}
          <div className="flex w-full flex-wrap items-center gap-2">
            <input
              className="h-9 w-40 min-w-0 rounded-md border border-[var(--border)] bg-[var(--input)] px-3 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
              placeholder="src IP"
              value={srcIpInput}
              onChange={(event) => setSrcIpInput(event.target.value)}
            />
            <input
              className="h-9 w-40 min-w-0 rounded-md border border-[var(--border)] bg-[var(--input)] px-3 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
              placeholder="dst IP"
              value={dstIpInput}
              onChange={(event) => setDstIpInput(event.target.value)}
            />
            <label className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
              Src port
              <input
                inputMode="numeric"
                className={portInputClass(portInputs.srcPortFrom)}
                placeholder="from"
                value={portInputs.srcPortFrom}
                onChange={(event) => updatePortInput('srcPortFrom', event.target.value)}
              />
              <span>-</span>
              <input
                inputMode="numeric"
                className={portInputClass(portInputs.srcPortTo)}
                placeholder="to"
                value={portInputs.srcPortTo}
                onChange={(event) => updatePortInput('srcPortTo', event.target.value)}
              />
            </label>
            <label className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
              Dst port
              <input
                inputMode="numeric"
                className={portInputClass(portInputs.dstPortFrom)}
                placeholder="from"
                value={portInputs.dstPortFrom}
                onChange={(event) => updatePortInput('dstPortFrom', event.target.value)}
              />
              <span>-</span>
              <input
                inputMode="numeric"
                className={portInputClass(portInputs.dstPortTo)}
                placeholder="to"
                value={portInputs.dstPortTo}
                onChange={(event) => updatePortInput('dstPortTo', event.target.value)}
              />
            </label>
            {portError ? (
              <span className="text-xs font-medium text-red-400">{portError}</span>
            ) : null}
          </div>
        </div>

        <div
          ref={scrollContainerRef}
          className="min-h-0 flex-1 overflow-auto"
          onScroll={loadMoreOnVerticalScroll}
        >
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
                <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Src IP</th>
                <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Dst IP</th>
                <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Ports</th>
                <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Direction</th>
                <SortableHeader label="Bytes" sortKey="bytes" activeKey={sortKey} direction={sortDirection} onSort={toggleSort} />
                <SortableHeader label="Packets" sortKey="packets" activeKey={sortKey} direction={sortDirection} onSort={toggleSort} />
                {includeAttributes ? (
                  <th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">
                    Attributes
                  </th>
                ) : null}
                <th className="border-b border-[var(--border)] px-3 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {paddingTop > 0 ? (
                <tr aria-hidden="true">
                  <td colSpan={columnCount} style={{ height: paddingTop, padding: 0 }} />
                </tr>
              ) : null}
              {virtualRows.map((virtualRow) => {
                const row = rows[virtualRow.index]
                if (!row) {
                  return null
                }
                return (
                  <tr
                    key={row.id}
                    className={cn(
                      'cursor-pointer border-b border-[var(--border)] text-[var(--text-primary)] transition hover:bg-[var(--panel-hover)]',
                      selectedId === row.id && 'bg-sky-500/10',
                    )}
                    style={{ height: TABLE_ROW_HEIGHT }}
                    onClick={() => {
                      setSelectedId(row.id)
                      setSelectedStartTime(row.event_start_time)
                    }}
                  >
                    <td className="border-r border-[var(--border)] px-3 py-2 text-right font-mono text-[11px] text-[var(--text-secondary)]">
                      {virtualRow.index + 1}
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
                    {includeAttributes ? <AttributesCell attributes={row.attributes} /> : null}
                    <td className="px-3 py-2">{row.normalization_status}</td>
                  </tr>
                )
              })}
              {paddingBottom > 0 ? (
                <tr aria-hidden="true">
                  <td colSpan={columnCount} style={{ height: paddingBottom, padding: 0 }} />
                </tr>
              ) : null}
            </tbody>
          </table>
          <div
            ref={sentinelRef}
            className="sticky left-0 grid min-h-20 place-items-center text-sm text-[var(--text-secondary)]"
          >
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

      <aside className="relative flex min-h-0 min-w-0 flex-col bg-[var(--panel-alt)]">
        <button
          type="button"
          role="separator"
          aria-label="Resize Cell Data panel"
          aria-orientation="vertical"
          aria-valuemin={280}
          aria-valuemax={720}
          aria-valuenow={detailWidth}
          title="Drag to resize Cell Data"
          className="absolute bottom-0 left-0 top-0 z-20 hidden w-1 -translate-x-1/2 touch-none cursor-col-resize bg-transparent hover:bg-sky-400/70 focus-visible:bg-sky-400 lg:block"
          onPointerDown={(event) => event.currentTarget.setPointerCapture(event.pointerId)}
          onPointerMove={resizeDetailPane}
          onPointerUp={(event) => event.currentTarget.releasePointerCapture(event.pointerId)}
          onKeyDown={(event) => {
            if (event.key === 'ArrowLeft') {
              setDetailWidth((current) => Math.min(720, current + 24))
            } else if (event.key === 'ArrowRight') {
              setDetailWidth((current) => Math.max(280, current - 24))
            }
          }}
        />
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

function createInitialTimeWindow() {
  return createTimeWindow(60 * 60_000)
}

function createTimeWindow(durationMs: number) {
  const to = new Date()
  const from = new Date(to.getTime() - durationMs)
  return {
    fromInput: toLocalDatetime(from),
    toInput: toLocalDatetime(to),
    query: { from: from.toISOString(), to: to.toISOString() },
  }
}

function getTimeWindowError(fromLocal: string, toLocal: string) {
  const fromMs = new Date(fromLocal).getTime()
  const toMs = new Date(toLocal).getTime()
  if (Number.isNaN(fromMs) || Number.isNaN(toMs)) {
    return 'Invalid date'
  }
  if (toMs <= fromMs) {
    return '"To" must be after "From"'
  }
  if (toMs - fromMs > MAX_QUERY_WINDOW_MS) {
    return 'Range exceeds max query window (7 days)'
  }
  return ''
}

function parseTimeWindow(fromLocal: string, toLocal: string) {
  if (getTimeWindowError(fromLocal, toLocal)) {
    return null
  }
  return {
    from: new Date(fromLocal).toISOString(),
    to: new Date(toLocal).toISOString(),
  }
}

function formatTimeRange(from: string, to: string) {
  const options: Intl.DateTimeFormatOptions = {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }
  return `${new Date(from).toLocaleString([], options)} - ${new Date(to).toLocaleString([], options)}`
}

function getPortRangeError(inputs: PortRangeInputs) {
  const hasInvalidPort = PORT_RANGE_FIELDS.some((field) =>
    isInvalidPortRangeValue(inputs[field]),
  )
  return hasInvalidPort
    ? `Port values must be integers from 0 to ${MAX_PORT_RANGE_VALUE}.`
    : ''
}

function isInvalidPortRangeValue(value: string) {
  const trimmed = value.trim()
  if (trimmed === '') {
    return false
  }
  if (!/^\d+$/.test(trimmed)) {
    return true
  }
  const parsed = Number(trimmed)
  return parsed < 0 || parsed > MAX_PORT_RANGE_VALUE
}

function portInputClass(value: string) {
  return cn(
    'h-9 w-20 rounded-md border bg-[var(--input)] px-2 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500',
    isInvalidPortRangeValue(value) ? 'border-red-500' : 'border-[var(--border)]',
  )
}

function AttributesCell({
  attributes,
}: {
  attributes: Record<string, unknown> | undefined
}) {
  const value = attributes ? JSON.stringify(attributes) : '-'
  return (
    <td
      className="max-w-64 truncate border-r border-[var(--border)] px-3 py-2 font-mono text-[11px] text-[var(--text-secondary)]"
      title={value}
    >
      {value}
    </td>
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
  // Port ranges
  const srcPortFrom = parsePort(filters.srcPortFrom)
  if (srcPortFrom !== undefined) params.src_port_from = srcPortFrom
  const srcPortTo = parsePort(filters.srcPortTo)
  if (srcPortTo !== undefined) params.src_port_to = srcPortTo
  const dstPortFrom = parsePort(filters.dstPortFrom)
  if (dstPortFrom !== undefined) params.dst_port_from = dstPortFrom
  const dstPortTo = parsePort(filters.dstPortTo)
  if (dstPortTo !== undefined) params.dst_port_to = dstPortTo
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

/** Convert a Date to the `YYYY-MM-DDTHH:mm` string required by datetime-local inputs */
function toLocalDatetime(d: Date) {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
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
