import { useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import { MaterialIcon } from '@/components/shell/MaterialIcon'
import { getProtocols, getTopPorts, getTopTalkers } from '@/lib/api-client'
import { formatBytes, formatNumber } from '@/lib/format'
import { cn } from '@/lib/utils'
import { useAppStore } from '@/store/app-store'
import type {
	AggregationMetric,
	ProtocolResponse,
	ProtocolsResponse,
	TopPortResponse,
	TopPortsResponse,
	TopTalkerResponse,
	TopTalkersResponse,
} from '@/types/api'

type AggregationTab = 'protocols' | 'top-ports' | 'top-talkers'

const MAX_QUERY_WINDOW_MS = 7 * 24 * 60 * 60 * 1000 // 7 days
const LIMIT_OPTIONS = [10, 20, 50, 100]

export function AnalyticsView() {
	const [activeSubTab, setActiveSubTab] = useState<AggregationTab>('protocols')
	const [metric, setMetric] = useState<AggregationMetric>('bytes')
	const [direction, setDirection] = useState<'src' | 'dst'>('src')
	const [limit, setLimit] = useState<number>(20)

	// Time range state
	const [timeWindow, setTimeWindow] = useState(createInitialTimeWindow().query)
	const [fromInput, setFromInput] = useState(createInitialTimeWindow().fromInput)
	const [toInput, setToInput] = useState(createInitialTimeWindow().toInput)

	const timeError = useMemo(() => getTimeWindowError(fromInput, toInput), [fromInput, toInput])

	// API settings from Zustand
	const apiBaseUrl = useAppStore((state) => state.apiBaseUrl)
	const apiKey = useAppStore((state) => state.apiKey)
	const setLastApiLatency = useAppStore((state) => state.setLastApiLatency)

	const timeRangeMenuRef = useRef<HTMLDetailsElement | null>(null)
	const [latency, setLatency] = useState<number | null>(null)

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

	function refreshData() {
		const duration = Date.parse(timeWindow.to) - Date.parse(timeWindow.from)
		applyTimeWindow(createTimeWindow(duration))
	}

	function applyTimeWindow(nextWindow: ReturnType<typeof createTimeWindow>) {
		setFromInput(nextWindow.fromInput)
		setToInput(nextWindow.toInput)
		setTimeWindow(nextWindow.query)
		timeRangeMenuRef.current?.removeAttribute('open')
	}

	// Dynamic params for query
	const queryParams = useMemo(() => {
		const baseParams: Record<string, string | number | undefined> = {
			from: timeWindow.from,
			to: timeWindow.to,
			metric,
			limit,
		}
		if (activeSubTab !== 'protocols') {
			baseParams.direction = direction
		}
		return baseParams
	}, [activeSubTab, timeWindow, metric, direction, limit])

	// React Queries
	const { data, isFetching, isError, refetch } = useQuery<
		ProtocolsResponse | TopPortsResponse | TopTalkersResponse
	>({
		queryKey: ['analytics', activeSubTab, queryParams, apiBaseUrl, Boolean(apiKey)],
		queryFn: async ({ signal }) => {
			const client = { baseUrl: apiBaseUrl, apiKey, signal }
			const startPerf = performance.now()
			try {
				let res: ProtocolsResponse | TopPortsResponse | TopTalkersResponse
				if (activeSubTab === 'protocols') {
					res = await getProtocols(queryParams, client)
				} else if (activeSubTab === 'top-ports') {
					res = await getTopPorts(queryParams, client)
				} else {
					res = await getTopTalkers(queryParams, client)
				}
				const elapsed = Math.round(performance.now() - startPerf)
				setLatency(elapsed)
				setLastApiLatency(elapsed)
				return res
			} catch (err) {
				const elapsed = Math.round(performance.now() - startPerf)
				setLatency(elapsed)
				setLastApiLatency(elapsed)
				throw err
			}
		},
		retry: 2,
		staleTime: 10_000,
	})

	const items = data?.items ?? []

	const protocolItems = activeSubTab === 'protocols' ? (items as ProtocolResponse[]) : []
	const portItems = activeSubTab === 'top-ports' ? (items as TopPortResponse[]) : []
	const talkerItems = activeSubTab === 'top-talkers' ? (items as TopTalkerResponse[]) : []

	function formatValue(val: number) {
		if (metric === 'bytes') {
			return formatBytes(val)
		}
		return formatNumber(val)
	}

	return (
		<section className="flex flex-col h-[calc(100svh-8rem)] overflow-hidden rounded-lg border border-[var(--border)] bg-[var(--panel)]">
			{/* Top bar: Tab selector */}
			<div className="flex min-h-12 flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] px-4 py-2">
				<div className="flex items-center gap-1">
					<Button
						type="button"
						size="sm"
						variant={activeSubTab === 'protocols' ? 'primary' : 'ghost'}
						onClick={() => setActiveSubTab('protocols')}
					>
						Protocols
					</Button>
					<Button
						type="button"
						size="sm"
						variant={activeSubTab === 'top-ports' ? 'primary' : 'ghost'}
						onClick={() => setActiveSubTab('top-ports')}
					>
						Top Ports
					</Button>
					<Button
						type="button"
						size="sm"
						variant={activeSubTab === 'top-talkers' ? 'primary' : 'ghost'}
						onClick={() => setActiveSubTab('top-talkers')}
					>
						Top Talkers
					</Button>
				</div>

				<div className="flex flex-wrap items-center gap-2">
					{latency !== null && (
						<span className="text-xs text-sky-400 font-mono mr-2">{latency}ms latency</span>
					)}
					<Button
						type="button"
						size="sm"
						onClick={refreshData}
					>
						<MaterialIcon name="refresh" className="text-[18px]" />
						Refresh
					</Button>
				</div>
			</div>

			{/* Filters row */}
			<div className="flex flex-wrap items-center gap-4 border-b border-[var(--border)] bg-[var(--panel-alt)] p-3">
				{/* Time range picker */}
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

				{/* Metric Selector */}
				<label className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
					Metric
					<select
						className="h-9 cursor-pointer rounded-md border border-[var(--border)] bg-[var(--input)] px-3 pr-8 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
						value={metric}
						onChange={(e) => setMetric(e.target.value as AggregationMetric)}
					>
						<option value="bytes">Bytes</option>
						<option value="packets">Packets</option>
						<option value="flows">Flows</option>
					</select>
				</label>

				{/* Direction Selector (Only for Ports/Talkers) */}
				{activeSubTab !== 'protocols' && (
					<label className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
						Direction
						<select
							className="h-9 cursor-pointer rounded-md border border-[var(--border)] bg-[var(--input)] px-3 pr-8 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
							value={direction}
							onChange={(e) => setDirection(e.target.value as 'src' | 'dst')}
						>
							<option value="src">Source</option>
							<option value="dst">Destination</option>
						</select>
					</label>
				)}

				{/* Limit Selector */}
				<label className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
					Limit
					<select
						className="h-9 cursor-pointer rounded-md border border-[var(--border)] bg-[var(--input)] px-3 pr-8 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
						value={limit}
						onChange={(e) => setLimit(Number(e.target.value))}
					>
						{LIMIT_OPTIONS.map((v) => <option key={v} value={v}>{v}</option>)}
					</select>
				</label>
			</div>

			{/* Results table */}
			<div className="min-h-0 flex-1 overflow-auto">
				<table className="w-full border-collapse text-left text-xs whitespace-nowrap">
					<thead className="sticky top-0 z-10 bg-[var(--table-header)] text-[var(--text-secondary)]">
						{activeSubTab === 'protocols' ? (
							<tr>
								<th className="w-14 border-b border-r border-[var(--border)] px-3 py-2 text-right font-medium">#</th>
								<th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Protocol Number</th>
								<th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Transport Protocol</th>
								<th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Metric Value</th>
								<th className="border-b border-[var(--border)] px-3 py-2 font-medium">Flow Count</th>
							</tr>
						) : activeSubTab === 'top-ports' ? (
							<tr>
								<th className="w-14 border-b border-r border-[var(--border)] px-3 py-2 text-right font-medium">#</th>
								<th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Port</th>
								<th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Metric Value</th>
								<th className="border-b border-[var(--border)] px-3 py-2 font-medium">Flow Count</th>
							</tr>
						) : (
							<tr>
								<th className="w-14 border-b border-r border-[var(--border)] px-3 py-2 text-right font-medium">#</th>
								<th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">IP Address</th>
								<th className="border-b border-r border-[var(--border)] px-3 py-2 font-medium">Metric Value</th>
								<th className="border-b border-[var(--border)] px-3 py-2 font-medium">Flow Count</th>
							</tr>
						)}
					</thead>
					<tbody>
						{activeSubTab === 'protocols' &&
							protocolItems.map((item, index) => (
								<tr
									key={index}
									className="border-b border-[var(--border)] text-[var(--text-primary)] hover:bg-[var(--panel-hover)]"
								>
									<td className="border-r border-[var(--border)] px-3 py-2 text-right font-mono text-[11px] text-[var(--text-secondary)]">
										{index + 1}
									</td>
									<td className="border-r border-[var(--border)] px-3 py-2 font-mono">{item.protocol_number}</td>
									<td className="border-r border-[var(--border)] px-3 py-2">{item.transport_protocol || '-'}</td>
									<td className="border-r border-[var(--border)] px-3 py-2 font-mono">{formatValue(item.value)}</td>
									<td className="px-3 py-2 font-mono">{formatNumber(item.flow_count)}</td>
								</tr>
							))}

						{activeSubTab === 'top-ports' &&
							portItems.map((item, index) => (
								<tr
									key={index}
									className="border-b border-[var(--border)] text-[var(--text-primary)] hover:bg-[var(--panel-hover)]"
								>
									<td className="border-r border-[var(--border)] px-3 py-2 text-right font-mono text-[11px] text-[var(--text-secondary)]">
										{index + 1}
									</td>
									<td className="border-r border-[var(--border)] px-3 py-2 font-mono">{item.port}</td>
									<td className="border-r border-[var(--border)] px-3 py-2 font-mono">{formatValue(item.value)}</td>
									<td className="px-3 py-2 font-mono">{formatNumber(item.flow_count)}</td>
								</tr>
							))}

						{activeSubTab === 'top-talkers' &&
							talkerItems.map((item, index) => (
								<tr
									key={index}
									className="border-b border-[var(--border)] text-[var(--text-primary)] hover:bg-[var(--panel-hover)]"
								>
									<td className="border-r border-[var(--border)] px-3 py-2 text-right font-mono text-[11px] text-[var(--text-secondary)]">
										{index + 1}
									</td>
									<td className="border-r border-[var(--border)] px-3 py-2 font-mono">{item.ip}</td>
									<td className="border-r border-[var(--border)] px-3 py-2 font-mono">{formatValue(item.value)}</td>
									<td className="px-3 py-2 font-mono">{formatNumber(item.flow_count)}</td>
								</tr>
							))}
					</tbody>
				</table>

				{/* Loading and empty states */}
				<div className="grid min-h-20 place-items-center text-sm text-[var(--text-secondary)] p-4">
					{isFetching && items.length === 0 ? 'Loading aggregations...' : null}
					{isError && !isFetching ? (
						<Button type="button" variant="danger" onClick={() => void refetch()}>
							Query failed. Try again.
						</Button>
					) : null}
					{!isFetching && !isError && items.length === 0 ? 'No metrics found in this window.' : null}
				</div>
			</div>
		</section>
	)
}

function createInitialTimeWindow() {
	return createTimeWindow(60 * 60_000) // 1 hour
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

function toLocalDatetime(d: Date) {
	const pad = (n: number) => String(n).padStart(2, '0')
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}
