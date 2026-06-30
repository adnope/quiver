import {
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from 'react'
import { useQuery } from '@tanstack/react-query'
import { MaterialIcon } from '@/components/shell/MaterialIcon'
import { Button } from '@/components/ui/button'
import { getSystemLogs, type SystemLogLine, type SystemLogsParams } from '@/lib/api-client'
import { cn } from '@/lib/utils'
import { useAppStore } from '@/store/app-store'

const PRESETS = [
  { label: '15m', durationMs: 15 * 60_000 },
  { label: '1h', durationMs: 60 * 60_000 },
  { label: '6h', durationMs: 6 * 60 * 60_000 },
  { label: '24h', durationMs: 24 * 60 * 60_000 },
  { label: '7d', durationMs: 7 * 24 * 60 * 60_000 },
]

const LEVEL_OPTIONS = ['all', 'DEBUG', 'INFO', 'WARN', 'ERROR'] as const
const LIMIT_OPTIONS = [100, 200, 500, 1000] as const
const DEFAULT_LIMIT = 200
const LIVE_LOGS_REFRESH_MS = 2_000
const AUTO_SCROLL_BOTTOM_THRESHOLD_PX = 4
const INFINITE_SCROLL_TOP_THRESHOLD_PX = 24

type LogLevelFilter = (typeof LEVEL_OPTIONS)[number]
type LogLimit = (typeof LIMIT_OPTIONS)[number]

interface LogsWindow {
  from: string
  to: string
  fromInput: string
  toInput: string
  presetLabel?: string
}

interface InitialLogsState {
  window: LogsWindow
  level: LogLevelFilter
  search: string
  limit: LogLimit
}

interface OlderLogsState {
  datasetKey: string
  logs: SystemLogLine[]
  hasMoreOlder: boolean
  isLoadingOlder: boolean
  error: string | undefined
}

const EMPTY_OLDER_LOGS_STATE: OlderLogsState = {
  datasetKey: '',
  logs: [],
  hasMoreOlder: true,
  isLoadingOlder: false,
  error: undefined,
}

export function LogsView() {
  const [initialState] = useState(createInitialLogsState)
  const [windowState, setWindowState] = useState(initialState.window)
  const [draftFrom, setDraftFrom] = useState(initialState.window.fromInput)
  const [draftTo, setDraftTo] = useState(initialState.window.toInput)
  const [levelFilter, setLevelFilter] = useState<LogLevelFilter>(initialState.level)
  const [draftSearch, setDraftSearch] = useState(initialState.search)
  const [searchFilter, setSearchFilter] = useState(initialState.search)
  const [limit, setLimit] = useState<LogLimit>(initialState.limit)
  const [olderLogsState, setOlderLogsState] = useState<OlderLogsState>(EMPTY_OLDER_LOGS_STATE)

  const timeRangeMenuRef = useRef<HTMLDetailsElement | null>(null)
  const terminalRef = useRef<HTMLDivElement | null>(null)
  const logLinesRef = useRef<SystemLogLine[]>([])
  const datasetKeyRef = useRef('')
  const olderLoadInFlightRef = useRef(false)
  const pendingPrependScrollHeightRef = useRef<number | null>(null)
  const shouldStickToBottomRef = useRef(true)

  const apiBaseUrl = useAppStore((state) => state.apiBaseUrl)
  const apiKey = useAppStore((state) => state.apiKey)
  const lastApiLatency = useAppStore((state) => state.lastApiLatency)
  const setLastApiLatency = useAppStore((state) => state.setLastApiLatency)

  const timeError = useMemo(() => getTimeError(draftFrom, draftTo), [draftFrom, draftTo])

  const isLiveWindow = Boolean(windowState.presetLabel)
  const queryKeyParams = useMemo(
    () => ({
      from: windowState.from,
      to: windowState.to,
      presetLabel: windowState.presetLabel ?? '',
      level: levelFilter,
      search: searchFilter.trim(),
      limit,
    }),
    [levelFilter, limit, searchFilter, windowState]
  )

  const datasetKey = useMemo(
    () => JSON.stringify({ queryKeyParams, apiBaseUrl, hasApiKey: Boolean(apiKey) }),
    [apiBaseUrl, apiKey, queryKeyParams]
  )

  const activeOlderLogsState =
    olderLogsState.datasetKey === datasetKey ? olderLogsState : EMPTY_OLDER_LOGS_STATE

  const logsQuery = useQuery({
    queryKey: ['system-logs', queryKeyParams, apiBaseUrl, Boolean(apiKey)],
    queryFn: async ({ signal }) => {
      const startedAt = performance.now()
      try {
        const logs = await getSystemLogs(
          buildSystemLogsParams(windowState, levelFilter, searchFilter, limit),
          {
            baseUrl: apiBaseUrl,
            apiKey,
            signal,
          }
        )
        setLastApiLatency(Math.round(performance.now() - startedAt))
        return logs
      } catch (error) {
        setLastApiLatency(Math.round(performance.now() - startedAt))
        throw error
      }
    },
    retry: 2,
    staleTime: 1_000,
    gcTime: 5 * 60_000,
    refetchInterval: isLiveWindow ? LIVE_LOGS_REFRESH_MS : false,
  })

  const logLines = useMemo(
    () => mergeLogLines(activeOlderLogsState.logs, logsQuery.data ?? []),
    [activeOlderLogsState.logs, logsQuery.data]
  )

  const hasMoreOlder =
    activeOlderLogsState.hasMoreOlder && !(logsQuery.data && logsQuery.data.length < limit)

  useEffect(() => {
    datasetKeyRef.current = datasetKey
    olderLoadInFlightRef.current = false
    pendingPrependScrollHeightRef.current = null
    shouldStickToBottomRef.current = true
  }, [datasetKey])

  useEffect(() => {
    logLinesRef.current = logLines
  }, [logLines])

  useEffect(() => {
    writeLogsQuery(windowState, levelFilter, searchFilter, limit)
  }, [levelFilter, limit, searchFilter, windowState])

  useLayoutEffect(() => {
    const terminal = terminalRef.current
    if (!terminal) {
      return
    }

    const previousScrollHeight = pendingPrependScrollHeightRef.current
    if (previousScrollHeight !== null) {
      terminal.scrollTop += terminal.scrollHeight - previousScrollHeight
      pendingPrependScrollHeightRef.current = null
      shouldStickToBottomRef.current = isTerminalScrolledToBottom(terminal)
      return
    }

    if (shouldStickToBottomRef.current) {
      terminal.scrollTop = terminal.scrollHeight
      shouldStickToBottomRef.current = true
    }
  }, [logLines.length, logsQuery.dataUpdatedAt])

  useEffect(() => {
    function closeTimeRangeMenu(event: MouseEvent | TouchEvent) {
      const menu = timeRangeMenuRef.current
      if (!menu?.open) {
        return
      }

      const target = event.target
      if (target instanceof Node && !menu.contains(target)) {
        menu.removeAttribute('open')
      }
    }

    document.addEventListener('mousedown', closeTimeRangeMenu)
    document.addEventListener('touchstart', closeTimeRangeMenu)

    return () => {
      document.removeEventListener('mousedown', closeTimeRangeMenu)
      document.removeEventListener('touchstart', closeTimeRangeMenu)
    }
  }, [])

  function updateTerminalStickinessAndMaybeLoadOlder() {
    const terminal = terminalRef.current
    if (!terminal) {
      return
    }

    shouldStickToBottomRef.current = isTerminalScrolledToBottom(terminal)

    if (terminal.scrollTop <= INFINITE_SCROLL_TOP_THRESHOLD_PX) {
      void loadOlderLogs()
    }
  }

  async function loadOlderLogs() {
    if (olderLoadInFlightRef.current || !hasMoreOlder || logsQuery.isLoading) {
      return
    }

    const currentLogs = logLinesRef.current
    const oldestLog = currentLogs[0]
    if (!oldestLog) {
      return
    }

    const lowerBound = getWindowLowerBound(windowState)
    if (timestampMs(oldestLog.timestamp) <= timestampMs(lowerBound) + 1) {
      setOlderLogsState((current) => ({
        datasetKey,
        logs: current.datasetKey === datasetKey ? current.logs : [],
        hasMoreOlder: false,
        isLoadingOlder: false,
        error: undefined,
      }))
      return
    }

    const terminal = terminalRef.current
    const requestDatasetKey = datasetKeyRef.current
    const previousScrollHeight = terminal?.scrollHeight ?? null

    olderLoadInFlightRef.current = true
    setOlderLogsState((current) => ({
      datasetKey: requestDatasetKey,
      logs: current.datasetKey === requestDatasetKey ? current.logs : [],
      hasMoreOlder: current.datasetKey === requestDatasetKey ? current.hasMoreOlder : true,
      isLoadingOlder: true,
      error: undefined,
    }))

    const startedAt = performance.now()
    try {
      const olderLogs = await getSystemLogs(
        buildOlderSystemLogsParams(
          windowState,
          levelFilter,
          searchFilter,
          limit,
          oldestLog.timestamp
        ),
        {
          baseUrl: apiBaseUrl,
          apiKey,
        }
      )

      setLastApiLatency(Math.round(performance.now() - startedAt))

      if (requestDatasetKey !== datasetKeyRef.current) {
        return
      }

      const visibleMergedLogs = mergeLogLines(currentLogs, olderLogs)
      const addedVisibleLogs = visibleMergedLogs.length > currentLogs.length

      if (previousScrollHeight !== null && addedVisibleLogs) {
        pendingPrependScrollHeightRef.current = previousScrollHeight
      }

      setOlderLogsState((current) => {
        const currentOlderLogs = current.datasetKey === requestDatasetKey ? current.logs : []
        const mergedOlderLogs = mergeLogLines(currentOlderLogs, olderLogs)

        return {
          datasetKey: requestDatasetKey,
          logs: mergedOlderLogs,
          hasMoreOlder: addedVisibleLogs && olderLogs.length >= limit,
          isLoadingOlder: false,
          error: undefined,
        }
      })
    } catch (error) {
      if (requestDatasetKey === datasetKeyRef.current) {
        setOlderLogsState((current) => ({
          datasetKey: requestDatasetKey,
          logs: current.datasetKey === requestDatasetKey ? current.logs : [],
          hasMoreOlder: current.datasetKey === requestDatasetKey ? current.hasMoreOlder : true,
          isLoadingOlder: false,
          error: normalizeOlderLogsError(error),
        }))
      }
    } finally {
      if (requestDatasetKey === datasetKeyRef.current) {
        olderLoadInFlightRef.current = false
      }
    }
  }

  function applyWindow() {
    const parsed = parseWindowInputs(draftFrom, draftTo)
    if (!parsed) {
      return
    }
    shouldStickToBottomRef.current = true
    setWindowState(parsed)
    timeRangeMenuRef.current?.removeAttribute('open')
  }

  function applyPreset(preset: (typeof PRESETS)[number]) {
    const next = createWindow(preset.durationMs, preset.label)
    shouldStickToBottomRef.current = true
    setDraftFrom(next.fromInput)
    setDraftTo(next.toInput)
    setWindowState(next)
    timeRangeMenuRef.current?.removeAttribute('open')
  }

  function refreshLogs() {
    void logsQuery.refetch()
  }

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    shouldStickToBottomRef.current = true
    setSearchFilter(draftSearch.trim())
  }

  function clearSearch() {
    shouldStickToBottomRef.current = true
    setDraftSearch('')
    setSearchFilter('')
  }

  const isEmpty = !logsQuery.isLoading && !logsQuery.isError && logLines.length === 0

  return (
    <section className="flex h-[calc(100svh-13rem)] min-h-[20rem] flex-col overflow-hidden rounded-lg border border-[var(--border)] bg-[var(--panel)] shadow-sm">
      <div className="flex flex-wrap items-center gap-3 border-b border-[var(--border)] bg-[var(--panel-alt)] p-3">
        <details ref={timeRangeMenuRef} className="relative">
          <summary className="flex h-9 min-w-[21rem] cursor-pointer list-none items-center gap-2 rounded-md border border-[var(--border)] bg-[var(--input)] px-3 text-xs text-[var(--text-primary)] hover:border-sky-500/60">
            <MaterialIcon name="schedule" className="text-[18px] text-[var(--text-secondary)]" />
            <span className="truncate">{formatSelectedWindow(windowState)}</span>
          </summary>
          <div className="absolute left-0 top-full z-30 mt-2 w-[21rem] max-w-[92vw] space-y-3 rounded-md border border-[var(--border)] bg-[var(--panel)] p-3 shadow-xl">
            <div className="grid grid-cols-5 gap-1.5">
              {PRESETS.map((preset) => (
                <Button
                  key={preset.label}
                  type="button"
                  size="sm"
                  variant="secondary"
                  onClick={() => applyPreset(preset)}
                >
                  {preset.label}
                </Button>
              ))}
            </div>

            <div className="grid gap-2">
              <label className="grid gap-1.5 text-xs text-[var(--text-secondary)]">
                From
                <input
                  type="datetime-local"
                  step="1"
                  className={cn(
                    'h-9 min-w-0 rounded-md border bg-[var(--input)] px-2 text-[13px] text-[var(--text-primary)] outline-none transition focus:border-sky-500',
                    timeError ? 'border-red-500' : 'border-[var(--border)]'
                  )}
                  value={draftFrom}
                  onChange={(event) => setDraftFrom(event.target.value)}
                />
              </label>
              <label className="grid gap-1.5 text-xs text-[var(--text-secondary)]">
                To
                <input
                  type="datetime-local"
                  step="1"
                  className={cn(
                    'h-9 min-w-0 rounded-md border bg-[var(--input)] px-2 text-[13px] text-[var(--text-primary)] outline-none transition focus:border-sky-500',
                    timeError ? 'border-red-500' : 'border-[var(--border)]'
                  )}
                  value={draftTo}
                  onChange={(event) => setDraftTo(event.target.value)}
                />
              </label>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3">
              <span className="min-h-4 text-xs font-medium text-red-400">{timeError ?? ''}</span>
              <Button
                type="button"
                size="sm"
                variant="primary"
                disabled={Boolean(timeError)}
                onClick={applyWindow}
              >
                Apply window
              </Button>
            </div>
          </div>
        </details>

        <label className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
          Level
          <select
            className="h-9 cursor-pointer rounded-md border border-[var(--border)] bg-[var(--input)] px-3 pr-8 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
            value={levelFilter}
            onChange={(event) => {
              shouldStickToBottomRef.current = true
              setLevelFilter(event.target.value as LogLevelFilter)
            }}
          >
            {LEVEL_OPTIONS.map((level) => (
              <option key={level} value={level}>
                {level === 'all' ? 'All' : level}
              </option>
            ))}
          </select>
        </label>

        <label className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
          Limit
          <select
            className="h-9 cursor-pointer rounded-md border border-[var(--border)] bg-[var(--input)] px-3 pr-8 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
            value={limit}
            onChange={(event) => {
              shouldStickToBottomRef.current = true
              setLimit(Number(event.target.value) as LogLimit)
            }}
          >
            {LIMIT_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>

        <form className="flex min-w-[18rem] flex-1 items-center gap-2" onSubmit={submitSearch}>
          <div className="relative min-w-0 flex-1">
            <MaterialIcon
              name="search"
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[17px] text-[var(--text-secondary)]"
            />
            <input
              className="h-9 w-full rounded-md border border-[var(--border)] bg-[var(--input)] pl-11 pr-9 text-[13px] text-[var(--text-primary)] outline-none transition placeholder:text-[13px] placeholder:text-[var(--text-secondary)] focus:border-sky-500"
              placeholder="Search message or JSON attributes"
              value={draftSearch}
              onChange={(event) => setDraftSearch(event.target.value)}
            />
            {draftSearch !== '' ? (
              <button
                type="button"
                className="absolute right-2 top-1/2 grid size-5 -translate-y-1/2 place-items-center rounded text-[var(--text-secondary)] hover:bg-[var(--panel-hover)] hover:text-[var(--text-primary)]"
                aria-label="Clear log search"
                onClick={clearSearch}
              >
                <MaterialIcon name="close" className="text-[16px]" />
              </button>
            ) : null}
          </div>
          <Button type="submit" size="sm" variant="secondary" className="text-[13px]">
            Search
          </Button>
        </form>

        <div className="ml-auto flex flex-wrap items-center gap-2">
          {lastApiLatency !== null ? (
            <span className="rounded-md border border-[var(--border)] bg-[var(--panel)] px-2.5 py-1.5 font-mono text-xs text-[#00A4F4]">
              {lastApiLatency}ms latency
            </span>
          ) : null}
          <Button type="button" size="sm" className="text-[13px]" onClick={refreshLogs}>
            <MaterialIcon name="refresh" className="text-[17px]" />
            Refresh
          </Button>
        </div>
      </div>

      <div className="flex min-h-0 flex-1 flex-col bg-[#FFFFFF]">
        <div className="flex h-9 shrink-0 items-center justify-between bg-[#FFFFFF] px-4">
          <div className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-red-400" />
            <span className="size-2 rounded-full bg-amber-400" />
            <span className="size-2 rounded-full bg-emerald-400" />
          </div>
          <div className="flex min-w-0 items-center gap-2 text-xs text-slate-500">
            <span className="font-mono">{logLines.length} lines</span>
          </div>
        </div>

        <div
          ref={terminalRef}
          className="min-h-0 flex-1 overflow-auto py-2 font-mono text-[12px] leading-5"
          aria-live="polite"
          onScroll={updateTerminalStickinessAndMaybeLoadOlder}
        >
          {activeOlderLogsState.isLoadingOlder ? (
            <div className="px-4 py-1 text-[12px] text-[#00A4F4]">Loading older logs...</div>
          ) : null}

          {activeOlderLogsState.error ? (
            <div className="px-4 py-1 text-[12px] text-red-600">{activeOlderLogsState.error}</div>
          ) : null}

          {!hasMoreOlder && logLines.length > 0 ? (
            <div className="px-4 py-1 text-[12px] text-slate-400">
              Start of selected log window.
            </div>
          ) : null}

          {logsQuery.isError ? (
            <TerminalState
              icon="error"
              title="Could not load system logs"
              detail="Check the API key metrics scope and backend logs endpoint, then retry."
              action={
                <Button
                  type="button"
                  size="sm"
                  variant="secondary"
                  onClick={() => void logsQuery.refetch()}
                >
                  Retry
                </Button>
              }
            />
          ) : logsQuery.isLoading && logLines.length === 0 ? (
            <TerminalState
              icon="hourglass_top"
              title="Loading log lines"
              detail="Querying the selected time window."
            />
          ) : isEmpty ? (
            <TerminalState
              icon="data_object"
              title="No logs matched this query"
              detail="Widen the time range, clear search, or choose another level."
            />
          ) : (
            <div role="log" aria-label="System log lines">
              {logLines.map((log, index) => (
                <LogTerminalLine key={logLineKey(log, index)} log={log} />
              ))}
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

interface TerminalStateProps {
  icon: string
  title: string
  detail: string
  action?: ReactNode
}

function TerminalState({ icon, title, detail, action }: TerminalStateProps) {
  return (
    <div className="grid min-h-full place-items-center px-4 py-10 text-center">
      <div className="max-w-md rounded-lg border border-slate-200 bg-slate-50 p-5">
        <MaterialIcon name={icon} className="mx-auto text-[24px] text-slate-500" />
        <p className="mt-3 text-sm font-semibold text-slate-900">{title}</p>
        <p className="mt-1 text-xs leading-5 text-slate-500">{detail}</p>
        {action ? <div className="mt-4 flex justify-center">{action}</div> : null}
      </div>
    </div>
  )
}

function LogTerminalLine({ log }: { log: SystemLogLine }) {
  const level = normalizeLevel(log.level)
  const attributes = stringifyAttributes(log.attributes)

  return (
    <div
      className={cn(
        'group whitespace-pre-wrap break-words px-4 py-1 text-[12px] transition-colors hover:bg-slate-100',
        levelTextClass(level)
      )}
    >
      <span>[{formatLogTimestamp(log.timestamp)}] </span>
      <span className="font-semibold">[{level}]</span>
      <span> {log.message || '(no message)'}: </span>
      <span>{attributes}</span>
    </div>
  )
}

function createInitialLogsState(): InitialLogsState {
  const params = new URLSearchParams(window.location.search)
  const parsedWindow = parseWindowFromParams(params)

  return {
    window: parsedWindow ?? createWindow(60 * 60_000, '1h'),
    level: parseLevelFilter(params.get('level')),
    search: params.get('search')?.trim() ?? '',
    limit: parseLimit(params.get('limit')),
  }
}

function parseWindowFromParams(params: URLSearchParams) {
  const presetLabel = params.get('range')
  const preset = PRESETS.find((item) => item.label === presetLabel)
  if (preset) {
    return createWindow(preset.durationMs, preset.label)
  }

  const fromParam = params.get('from')
  const toParam = params.get('to')
  if (!fromParam || !toParam) {
    return undefined
  }

  return parseWindowInputs(
    toLocalInputValue(new Date(fromParam)),
    toLocalInputValue(new Date(toParam))
  )
}

function createWindow(durationMs: number, presetLabel?: string): LogsWindow {
  const to = new Date()
  const from = new Date(to.getTime() - durationMs)
  const base = {
    from: from.toISOString(),
    to: to.toISOString(),
    fromInput: toLocalInputValue(from),
    toInput: toLocalInputValue(to),
  }

  return presetLabel ? { ...base, presetLabel } : base
}

function parseWindowInputs(fromInput: string, toInput: string): LogsWindow | undefined {
  const from = new Date(fromInput)
  const to = new Date(toInput)
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime())) {
    return undefined
  }
  if (from >= to) {
    return undefined
  }

  return {
    from: from.toISOString(),
    to: to.toISOString(),
    fromInput,
    toInput,
  }
}

function getTimeError(fromInput: string, toInput: string) {
  const from = new Date(fromInput)
  const to = new Date(toInput)
  if (!fromInput || !toInput) {
    return 'Both from and to are required.'
  }
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime())) {
    return 'Enter a valid time window.'
  }
  if (from >= to) {
    return 'From must be before to.'
  }
  return undefined
}

function getWindowDurationMs(windowState: LogsWindow) {
  const durationMs = Date.parse(windowState.to) - Date.parse(windowState.from)
  return Number.isFinite(durationMs) && durationMs > 0 ? durationMs : 60 * 60_000
}

function getWindowLowerBound(windowState: LogsWindow) {
  if (windowState.presetLabel) {
    return new Date(Date.now() - getWindowDurationMs(windowState)).toISOString()
  }
  return windowState.from
}

function buildSystemLogsParams(
  windowState: LogsWindow,
  levelFilter: LogLevelFilter,
  searchFilter: string,
  limit: LogLimit
): SystemLogsParams {
  const params: SystemLogsParams = { limit }

  if (windowState.presetLabel) {
    params.from = getWindowLowerBound(windowState)
  } else {
    params.from = windowState.from
    params.to = windowState.to
  }

  if (levelFilter !== 'all') {
    params.level = levelFilter
  }

  const trimmedSearch = searchFilter.trim()
  if (trimmedSearch !== '') {
    params.search = trimmedSearch
  }

  return params
}

function buildOlderSystemLogsParams(
  windowState: LogsWindow,
  levelFilter: LogLevelFilter,
  searchFilter: string,
  limit: LogLimit,
  oldestTimestamp: string
): SystemLogsParams {
  const params: SystemLogsParams = {
    limit,
    from: getWindowLowerBound(windowState),
    to: oldestTimestamp,
  }

  if (levelFilter !== 'all') {
    params.level = levelFilter
  }

  const trimmedSearch = searchFilter.trim()
  if (trimmedSearch !== '') {
    params.search = trimmedSearch
  }

  return params
}

function parseLevelFilter(rawLevel: string | null): LogLevelFilter {
  const normalized = rawLevel?.trim().toUpperCase()
  if (normalized && LEVEL_OPTIONS.includes(normalized as LogLevelFilter)) {
    return normalized as LogLevelFilter
  }
  return 'all'
}

function parseLimit(rawLimit: string | null): LogLimit {
  const parsed = Number(rawLimit)
  if (LIMIT_OPTIONS.includes(parsed as LogLimit)) {
    return parsed as LogLimit
  }
  return DEFAULT_LIMIT
}

function writeLogsQuery(
  windowState: LogsWindow,
  levelFilter: LogLevelFilter,
  searchFilter: string,
  limit: LogLimit
) {
  const search = new URLSearchParams(window.location.search)

  if (windowState.presetLabel) {
    search.set('range', windowState.presetLabel)
    search.delete('from')
    search.delete('to')
  } else {
    search.delete('range')
    search.set('from', windowState.from)
    search.set('to', windowState.to)
  }

  search.set('limit', String(limit))

  if (levelFilter === 'all') {
    search.delete('level')
  } else {
    search.set('level', levelFilter)
  }

  const trimmedSearch = searchFilter.trim()
  if (trimmedSearch === '') {
    search.delete('search')
  } else {
    search.set('search', trimmedSearch)
  }

  const nextUrl = `${window.location.pathname}?${search.toString()}${window.location.hash}`
  window.history.replaceState(null, '', nextUrl)
}

function formatSelectedWindow(windowState: LogsWindow) {
  if (windowState.presetLabel) {
    return `Last ${windowState.presetLabel} · live`
  }
  return formatTimeRange(windowState.from, windowState.to)
}

function formatTimeRange(from: string, to: string) {
  return `${formatDateTime(from)} → ${formatDateTime(to)}`
}

function formatDateTime(value: string) {
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) {
    return value
  }

  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date)
}

function formatLogTimestamp(value: string) {
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) {
    return value
  }
  return date.toISOString()
}

function toLocalInputValue(date: Date) {
  if (!Number.isFinite(date.getTime())) {
    return ''
  }
  const offsetMs = date.getTimezoneOffset() * 60_000
  return new Date(date.getTime() - offsetMs).toISOString().slice(0, 19)
}

function compareLogTimestamps(a: SystemLogLine, b: SystemLogLine) {
  return timestampMs(a.timestamp) - timestampMs(b.timestamp)
}

function timestampMs(value: string) {
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) ? parsed : 0
}

function normalizeLevel(level: string) {
  const normalized = level.trim().toUpperCase()
  return normalized === '' ? 'INFO' : normalized
}

function levelTextClass(level: string) {
  switch (level) {
    case 'ERROR':
    case 'FATAL':
      return 'text-red-600'
    case 'WARN':
    case 'WARNING':
      return 'text-amber-600'
    case 'DEBUG':
      return 'text-violet-600'
    case 'INFO':
      return 'text-emerald-700'
    default:
      return 'text-slate-700'
  }
}

function stringifyAttributes(attributes: unknown) {
  if (attributes === null || attributes === undefined) {
    return '{}'
  }

  try {
    const json = JSON.stringify(attributes)
    return json === undefined ? '{}' : json
  } catch {
    return '{"serialization_error":"attributes could not be stringified"}'
  }
}

function logLineKey(log: SystemLogLine, index: number) {
  return `${log.timestamp}-${log.level}-${log.message}-${stringifyAttributes(log.attributes)}-${index}`
}

function logIdentity(log: SystemLogLine) {
  return `${log.timestamp}\u0000${log.level}\u0000${log.message}\u0000${stringifyAttributes(log.attributes)}`
}

function mergeLogLines(currentLogs: SystemLogLine[], incomingLogs: SystemLogLine[]) {
  if (incomingLogs.length === 0) {
    return currentLogs
  }

  const mergedByKey = new Map<string, SystemLogLine>()
  for (const log of currentLogs) {
    mergedByKey.set(logIdentity(log), log)
  }
  for (const log of incomingLogs) {
    mergedByKey.set(logIdentity(log), log)
  }

  return Array.from(mergedByKey.values()).sort(compareLogTimestamps)
}

function isTerminalScrolledToBottom(terminal: HTMLDivElement) {
  const distanceFromBottom = terminal.scrollHeight - terminal.scrollTop - terminal.clientHeight
  return distanceFromBottom <= AUTO_SCROLL_BOTTOM_THRESHOLD_PX
}

function normalizeOlderLogsError(error: unknown) {
  if (error instanceof Error && error.message.trim() !== '') {
    return `Could not load older logs: ${error.message}`
  }
  return 'Could not load older logs.'
}
