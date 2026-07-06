import { useLayoutEffect, useRef, type FormEvent, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import { MaterialIcon } from '@/components/shell/MaterialIcon'
import type { AdvancedFilters } from './advanced-search'

interface AdvancedSearchPanelProps {
  filters: AdvancedFilters
  activeCount: number
  error: string
  open: boolean
  onChange: <K extends keyof AdvancedFilters>(key: K, value: AdvancedFilters[K]) => void
  onApply: (event: FormEvent<HTMLFormElement>) => void
  onClear: () => void
  onOpenChange: (open: boolean) => void
  onExpandedHeightChange: (height: number) => void
}

const inputClass =
  'h-9 min-w-0 rounded-md border border-[var(--border)] bg-[var(--input)] px-3 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500'

export function AdvancedSearchPanel({
  filters,
  activeCount,
  error,
  open,
  onChange,
  onApply,
  onClear,
  onOpenChange,
  onExpandedHeightChange,
}: AdvancedSearchPanelProps) {
  const formRef = useRef<HTMLFormElement>(null)

  useLayoutEffect(() => {
    if (!open || !formRef.current) {
      onExpandedHeightChange(0)
      return
    }

    const form = formRef.current
    const updateHeight = () =>
      onExpandedHeightChange(Math.ceil(form.getBoundingClientRect().height))
    updateHeight()
    const observer = new ResizeObserver(updateHeight)
    observer.observe(form)
    return () => observer.disconnect()
  }, [onExpandedHeightChange, open])

  return (
    <details
      className="w-full rounded-md border border-[var(--border)] bg-[var(--panel)]"
      open={open}
      onToggle={(event) => onOpenChange(event.currentTarget.open)}
    >
      <summary className="flex h-9 cursor-pointer list-none items-center justify-between gap-3 px-3 text-xs font-medium text-[var(--text-primary)] hover:bg-[var(--panel-hover)]">
        <span className="flex items-center gap-2">
          <MaterialIcon name="tune" className="text-[18px] text-[var(--text-secondary)]" />
          Advanced search
          {activeCount > 0 ? (
            <span className="rounded-full bg-sky-500/15 px-2 py-0.5 text-[11px] text-sky-400">
              {activeCount} active
            </span>
          ) : null}
        </span>
        <span className="text-[11px] font-normal text-amber-400">
          Unindexed filters may be slow
        </span>
      </summary>
      <form
        ref={formRef}
        className="space-y-3 border-t border-[var(--border)] p-3"
        onSubmit={onApply}
      >
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          <AdvancedField label="Attributes contains" className="xl:col-span-2">
            <input
              className={inputClass}
              maxLength={256}
              placeholder="Literal text in attributes JSON"
              value={filters.attributesContains}
              onChange={(event) => onChange('attributesContains', event.target.value)}
            />
          </AdvancedField>
          <AdvancedField label="Source host">
            <input
              className={inputClass}
              placeholder="Exact source host"
              value={filters.sourceHost}
              onChange={(event) => onChange('sourceHost', event.target.value)}
            />
          </AdvancedField>
          <AdvancedField label="Collector source IP">
            <input
              className={inputClass}
              placeholder="IPv4 or IPv6"
              value={filters.sourceIp}
              onChange={(event) => onChange('sourceIp', event.target.value)}
            />
          </AdvancedField>
          <AdvancedField label="Next-hop IP">
            <input
              className={inputClass}
              placeholder="IPv4 or IPv6"
              value={filters.nextHopIp}
              onChange={(event) => onChange('nextHopIp', event.target.value)}
            />
          </AdvancedField>
          <AdvancedRangeField
            label="Bytes"
            from={filters.bytesFrom}
            to={filters.bytesTo}
            onFromChange={(value) => onChange('bytesFrom', value)}
            onToChange={(value) => onChange('bytesTo', value)}
          />
          <AdvancedRangeField
            label="Packets"
            from={filters.packetsFrom}
            to={filters.packetsTo}
            onFromChange={(value) => onChange('packetsFrom', value)}
            onToChange={(value) => onChange('packetsTo', value)}
          />
          <AdvancedRangeField
            label="Duration (ms)"
            from={filters.durationMsFrom}
            to={filters.durationMsTo}
            onFromChange={(value) => onChange('durationMsFrom', value)}
            onToChange={(value) => onChange('durationMsTo', value)}
          />
          <AdvancedField label="Flow state">
            <input
              className={inputClass}
              maxLength={128}
              placeholder="Exact state"
              value={filters.flowState}
              onChange={(event) => onChange('flowState', event.target.value)}
            />
          </AdvancedField>
          <AdvancedField label="TCP flags">
            <input
              className={inputClass}
              inputMode="numeric"
              placeholder="0-65535"
              value={filters.tcpFlags}
              onChange={(event) => onChange('tcpFlags', event.target.value)}
            />
          </AdvancedField>
          <AdvancedField label="Input interface">
            <input
              className={inputClass}
              inputMode="numeric"
              placeholder="Interface ID"
              value={filters.inputInterface}
              onChange={(event) => onChange('inputInterface', event.target.value)}
            />
          </AdvancedField>
          <AdvancedField label="Output interface">
            <input
              className={inputClass}
              inputMode="numeric"
              placeholder="Interface ID"
              value={filters.outputInterface}
              onChange={(event) => onChange('outputInterface', event.target.value)}
            />
          </AdvancedField>
          <AdvancedField label="Sampling rate">
            <input
              className={inputClass}
              inputMode="numeric"
              placeholder="Positive integer"
              value={filters.samplingRate}
              onChange={(event) => onChange('samplingRate', event.target.value)}
            />
          </AdvancedField>
          <AdvancedField label="IP version">
            <select
              className={inputClass}
              value={filters.ipVersion}
              onChange={(event) => onChange('ipVersion', event.target.value as '' | '4' | '6')}
            >
              <option value="">Any</option>
              <option value="4">IPv4</option>
              <option value="6">IPv6</option>
            </select>
          </AdvancedField>
          <AdvancedField label="Normalization status">
            <select
              className={inputClass}
              value={filters.normalizationStatus}
              onChange={(event) =>
                onChange('normalizationStatus', event.target.value as '' | 'ok' | 'partial')
              }
            >
              <option value="">Any</option>
              <option value="ok">OK</option>
              <option value="partial">Partial</option>
            </select>
          </AdvancedField>
          <AdvancedField label="Normalization error contains" className="xl:col-span-2">
            <input
              className={inputClass}
              maxLength={256}
              placeholder="Literal error text"
              value={filters.normalizationErrorContains}
              onChange={(event) => onChange('normalizationErrorContains', event.target.value)}
            />
          </AdvancedField>
        </div>
        <div className="flex min-h-8 items-center justify-between gap-3">
          <span className="text-xs font-medium text-red-400">{error}</span>
          <div className="flex items-center gap-2">
            <Button type="button" size="sm" variant="secondary" onClick={onClear}>
              Clear
            </Button>
            <Button type="submit" size="sm" variant="primary" disabled={Boolean(error)}>
              Apply advanced filters
            </Button>
          </div>
        </div>
      </form>
    </details>
  )
}

function AdvancedField({
  label,
  className,
  children,
}: {
  label: string
  className?: string
  children: ReactNode
}) {
  return (
    <label className={`grid gap-1 text-xs text-[var(--text-secondary)] ${className ?? ''}`}>
      {label}
      {children}
    </label>
  )
}

function AdvancedRangeField({
  label,
  from,
  to,
  onFromChange,
  onToChange,
}: {
  label: string
  from: string
  to: string
  onFromChange: (value: string) => void
  onToChange: (value: string) => void
}) {
  return (
    <AdvancedField label={label}>
      <span className="grid grid-cols-[1fr_auto_1fr] items-center gap-2">
        <input
          className={inputClass}
          inputMode="numeric"
          placeholder="Min"
          value={from}
          onChange={(event) => onFromChange(event.target.value)}
        />
        <span>-</span>
        <input
          className={inputClass}
          inputMode="numeric"
          placeholder="Max"
          value={to}
          onChange={(event) => onToChange(event.target.value)}
        />
      </span>
    </AdvancedField>
  )
}
