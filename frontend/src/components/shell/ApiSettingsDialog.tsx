import { useEffect, useState } from 'react'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { validateBackendSettings } from '@/lib/api-client'
import { useAppStore } from '@/store/app-store'
import { MaterialIcon } from '@/components/shell/MaterialIcon'

interface ApiSettingsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function ApiSettingsDialog({ open, onOpenChange }: ApiSettingsDialogProps) {
  const savedBaseUrl = useAppStore((state) => state.apiBaseUrl)
  const savedApiKey = useAppStore((state) => state.apiKey)
  const setApiBaseUrl = useAppStore((state) => state.setApiBaseUrl)
  const setApiKey = useAppStore((state) => state.setApiKey)
  const clearApiSettings = useAppStore((state) => state.clearApiSettings)
  const [baseUrl, setBaseUrl] = useState(savedBaseUrl)
  const [apiKeyValue, setApiKeyValue] = useState(savedApiKey)
  const [error, setError] = useState<string | undefined>()
  const [isValidating, setIsValidating] = useState(false)
  const [showApiKey, setShowApiKey] = useState(false)

  useEffect(() => {
    if (open) {
      setBaseUrl(savedBaseUrl)
      setApiKeyValue(savedApiKey)
      setError(undefined)
    }
  }, [open, savedBaseUrl, savedApiKey])

  async function save() {
    setIsValidating(true)
    setError(undefined)
    try {
      const validated = await validateBackendSettings({
        baseUrl,
        apiKey: apiKeyValue,
      })
      setApiBaseUrl(validated.baseUrl)
      setApiKey(validated.apiKey)
      setError(undefined)
      onOpenChange(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid API settings.')
    } finally {
      setIsValidating(false)
    }
  }

  function clear() {
    clearApiSettings()
    setBaseUrl('')
    setApiKeyValue('')
    setError(undefined)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Settings</DialogTitle>
          <DialogDescription>
            Configure the Quiver backend endpoint and scoped API key.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <label className="block space-y-1.5 text-sm">
            <span className="font-medium text-[var(--text-primary)]">Backend URL</span>
            <input
              className="h-9 w-full rounded-md border border-[var(--border)] bg-[var(--input)] px-3 text-sm text-[var(--text-primary)] outline-none transition focus:border-sky-500"
              placeholder="Same origin"
              value={baseUrl}
              onChange={(event) => {
                setBaseUrl(event.target.value)
                setError(undefined)
              }}
            />
          </label>

          <label className="block space-y-1.5 text-sm">
            <span className="font-medium text-[var(--text-primary)]">API Key</span>
            <div className="flex h-9 rounded-md border border-[var(--border)] bg-[var(--input)] transition focus-within:border-sky-500">
              <input
                className="min-w-0 flex-1 bg-transparent px-3 font-mono text-sm text-[var(--text-primary)] outline-none"
                type={showApiKey ? 'text' : 'password'}
                autoComplete="off"
                value={apiKeyValue}
                onChange={(event) => {
                  setApiKeyValue(event.target.value)
                  setError(undefined)
                }}
              />
              <button
                type="button"
                className="grid size-9 shrink-0 place-items-center text-[var(--text-secondary)] transition hover:text-[var(--text-primary)]"
                aria-label={showApiKey ? 'Hide API key' : 'Show API key'}
                title={showApiKey ? 'Hide API key' : 'Show API key'}
                onClick={() => setShowApiKey((current) => !current)}
              >
                <MaterialIcon name={showApiKey ? 'visibility_off' : 'visibility'} />
              </button>
            </div>
          </label>

          {error ? (
            <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
              {error}
            </div>
          ) : null}

          <div className="flex justify-between gap-2">
            <Button type="button" variant="ghost" onClick={clear}>
              Clear
            </Button>
            <div className="flex gap-2">
              <DialogClose asChild>
                <Button type="button" variant="secondary" onClick={() => onOpenChange(false)}>
                  Cancel
                </Button>
              </DialogClose>
              <Button
                type="button"
                variant="primary"
                disabled={isValidating}
                onClick={() => void save()}
              >
                {isValidating ? 'Validating...' : 'Save'}
              </Button>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
