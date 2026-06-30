import type { UseQueryResult } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import { MaterialIcon } from '@/components/shell/MaterialIcon'
import { routeForTab } from '@/lib/routes'
import { useAppStore } from '@/store/app-store'
import type { DetailedHealthResponse, HealthResponse } from '@/types/api'

interface TopNavProps {
  health: UseQueryResult<HealthResponse | DetailedHealthResponse>
  onOpenSettings: () => void
}

const tabs = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'history', label: 'History' },
  { id: 'explorer', label: 'Flow Explorer' },
  { id: 'analytics', label: 'Analytics' },
  { id: 'logs', label: 'Logs' },
] as const

export function TopNav({ health, onOpenSettings }: TopNavProps) {
  const activeTab = useAppStore((state) => state.activeTab)
  const setActiveTab = useAppStore((state) => state.setActiveTab)
  const theme = useAppStore((state) => state.theme)
  const setTheme = useAppStore((state) => state.setTheme)

  function navigate(tab: (typeof tabs)[number]['id']) {
    const nextRoute = routeForTab(tab)
    if (window.location.pathname !== nextRoute) {
      window.history.pushState(null, '', nextRoute)
    }
    setActiveTab(tab)
  }

  const healthStatus = health.data?.status ?? (health.isError ? 'fail' : 'degraded')
  const statusLabel =
    healthStatus === 'ok' ? 'Healthy' : healthStatus === 'degraded' ? 'Degraded' : 'Error'

  return (
    <header className="fixed left-0 right-0 top-0 z-40 h-14 border-b border-[var(--border)] bg-[var(--nav)] backdrop-blur">
      <div className="flex h-full items-center justify-between gap-3 px-4 md:px-6">
        <div className="flex min-w-0 items-center gap-4">
          <div className="flex shrink-0 items-center gap-2">
            <img src="/quiver.png" alt="Quiver Logo" className="size-7 object-contain" />
            <span className="text-sm font-semibold tracking-normal text-[var(--text-primary)]">
              Quiver
            </span>
          </div>

          <nav className="hidden items-center gap-1 md:flex">
            {tabs.map((tab) => (
              <Button
                key={tab.id}
                type="button"
                size="sm"
                variant={activeTab === tab.id ? 'primary' : 'ghost'}
                onClick={() => navigate(tab.id)}
              >
                {tab.label}
              </Button>
            ))}
          </nav>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <div className="hidden h-9 items-center gap-2 px-3 text-[11px] uppercase tracking-normal text-[var(--text-secondary)] sm:flex">
            <span className={healthClass(healthStatus)} />
            <span className="font-mono normal-case tracking-normal">API: {statusLabel}</span>
          </div>

          <Button
            type="button"
            variant="ghost"
            size="icon"
            aria-label="Toggle theme"
            title="Toggle theme"
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          >
            <MaterialIcon name={theme === 'dark' ? 'dark_mode' : 'light_mode'} />
          </Button>

          <Button
            type="button"
            variant="ghost"
            size="icon"
            aria-label="API settings"
            title="API settings"
            onClick={onOpenSettings}
          >
            <MaterialIcon name="settings" />
          </Button>
        </div>
      </div>
    </header>
  )
}

function healthClass(status: string) {
  if (status === 'ok') {
    return 'h-4 w-1 rounded-full bg-emerald-300 shadow-[0_0_14px_rgba(110,231,183,0.35)]'
  }
  if (status === 'degraded') {
    return 'h-4 w-1 rounded-full bg-amber-300'
  }
  return 'h-4 w-1 rounded-full bg-red-400'
}
