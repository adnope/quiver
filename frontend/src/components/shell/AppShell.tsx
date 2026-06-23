import { Suspense, lazy, useEffect, useMemo, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ApiSettingsDialog } from '@/components/shell/ApiSettingsDialog'
import { DisconnectedBanner } from '@/components/shell/DisconnectedBanner'
import { TopNav } from '@/components/shell/TopNav'
import { useHealth } from '@/hooks/useHealth'
import { applyThemePreference, useAppStore } from '@/store/app-store'

const DashboardView = lazy(() =>
  import('@/components/dashboard/DashboardView').then((module) => ({
    default: module.DashboardView,
  })),
)
const ExplorerView = lazy(() =>
  import('@/components/explorer/ExplorerView').then((module) => ({
    default: module.ExplorerView,
  })),
)
const AnalyticsView = lazy(() =>
  import('@/components/analytics/AnalyticsView').then((module) => ({
    default: module.AnalyticsView,
  })),
)

export function AppShell() {
  const queryClient = useQueryClient()
  const activeTab = useAppStore((state) => state.activeTab)
  const theme = useAppStore((state) => state.theme)
  const apiBaseUrl = useAppStore((state) => state.apiBaseUrl)
  const apiKey = useAppStore((state) => state.apiKey)
  const health = useHealth()
  const [settingsOpen, setSettingsOpen] = useState(false)
  const shouldPromptSettings = !apiKey || (health.isError && apiBaseUrl === '')

  useEffect(() => {
    applyThemePreference(theme)
  }, [theme])

  const mainContent = useMemo(() => {
    if (activeTab === 'dashboard') {
      return <DashboardView />
    }
    if (activeTab === 'analytics') {
      return <AnalyticsView />
    }
    return <ExplorerView />
  }, [activeTab])

  return (
    <div className="min-h-svh bg-[var(--app-bg)] text-[var(--text-primary)]">
      <TopNav
        health={health}
        onOpenSettings={() => setSettingsOpen(true)}
      />
      <DisconnectedBanner
        visible={health.isError}
        onRetry={() => void queryClient.invalidateQueries({ queryKey: ['health'] })}
      />

      <main className="mx-auto w-full max-w-[1440px] px-4 pb-6 pt-[72px] md:px-6">
        {activeTab === 'dashboard' ? (
          <div className="mb-4 flex items-end justify-between gap-4">
            <div>
              <h1 className="text-lg font-semibold tracking-normal text-[var(--text-primary)]">
                Dashboard
              </h1>
              <p className="mt-1 text-sm text-[var(--text-secondary)]">
                Live metrics and historical telemetry
              </p>
            </div>
          </div>
        ) : null}

        <Suspense fallback={<ViewSkeleton />}>
          {mainContent}
        </Suspense>
      </main>

      <ApiSettingsDialog
        open={settingsOpen || shouldPromptSettings}
        onOpenChange={setSettingsOpen}
      />
    </div>
  )
}

function ViewSkeleton() {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {[0, 1, 2, 3].map((item) => (
        <div
          key={item}
          className="h-72 animate-pulse rounded-lg border border-[var(--border)] bg-[var(--panel)]"
        />
      ))}
    </div>
  )
}
