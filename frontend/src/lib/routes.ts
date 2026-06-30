import type { ActiveTab } from '@/types/api'

const ROUTES: Record<ActiveTab, string> = {
  dashboard: '/dashboard',
  history: '/history',
  explorer: '/flows',
  analytics: '/analytics',
  logs: '/logs',
}

export function routeForTab(tab: ActiveTab) {
  return ROUTES[tab]
}

export function tabFromPath(pathname: string): ActiveTab {
  const normalized = normalizePath(pathname)
  switch (normalized) {
    case '/history':
      return 'history'
    case '/flows':
      return 'explorer'
    case '/analytics':
      return 'analytics'
    case '/logs':
      return 'logs'
    case '/dashboard':
    case '/':
    default:
      return 'dashboard'
  }
}

export function isKnownRoute(pathname: string) {
  const normalized = normalizePath(pathname)
  return normalized === '/' || Object.values(ROUTES).includes(normalized)
}

function normalizePath(pathname: string) {
  const normalized = pathname.replace(/\/+$/, '')
  return normalized === '' ? '/' : normalized
}
