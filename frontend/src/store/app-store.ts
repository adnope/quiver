import { create } from 'zustand'
import { createJSONStorage, persist } from 'zustand/middleware'
import type { ActiveTab, ThemePreference } from '@/types/api'

interface AppState {
  activeTab: ActiveTab
  theme: ThemePreference
  apiBaseUrl: string
  apiKey: string
  lastApiLatency: number | null
  setActiveTab: (tab: ActiveTab) => void
  setTheme: (theme: ThemePreference) => void
  setApiBaseUrl: (url: string) => void
  setApiKey: (key: string) => void
  clearApiSettings: () => void
  setLastApiLatency: (latency: number | null) => void
}

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      activeTab: 'dashboard',
      theme: 'dark',
      apiBaseUrl: '',
      apiKey: '',
      lastApiLatency: null,
      setActiveTab: (activeTab) => set({ activeTab }),
      setTheme: (theme) => set({ theme }),
      setApiBaseUrl: (apiBaseUrl) => set({ apiBaseUrl }),
      setApiKey: (apiKey) => set({ apiKey }),
      clearApiSettings: () => set({ apiBaseUrl: '', apiKey: '' }),
      setLastApiLatency: (lastApiLatency) => set({ lastApiLatency }),
    }),

    {
      name: 'quiver-ui-settings',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        activeTab: state.activeTab,
        theme: state.theme,
        apiBaseUrl: state.apiBaseUrl,
        apiKey: state.apiKey,
      }),
    },
  ),
)

export function applyThemePreference(theme: ThemePreference) {
  const root = document.documentElement
  const resolved =
    theme === 'system'
      ? window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light'
      : theme

  root.dataset.theme = resolved
  root.style.colorScheme = resolved
}
