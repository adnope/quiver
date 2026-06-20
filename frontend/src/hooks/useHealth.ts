import { useQuery } from '@tanstack/react-query'
import { getHealth } from '@/lib/api-client'
import { useAppStore } from '@/store/app-store'

export function useHealth() {
  const apiBaseUrl = useAppStore((state) => state.apiBaseUrl)
  const apiKey = useAppStore((state) => state.apiKey)

  return useQuery({
    queryKey: ['health', apiBaseUrl, Boolean(apiKey)],
    queryFn: ({ signal }) => getHealth({ baseUrl: apiBaseUrl, apiKey, signal }),
    refetchInterval: 5_000,
    retry: 2,
    staleTime: 2_000,
  })
}
