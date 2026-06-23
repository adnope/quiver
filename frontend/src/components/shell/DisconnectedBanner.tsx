import { Button } from '@/components/ui/button'
import { MaterialIcon } from '@/components/shell/MaterialIcon'

interface DisconnectedBannerProps {
  visible: boolean
  onRetry: () => void
}

export function DisconnectedBanner({ visible, onRetry }: DisconnectedBannerProps) {
  if (!visible) {
    return null
  }

  return (
    <div className="sticky top-14 z-30 flex min-h-10 items-center justify-between border-b border-red-500/30 bg-red-950/80 px-4 text-sm text-red-100 backdrop-blur md:px-6">
      <div className="flex items-center gap-2">
        <MaterialIcon name="warning" className="text-red-300" />
        <span>Disconnected from Quiver backend. Retrying connection...</span>
      </div>
      <Button type="button" variant="danger" size="sm" onClick={onRetry}>
        Retry
      </Button>
    </div>
  )
}
