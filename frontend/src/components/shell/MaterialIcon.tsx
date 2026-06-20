import { cn } from '@/lib/utils'

interface MaterialIconProps {
  name: string
  className?: string
  title?: string
}

export function MaterialIcon({ name, className, title }: MaterialIconProps) {
  return (
    <span
      aria-hidden={title ? undefined : true}
      aria-label={title}
      className={cn('material-symbols-rounded select-none text-[20px] leading-none', className)}
    >
      {name}
    </span>
  )
}
