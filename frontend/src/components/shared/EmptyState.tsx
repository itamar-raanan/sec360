import React from 'react'
import type { LucideIcon } from 'lucide-react'

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description?: string
  action?: { label: string; onClick: () => void }
  size?: 'sm' | 'md'
}

export default function EmptyState({ icon: Icon, title, description, action, size = 'md' }: EmptyStateProps) {
  return (
    <div
      className="flex flex-col items-center justify-center gap-3 text-center"
      style={{ padding: size === 'sm' ? '20px 16px' : '40px 16px' }}
    >
      <div
        className={`flex items-center justify-center flex-shrink-0 ${size === 'sm' ? 'w-9 h-9 rounded-xl' : 'w-12 h-12 rounded-2xl'}`}
        style={{ background: 'var(--surface-3)', border: '1px solid var(--border)' }}
      >
        <Icon size={size === 'sm' ? 15 : 20} className="text-zinc-500" strokeWidth={1.5} />
      </div>
      <div>
        <p className={`font-medium text-zinc-300 ${size === 'sm' ? 'text-xs' : 'text-sm'}`}>{title}</p>
        {description && (
          <p className={`mt-0.5 text-zinc-500 ${size === 'sm' ? 'text-[11px]' : 'text-xs'} max-w-[200px] leading-relaxed`}>
            {description}
          </p>
        )}
      </div>
      {action && (
        <button
          onClick={action.onClick}
          className="text-xs font-medium px-3 py-1.5 rounded-lg transition-opacity hover:opacity-80"
          style={{ background: 'var(--accent-dim)', color: 'var(--accent)', border: '1px solid var(--accent-ring)' }}
        >
          {action.label}
        </button>
      )}
    </div>
  )
}
