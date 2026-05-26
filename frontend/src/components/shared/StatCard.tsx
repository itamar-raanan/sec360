import React from 'react'
import type { LucideIcon } from 'lucide-react'

interface StatCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon: LucideIcon
  iconColor?: string
  trend?: { value: number; label?: string }
  loading?: boolean
  onClick?: () => void
  className?: string
  style?: React.CSSProperties
}

export default function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  iconColor = 'text-emerald-400',
  trend,
  loading,
  onClick,
  className,
  style,
}: StatCardProps) {
  return (
    <div
      className={`relative overflow-hidden rounded-xl p-5 fade-up ${
        onClick ? 'cursor-pointer pressable card card-interactive' : 'card'
      } ${className ?? ''}`}
      style={style}
      onClick={onClick}
    >
      {/* Subtle top accent line */}
      <div
        className={`absolute top-0 left-0 right-0 h-px ${iconColor.replace('text-', 'bg-').split(' ')[0]}`}
        style={{ opacity: 0.4 }}
      />

      <div className="flex items-center justify-between gap-3 mb-3">
        <span className="text-[10px] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--surface-6, #52525e)' }}>
          {title}
        </span>
        <div className={`${iconColor} opacity-60`}>
          <Icon size={14} strokeWidth={2} />
        </div>
      </div>

      {loading ? (
        <div className="space-y-2.5">
          <div className="h-8 w-20 shimmer rounded-md" />
          <div className="h-3 w-32 shimmer rounded opacity-60" />
        </div>
      ) : (
        <div>
          <div className="flex items-baseline gap-2">
            <span className="text-[28px] font-bold leading-none tabular-nums tracking-tight" style={{ color: 'var(--text-1)' }}>
              {value}
            </span>
            {trend && (
              <span className={`text-xs font-semibold tabular-nums ${trend.value >= 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                {trend.value >= 0 ? '↑' : '↓'}{Math.abs(trend.value)}%
                {trend.label && (
                  <span className="font-normal ml-1" style={{ color: 'var(--text-4)' }}>{trend.label}</span>
                )}
              </span>
            )}
          </div>
          {subtitle && (
            <p className="text-[12px] mt-1.5 leading-relaxed" style={{ color: 'var(--text-4)' }}>
              {subtitle}
            </p>
          )}
        </div>
      )}
    </div>
  )
}
