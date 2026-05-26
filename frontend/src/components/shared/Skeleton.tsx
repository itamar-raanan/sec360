import React from 'react'

interface SkeletonProps {
  className?: string
  style?: React.CSSProperties
}

export function Skeleton({ className = '', style }: SkeletonProps) {
  return (
    <div
      className={`shimmer rounded-md ${className}`}
      style={style}
      aria-hidden
    />
  )
}

export function SkeletonDetailPanel() {
  return (
    <div className="p-5 space-y-5 animate-fade-in">
      <div className="flex items-center gap-3">
        <Skeleton className="w-12 h-12 rounded-full" />
        <div className="space-y-2 flex-1">
          <Skeleton className="h-4 w-36" />
          <Skeleton className="h-3 w-52 opacity-60" />
        </div>
      </div>
      <div className="space-y-2 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex items-center justify-between py-1">
            <Skeleton className="h-3 w-24 opacity-50" />
            <Skeleton className="h-3 w-32" style={{ animationDelay: `${i * 60}ms` }} />
          </div>
        ))}
      </div>
      <div className="space-y-2 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
        <Skeleton className="h-3 w-20 opacity-40" />
        <div className="grid grid-cols-2 gap-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-8 rounded-lg" style={{ animationDelay: `${i * 40}ms` }} />
          ))}
        </div>
      </div>
    </div>
  )
}

export function SkeletonRows({ count = 5, cols = 3 }: { count?: number; cols?: number }) {
  return (
    <div className="space-y-px">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-4 py-3.5" style={{ borderBottom: '1px solid var(--border)' }}>
          <Skeleton className="w-8 h-8 rounded-full flex-shrink-0" style={{ animationDelay: `${i * 40}ms` }} />
          {Array.from({ length: cols }).map((__, j) => (
            <Skeleton
              key={j}
              className="h-3.5 rounded"
              style={{
                width: j === 0 ? '30%' : j === cols - 1 ? '15%' : `${40 - j * 5}%`,
                animationDelay: `${i * 40 + j * 15}ms`,
              }}
            />
          ))}
        </div>
      ))}
    </div>
  )
}

export function SkeletonEventRows({ count = 8 }: { count?: number }) {
  return (
    <div className="space-y-1.5">
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className="flex items-start gap-4 p-3.5 rounded-xl"
          style={{ animationDelay: `${i * 35}ms`, background: 'var(--surface-2)', border: '1px solid var(--border)' }}
        >
          <Skeleton className="w-9 h-9 rounded-lg flex-shrink-0" style={{ animationDelay: `${i * 35}ms` }} />
          <div className="flex-1 space-y-2">
            <div className="flex gap-2">
              <Skeleton className="h-3.5 w-28" style={{ animationDelay: `${i * 35 + 20}ms` }} />
              <Skeleton className="h-3.5 w-16 opacity-60" style={{ animationDelay: `${i * 35 + 30}ms` }} />
            </div>
            <Skeleton className="h-3 w-40 opacity-40" style={{ animationDelay: `${i * 35 + 40}ms` }} />
          </div>
          <Skeleton className="h-3 w-20 opacity-50" style={{ animationDelay: `${i * 35 + 50}ms` }} />
        </div>
      ))}
    </div>
  )
}
