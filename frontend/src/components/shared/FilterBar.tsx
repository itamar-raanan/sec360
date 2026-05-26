import React, { useState, useRef, useEffect } from 'react'
import { Search, ChevronDown, X } from 'lucide-react'

export interface FilterOption {
  value: string
  label: string
  count?: number
}

export interface FilterGroup {
  id: string
  label: string
  options: FilterOption[]
  selected: string[]
  onToggle: (value: string) => void
  onClear: () => void
}

interface FilterBarProps {
  search: string
  onSearchChange: (v: string) => void
  searchPlaceholder?: string
  groups: FilterGroup[]
  activeCount: number
  onClearAll: () => void
  totalLabel?: string
}

function Dropdown({ group, onClose }: { group: FilterGroup; onClose: () => void }) {
  return (
    <div
      className="absolute top-full left-0 mt-1.5 z-50 rounded-xl overflow-hidden min-w-[180px]"
      style={{ background: 'var(--surface-2)', border: '1px solid var(--border-mid)', boxShadow: '0 12px 32px rgba(0,0,0,0.5)' }}
    >
      {group.options.map(opt => {
        const active = group.selected.includes(opt.value)
        return (
          <button
            key={opt.value}
            onClick={() => group.onToggle(opt.value)}
            className="w-full flex items-center gap-2.5 px-3 py-2 text-left transition-[background-color] duration-100"
            style={{ background: active ? 'rgba(16,185,129,0.08)' : 'transparent' }}
            onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--hover-1)' }}
            onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent' }}
          >
            {/* checkbox */}
            <span
              className="w-3.5 h-3.5 rounded flex-shrink-0 flex items-center justify-center border transition-colors"
              style={{
                background: active ? 'var(--accent)' : 'transparent',
                borderColor: active ? 'var(--accent)' : 'rgba(255,255,255,0.2)',
              }}
            >
              {active && (
                <svg width="8" height="8" viewBox="0 0 8 8" fill="none">
                  <path d="M1.5 4l2 2 3-3" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              )}
            </span>
            <span className="flex-1 text-xs" style={{ color: active ? '#d1fae5' : '#a1a1aa' }}>{opt.label}</span>
            {opt.count !== undefined && (
              <span className="text-[10px] tabular-nums flex-shrink-0" style={{ color: 'var(--text-4)' }}>{opt.count}</span>
            )}
          </button>
        )
      })}
      {group.selected.length > 0 && (
        <div style={{ borderTop: '1px solid var(--border)' }}>
          <button
            onClick={() => { group.onClear(); onClose() }}
            className="w-full flex items-center justify-center gap-1 px-3 py-1.5 text-xs text-red-400 hover:bg-red-500/10 transition-[background-color]"
          >
            <X size={10} /> Clear
          </button>
        </div>
      )}
    </div>
  )
}

export default function FilterBar({
  search, onSearchChange, searchPlaceholder = 'Search…',
  groups, activeCount, onClearAll, totalLabel,
}: FilterBarProps) {
  const [openGroup, setOpenGroup] = useState<string | null>(null)
  const barRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (barRef.current && !barRef.current.contains(e.target as Node)) setOpenGroup(null)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  // Collect all active chips
  const activeChips = groups.flatMap(g =>
    g.selected.map(val => ({
      groupId: g.id,
      groupLabel: g.label,
      value: val,
      label: g.options.find(o => o.value === val)?.label ?? val,
      onRemove: () => g.onToggle(val),
    }))
  )

  return (
    <div
      ref={barRef}
      className="flex-shrink-0"
      style={{ borderBottom: '1px solid var(--border)' }}
    >
      {/* Main bar */}
      <div className="flex items-center gap-2 px-4 py-2.5 flex-wrap">
        {/* Search */}
        <div className="relative flex-shrink-0" style={{ minWidth: 200 }}>
          <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={e => onSearchChange(e.target.value)}
            placeholder={searchPlaceholder}
            className="w-full rounded-lg pl-8 pr-3 py-1.5 text-xs focus:outline-none"
            style={{
              background: 'var(--surface-3)',
              border: '1px solid var(--border)',
              color: 'var(--text-1)',
              transition: 'border-color 120ms ease',
            }}
            onFocus={e => (e.target.style.borderColor = 'rgba(16,185,129,0.5)')}
            onBlur={e => (e.target.style.borderColor = 'var(--border)')}
          />
        </div>

        <div className="w-px h-5 bg-white/[0.08] flex-shrink-0 mx-1" />

        {/* Filter group buttons */}
        {groups.map(group => {
          const isOpen = openGroup === group.id
          const hasActive = group.selected.length > 0
          return (
            <div key={group.id} className="relative flex-shrink-0">
              <button
                onClick={() => setOpenGroup(isOpen ? null : group.id)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-[background-color,border-color] duration-120"
                style={{
                  background: hasActive ? 'rgba(16,185,129,0.10)' : 'var(--surface-3)',
                  border: `1px solid ${hasActive ? 'rgba(16,185,129,0.35)' : 'var(--border)'}`,
                  color: hasActive ? '#6ee7b7' : '#71717a',
                }}
              >
                {group.label}
                {hasActive && (
                  <span
                    className="flex items-center justify-center w-4 h-4 rounded-full text-[10px] font-bold"
                    style={{ background: 'rgba(16,185,129,0.25)', color: '#34d399' }}
                  >
                    {group.selected.length}
                  </span>
                )}
                <ChevronDown size={11} className={`transition-transform duration-150 ${isOpen ? 'rotate-180' : ''}`} />
              </button>
              {isOpen && <Dropdown group={group} onClose={() => setOpenGroup(null)} />}
            </div>
          )
        })}

        {/* Clear all + total */}
        <div className="ml-auto flex items-center gap-3 flex-shrink-0">
          {totalLabel && (
            <span className="text-[11px] tabular-nums" style={{ color: 'var(--text-4)' }}>{totalLabel}</span>
          )}
          {activeCount > 0 && (
            <button
              onClick={onClearAll}
              className="flex items-center gap-1 text-xs text-red-400 hover:text-red-300 transition-[color] duration-120"
            >
              <X size={11} /> Clear {activeCount}
            </button>
          )}
        </div>
      </div>

      {/* Active chips row */}
      {activeChips.length > 0 && (
        <div className="flex items-center gap-1.5 px-4 pb-2 flex-wrap">
          {activeChips.map(chip => (
            <button
              key={`${chip.groupId}-${chip.value}`}
              onClick={chip.onRemove}
              className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium transition-[background-color] duration-100 group"
              style={{ background: 'rgba(16,185,129,0.10)', border: '1px solid rgba(16,185,129,0.25)', color: '#6ee7b7' }}
              onMouseEnter={e => (e.currentTarget.style.background = 'rgba(16,185,129,0.18)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'rgba(16,185,129,0.10)')}
            >
              <span className="opacity-60">{chip.groupLabel}:</span> {chip.label}
              <X size={9} className="ml-0.5 opacity-60 group-hover:opacity-100" />
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
