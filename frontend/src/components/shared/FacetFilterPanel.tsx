import React from 'react'
import { X, Search } from 'lucide-react'

export interface FacetValue {
  value: string
  label: string
  count: number
}

export interface FacetGroup {
  id: string
  label: string
  values: FacetValue[]
  selected: string
  onSelect: (v: string) => void
}

interface Props {
  search: string
  onSearchChange: (v: string) => void
  searchPlaceholder?: string
  groups: FacetGroup[]
  activeCount: number
  onClearAll: () => void
  onClose: () => void
}

export default function FacetFilterPanel({
  search,
  onSearchChange,
  searchPlaceholder = 'Search…',
  groups,
  activeCount,
  onClearAll,
  onClose,
}: Props) {
  return (
    <div
      className="flex flex-col flex-shrink-0 h-full overflow-hidden"
      style={{
        width: 220,
        background: 'var(--surface-2)',
        borderRight: '1px solid var(--border)',
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-3 py-2.5 flex-shrink-0"
        style={{ borderBottom: '1px solid var(--border)' }}
      >
        <span className="text-xs font-bold uppercase tracking-widest" style={{ color: 'var(--text-4)', letterSpacing: '0.1em' }}>
          Filters
        </span>
        <button
          onClick={onClose}
          className="flex items-center justify-center rounded"
          style={{ width: 18, height: 18, color: 'var(--text-4)', transition: 'color 120ms ease' }}
          onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-2)')}
          onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-4)')}
        >
          <X size={12} />
        </button>
      </div>

      {/* Search */}
      <div className="px-3 py-2.5 flex-shrink-0" style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="relative">
          <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-4)' }} />
          <input
            type="text"
            value={search}
            onChange={e => onSearchChange(e.target.value)}
            placeholder={searchPlaceholder}
            className="w-full rounded-md pl-7 pr-2.5 py-1.5 focus:outline-none"
            style={{
              fontSize: 11.5,
              background: 'var(--surface-3)',
              border: '1px solid var(--border)',
              color: 'var(--text-1)',
              transition: 'border-color 120ms ease',
            }}
            onFocus={e => (e.target.style.borderColor = 'rgba(16,185,129,0.5)')}
            onBlur={e => (e.target.style.borderColor = 'var(--border)')}
          />
        </div>
      </div>

      {/* Facet groups */}
      <div className="flex-1 overflow-y-auto">
        {groups.map((group, gi) => (
          <div
            key={group.id}
            style={{ borderBottom: gi < groups.length - 1 ? '1px solid var(--border)' : 'none' }}
          >
            {/* Group header */}
            <div
              className="px-3 pt-3 pb-1.5"
              style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: 'var(--text-4)', textTransform: 'uppercase' }}
            >
              {group.label}
            </div>

            {/* Values */}
            {group.values.map(fv => {
              const active = group.selected === fv.value
              return (
                <button
                  key={fv.value}
                  onClick={() => group.onSelect(active ? '' : fv.value)}
                  className="w-full flex items-center justify-between px-3 py-1.5 text-left"
                  style={{
                    fontSize: 12,
                    background: active ? 'rgba(16,185,129,0.08)' : 'transparent',
                    color: active ? '#6ee7b7' : '#71717a',
                    transition: 'background-color 100ms ease, color 100ms ease',
                    borderLeft: active ? '2px solid rgba(16,185,129,0.6)' : '2px solid transparent',
                  }}
                  onMouseEnter={e => {
                    if (!active) {
                      e.currentTarget.style.background = 'rgba(255,255,255,0.03)'
                      e.currentTarget.style.color = 'var(--text-2)'
                    }
                  }}
                  onMouseLeave={e => {
                    if (!active) {
                      e.currentTarget.style.background = 'transparent'
                      e.currentTarget.style.color = 'var(--text-3)'
                    }
                  }}
                >
                  <span className="truncate">{fv.label}</span>
                  <span
                    className="ml-2 flex-shrink-0 rounded-full tabular-nums"
                    style={{
                      fontSize: 10,
                      fontWeight: 600,
                      padding: '1px 6px',
                      background: active ? 'rgba(16,185,129,0.15)' : 'var(--shimmer-a)',
                      color: active ? '#34d399' : '#52525e',
                    }}
                  >
                    {fv.count}
                  </span>
                </button>
              )
            })}

            {/* All option */}
            <button
              onClick={() => group.onSelect('')}
              className="w-full flex items-center px-3 py-1.5 text-left mb-1"
              style={{
                fontSize: 11,
                color: group.selected === '' ? '#a1a1aa' : '#3f3f46',
                background: 'transparent',
                transition: 'color 100ms ease',
                borderLeft: '2px solid transparent',
              }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-3)')}
              onMouseLeave={e => (e.currentTarget.style.color = group.selected === '' ? '#a1a1aa' : '#3f3f46')}
            >
              Show all
            </button>
          </div>
        ))}
      </div>

      {/* Footer */}
      {activeCount > 0 && (
        <div
          className="flex-shrink-0 px-3 py-2.5"
          style={{ borderTop: '1px solid var(--border)' }}
        >
          <button
            onClick={onClearAll}
            className="w-full flex items-center justify-center gap-1.5 rounded-md py-1.5"
            style={{
              fontSize: 11,
              color: '#f87171',
              background: 'rgba(239,68,68,0.06)',
              border: '1px solid rgba(239,68,68,0.15)',
              transition: 'background-color 120ms ease',
            }}
            onMouseEnter={e => (e.currentTarget.style.background = 'rgba(239,68,68,0.10)')}
            onMouseLeave={e => (e.currentTarget.style.background = 'rgba(239,68,68,0.06)')}
          >
            <X size={10} />
            Clear all filters
          </button>
        </div>
      )}
    </div>
  )
}
