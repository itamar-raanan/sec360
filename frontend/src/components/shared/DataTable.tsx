import React, { useState } from 'react'
import { ChevronUp, ChevronDown, ChevronsUpDown, Inbox } from 'lucide-react'

export interface Column<T> {
  key: string
  header: string
  sortable?: boolean
  render: (row: T) => React.ReactNode
  width?: string
}

interface DataTableProps<T> {
  columns: Column<T>[]
  data: T[]
  loading?: boolean
  onRowClick?: (row: T) => void
  keyExtractor: (row: T) => string
  emptyMessage?: string
  pagination?: {
    page: number
    pageSize: number
    total: number
    onPageChange: (page: number) => void
  }
}

export default function DataTable<T>({
  columns,
  data,
  loading,
  onRowClick,
  keyExtractor,
  emptyMessage = 'No data',
  pagination,
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')

  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const sortedData = [...data].sort((a, b) => {
    if (!sortKey) return 0
    const aVal = (a as Record<string, unknown>)[sortKey]
    const bVal = (b as Record<string, unknown>)[sortKey]
    if (aVal === bVal) return 0
    if (aVal == null) return 1
    if (bVal == null) return -1
    const cmp = aVal < bVal ? -1 : 1
    return sortDir === 'asc' ? cmp : -cmp
  })

  const totalPages = pagination ? Math.ceil(pagination.total / pagination.pageSize) : 1

  return (
    <div className="flex flex-col gap-3">
      <div className="overflow-x-auto rounded-xl" style={{ border: '1px solid var(--border)' }}>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border)', background: 'rgba(255,255,255,0.015)' }}>
              {columns.map((col) => (
                <th
                  key={col.key}
                  className={`px-4 py-3 text-left ${col.width || ''} ${col.sortable ? 'cursor-pointer select-none' : ''}`}
                  style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-4)', textTransform: 'uppercase', letterSpacing: '0.08em' }}
                  onClick={col.sortable ? () => handleSort(col.key) : undefined}
                >
                  <div className="flex items-center gap-1">
                    {col.header}
                    {col.sortable && (
                      <span style={{ color: 'var(--text-4)' }}>
                        {sortKey === col.key ? (
                          sortDir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />
                        ) : (
                          <ChevronsUpDown size={12} />
                        )}
                      </span>
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 6 }).map((_, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                  {columns.map((col, j) => (
                    <td key={col.key} className="px-4 py-3.5">
                      <div
                        className="h-3.5 shimmer rounded-md"
                        style={{
                          width: j === 0 ? '55%' : j === columns.length - 1 ? '35%' : `${65 - j * 5}%`,
                          animationDelay: `${i * 60 + j * 20}ms`,
                        }}
                      />
                    </td>
                  ))}
                </tr>
              ))
            ) : sortedData.length === 0 ? (
              <tr>
                <td colSpan={columns.length}>
                  <div className="flex flex-col items-center justify-center gap-3 py-16">
                    <div
                      className="w-10 h-10 rounded-full flex items-center justify-center"
                      style={{ background: 'var(--surface-3)' }}
                    >
                      <Inbox size={17} style={{ color: 'var(--text-4)' }} />
                    </div>
                    <div className="text-center">
                      <p className="text-sm font-medium" style={{ color: 'var(--text-3)' }}>{emptyMessage}</p>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--text-4)' }}>No records match the current filters</p>
                    </div>
                  </div>
                </td>
              </tr>
            ) : (
              sortedData.map((row, i) => (
                <tr
                  key={keyExtractor(row)}
                  className={`fade-up ${onRowClick ? 'cursor-pointer' : ''}`}
                  style={{
                    borderBottom: '1px solid var(--border)',
                    animationDelay: `${i * 20}ms`,
                    transition: 'background-color 120ms ease',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--hover-2)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                >
                  {columns.map((col) => (
                    <td key={col.key} className="px-4 py-3" style={{ color: 'var(--text-2)' }}>
                      {col.render(row)}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {pagination && totalPages > 1 && (
        <div className="flex items-center justify-between px-1">
          <span className="text-xs tabular-nums" style={{ color: 'var(--text-4)' }}>
            {Math.min((pagination.page - 1) * pagination.pageSize + 1, pagination.total)}–{Math.min(pagination.page * pagination.pageSize, pagination.total)} of {pagination.total}
          </span>
          <div className="flex items-center gap-1">
            <button
              disabled={pagination.page <= 1}
              onClick={() => pagination.onPageChange(pagination.page - 1)}
              className="px-3 py-1.5 text-xs rounded-lg pressable disabled:opacity-30 disabled:cursor-not-allowed"
              style={{ background: 'var(--surface-3)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
            >
              Prev
            </button>
            {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
              const p = Math.max(1, Math.min(pagination.page - 2, totalPages - 4)) + i
              const active = p === pagination.page
              return (
                <button
                  key={p}
                  onClick={() => pagination.onPageChange(p)}
                  className="px-3 py-1.5 text-xs rounded-lg pressable tabular-nums"
                  style={active
                    ? { background: 'var(--accent)', border: '1px solid transparent', color: '#fff', fontWeight: 600 }
                    : { background: 'var(--surface-3)', border: '1px solid var(--border)', color: 'var(--text-3)' }
                  }
                >
                  {p}
                </button>
              )
            })}
            <button
              disabled={pagination.page >= totalPages}
              onClick={() => pagination.onPageChange(pagination.page + 1)}
              className="px-3 py-1.5 text-xs rounded-lg pressable disabled:opacity-30 disabled:cursor-not-allowed"
              style={{ background: 'var(--surface-3)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
