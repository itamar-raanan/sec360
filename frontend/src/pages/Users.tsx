import React, { useState, useMemo, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import {
  User, ChevronRight, UserX, UserCheck, ShieldOff,
  ArrowUp, ArrowDown, ChevronsUpDown, AlertTriangle, Download,
} from 'lucide-react'
import apiClient from '../api/client'
import RiskBadge from '../components/shared/RiskBadge'
import FilterBar, { type FilterGroup } from '../components/shared/FilterBar'
import { usePanelStore } from '../store/panels'
import type { User as UserType } from '../types'

function hasAnomaly(user: UserType): boolean {
  const jc = user.sources?.jumpcloud
  const gw = user.sources?.google
  if (!jc || !gw) return false
  const jcActive = jc.active && !jc.suspended
  const gwActive = gw.active && !gw.suspended
  if (jcActive !== gwActive) return true
  if (jc.mfa !== gw.mfa) return true
  return false
}

const RISK_SCORE_RANGES: Record<string, [number, number]> = {
  low: [0, 25], medium: [26, 50], high: [51, 75], critical: [76, 100],
}

function exportCSV(users: UserType[]) {
  const headers = ['Name', 'Email', 'Department', 'Job Title', 'Status', 'MFA', 'Risk Score', 'Last Login']
  const rows = users.map(u => [
    u.full_name,
    u.email,
    u.department ?? '',
    u.job_title ?? '',
    u.suspended ? 'Suspended' : u.employment_status,
    u.mfa_enabled ? 'Enabled' : 'Disabled',
    String(u.risk_score),
    u.last_login ? new Date(u.last_login).toISOString() : '',
  ])
  const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `users-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

type SortField = 'name' | 'last_active'
type SortDir   = 'asc' | 'desc'

interface Filters {
  search: string
  department: string[]
  risk: string[]
  status: string[]
  mfa: string[]
  endpoint: string[]
}

const EMPTY: Filters = { search: '', department: [], risk: [], status: [], mfa: [], endpoint: [] }

function SortBtn({
  label, field, current, dir, onClick,
}: {
  label: string; field: SortField; current: SortField; dir: SortDir; onClick: (f: SortField) => void
}) {
  const active = current === field
  const Icon = active ? (dir === 'asc' ? ArrowUp : ArrowDown) : ChevronsUpDown
  return (
    <button
      onClick={() => onClick(field)}
      className={`flex items-center gap-1 text-xs transition-colors ${
        active ? 'text-emerald-400 font-medium' : 'text-zinc-500 hover:text-zinc-300'
      }`}
    >
      {label}
      <Icon size={11} className={active ? 'text-emerald-400' : 'text-zinc-600'} />
    </button>
  )
}

export default function Users() {
  const [searchParams] = useSearchParams()
  const { openPanel } = usePanelStore()

  const [filters, setFilters] = useState<Filters>(() => ({
    search:     '',
    department: [],
    risk:       searchParams.get('risk')     ? [searchParams.get('risk')!]     : [],
    status:     searchParams.get('status')   ? [searchParams.get('status')!]   : [],
    mfa:        searchParams.get('mfa')      ? [searchParams.get('mfa')!]      : [],
    endpoint:   searchParams.get('endpoint') ? [searchParams.get('endpoint')!] : [],
  }))

  // Sync URL params when navigating to this page from AI Insights deep links
  const prevParams = useRef(searchParams.toString())
  useEffect(() => {
    const paramsStr = searchParams.toString()
    if (paramsStr === prevParams.current) return
    prevParams.current = paramsStr
    setFilters(f => ({
      ...f,
      risk:     searchParams.get('risk')     ? [searchParams.get('risk')!]     : [],
      status:   searchParams.get('status')   ? [searchParams.get('status')!]   : [],
      mfa:      searchParams.get('mfa')      ? [searchParams.get('mfa')!]      : [],
      endpoint: searchParams.get('endpoint') ? [searchParams.get('endpoint')!] : [],
    }))
  }, [searchParams])

  useEffect(() => { setPage(1) }, [filters])

  const [sortField, setSortField] = useState<SortField>('name')
  const [sortDir, setSortDir]     = useState<SortDir>('asc')
  const [page, setPage] = useState(1)

  function toggleFilter<K extends keyof Omit<Filters, 'search'>>(key: K, val: string) {
    setFilters(f => {
      const arr = f[key] as string[]
      return { ...f, [key]: arr.includes(val) ? arr.filter(x => x !== val) : [...arr, val] }
    })
  }

  function handleSort(field: SortField) {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('asc') }
  }

  const activeFilterCount = Object.entries(filters).filter(
    ([k, v]) => k !== 'search' && Array.isArray(v) && (v as string[]).length > 0
  ).length

  const { data: raw = [], isLoading } = useQuery<UserType[]>({
    queryKey: ['users-all'],
    queryFn: async () => (await apiClient.get('/users?limit=2000')).data,
  })

  const facetCounts = useMemo(() => {
    const risk:     Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 }
    const dept:     Record<string, number> = {}
    const status:   Record<string, number> = { active: 0, suspended: 0, inactive: 0 }
    const mfa:      Record<string, number> = { enabled: 0, disabled: 0 }
    const endpoint: Record<string, number> = { no_endpoint: 0 }

    for (const u of raw) {
      for (const [level, [min, max]] of Object.entries(RISK_SCORE_RANGES)) {
        if (u.risk_score != null && u.risk_score >= min && u.risk_score <= max) {
          risk[level] = (risk[level] ?? 0) + 1
        }
      }
      const d = u.department ?? 'Unknown'
      dept[d] = (dept[d] ?? 0) + 1
      if (u.suspended) status.suspended++
      else if (u.employment_status === 'inactive') status.inactive++
      else status.active++
      if (u.mfa_enabled) mfa.enabled++
      else mfa.disabled++
      if ((u.endpoint_count ?? 0) === 0) endpoint.no_endpoint++
    }

    return { risk, dept, status, mfa, endpoint }
  }, [raw])

  const users = useMemo(() => {
    let list = [...raw]

    if (filters.search) {
      const q = filters.search.toLowerCase()
      list = list.filter(u =>
        u.full_name.toLowerCase().includes(q) ||
        u.email.toLowerCase().includes(q) ||
        (u.department ?? '').toLowerCase().includes(q)
      )
    }
    if (filters.risk.length) {
      list = list.filter(u =>
        filters.risk.some(r => {
          const [min, max] = RISK_SCORE_RANGES[r] ?? [0, 100]
          return u.risk_score != null && u.risk_score >= min && u.risk_score <= max
        })
      )
    }
    if (filters.department.length) {
      list = list.filter(u =>
        filters.department.some(d => (u.department ?? 'Unknown') === (d === 'unknown' ? 'Unknown' : d))
      )
    }
    if (filters.status.length) {
      list = list.filter(u => {
        const isSuspended = u.suspended
        const isInactive  = !u.suspended && u.employment_status === 'inactive'
        const isActive    = !u.suspended && u.employment_status !== 'inactive'
        return filters.status.some(s =>
          (s === 'suspended' && isSuspended) ||
          (s === 'inactive'  && isInactive)  ||
          (s === 'active'    && isActive)
        )
      })
    }
    if (filters.mfa.length) {
      list = list.filter(u =>
        filters.mfa.some(m => (m === 'enabled' && u.mfa_enabled) || (m === 'disabled' && !u.mfa_enabled))
      )
    }
    if (filters.endpoint.includes('no_endpoint')) {
      list = list.filter(u => (u.endpoint_count ?? 0) === 0)
    }

    list.sort((a, b) => {
      if (sortField === 'name') return (a.full_name ?? '').localeCompare(b.full_name ?? '', undefined, { sensitivity: 'base' })
      const ta = a.last_login ? new Date(a.last_login).getTime() : -Infinity
      const tb = b.last_login ? new Date(b.last_login).getTime() : -Infinity
      return ta - tb
    })
    return sortDir === 'asc' ? list : list.reverse()
  }, [raw, filters, sortField, sortDir])

  const PAGE_SIZE = 50
  const totalPages = Math.ceil(users.length / PAGE_SIZE)
  const pagedUsers = users.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const deptOptions = Object.entries(facetCounts.dept)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([d, count]) => ({ value: d === 'Unknown' ? 'unknown' : d, label: d, count }))

  const filterGroups: FilterGroup[] = [
    {
      id: 'risk', label: 'Risk',
      selected: filters.risk,
      onToggle: v => toggleFilter('risk', v),
      onClear: () => setFilters(f => ({ ...f, risk: [] })),
      options: [
        { value: 'critical', label: 'Critical', count: facetCounts.risk.critical ?? 0 },
        { value: 'high',     label: 'High',     count: facetCounts.risk.high     ?? 0 },
        { value: 'medium',   label: 'Medium',   count: facetCounts.risk.medium   ?? 0 },
        { value: 'low',      label: 'Low',      count: facetCounts.risk.low      ?? 0 },
      ],
    },
    {
      id: 'status', label: 'Status',
      selected: filters.status,
      onToggle: v => toggleFilter('status', v),
      onClear: () => setFilters(f => ({ ...f, status: [] })),
      options: [
        { value: 'active',    label: 'Active',    count: facetCounts.status.active    ?? 0 },
        { value: 'suspended', label: 'Suspended', count: facetCounts.status.suspended ?? 0 },
        { value: 'inactive',  label: 'Inactive',  count: facetCounts.status.inactive  ?? 0 },
      ],
    },
    {
      id: 'mfa', label: 'MFA',
      selected: filters.mfa,
      onToggle: v => toggleFilter('mfa', v),
      onClear: () => setFilters(f => ({ ...f, mfa: [] })),
      options: [
        { value: 'enabled',  label: 'Enabled',  count: facetCounts.mfa.enabled  ?? 0 },
        { value: 'disabled', label: 'Disabled', count: facetCounts.mfa.disabled ?? 0 },
      ],
    },
    {
      id: 'department', label: 'Department',
      selected: filters.department,
      onToggle: v => toggleFilter('department', v),
      onClear: () => setFilters(f => ({ ...f, department: [] })),
      options: deptOptions,
    },
    {
      id: 'endpoint', label: 'Endpoint',
      selected: filters.endpoint,
      onToggle: v => toggleFilter('endpoint', v),
      onClear: () => setFilters(f => ({ ...f, endpoint: [] })),
      options: [
        { value: 'no_endpoint', label: 'No Endpoint', count: facetCounts.endpoint.no_endpoint ?? 0 },
      ],
    },
  ]

  return (
    <div className="absolute inset-0 flex overflow-hidden">
      <div className="flex flex-col flex-1 min-w-0">

        {/* Toolbar */}
        <div
          className="flex-shrink-0 px-5 py-4 flex items-center gap-3"
          style={{ borderBottom: '1px solid var(--border)' }}
        >
          <h1 className="text-xl font-semibold text-white">Users</h1>
          <div className="flex-1" />
          <button
            onClick={() => exportCSV(users)}
            className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg"
            style={{ background: 'var(--surface-2)', border: '1px solid var(--border-mid)', color: 'var(--text-3)' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-1)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-3)')}
          >
            <Download size={13} />
            Export CSV
          </button>
        </div>

        {/* Filter bar */}
        <FilterBar
          search={filters.search}
          onSearchChange={v => setFilters(f => ({ ...f, search: v }))}
          searchPlaceholder="Search name or email…"
          groups={filterGroups}
          activeCount={activeFilterCount}
          onClearAll={() => setFilters(EMPTY)}
          totalLabel={`${users.length} user${users.length !== 1 ? 's' : ''}`}
        />

        {/* Sort bar */}
        <div
          className="flex-shrink-0 flex items-center gap-4 px-5 py-2"
          style={{ borderBottom: '1px solid var(--hover-1)', background: 'rgba(0,0,0,0.2)' }}
        >
          <SortBtn label="Name"        field="name"        current={sortField} dir={sortDir} onClick={handleSort} />
          <SortBtn label="Last Active" field="last_active" current={sortField} dir={sortDir} onClick={handleSort} />
        </div>

        {/* Rows */}
        <div className="flex-1 overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center justify-center h-40">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-500" />
            </div>
          ) : users.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-40" style={{ color: 'var(--text-4)' }}>
              <User className="w-8 h-8 mb-2 opacity-50" />
              <p className="text-sm">No users match your filters.</p>
              {activeFilterCount > 0 && (
                <button onClick={() => setFilters(EMPTY)} className="mt-2 text-xs text-emerald-400 hover:text-emerald-300">
                  Clear filters
                </button>
              )}
            </div>
          ) : (
            <div className="divide-y" style={{ borderColor: 'var(--hover-1)' }}>
              {pagedUsers.map(user => (
                <div
                  key={user.id}
                  onClick={() => openPanel('user', user.id, user.full_name)}
                  className="flex items-center gap-3 px-5 py-3.5 cursor-pointer transition-colors"
                  style={{ transition: 'background-color 80ms ease' }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--hover-2)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <div className="w-8 h-8 rounded-full bg-emerald-600/25 flex items-center justify-center text-emerald-300 font-semibold text-xs flex-shrink-0">
                    {user.full_name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className="text-sm font-medium truncate" style={{ color: 'var(--text-1)' }}>{user.full_name}</span>
                      {user.suspended || user.employment_status === 'inactive' ? (
                        <span className="inline-flex items-center gap-0.5 text-xs px-1.5 py-0.5 rounded-full border bg-red-500/10 border-red-500/25 text-red-400 flex-shrink-0">
                          <UserX size={9} /> {user.suspended ? 'Suspended' : 'Inactive'}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-0.5 text-xs px-1.5 py-0.5 rounded-full border bg-emerald-500/10 border-green-500/25 text-emerald-300 flex-shrink-0">
                          <UserCheck size={9} /> Active
                        </span>
                      )}
                      {!user.mfa_enabled && (
                        <ShieldOff className="w-3 h-3 text-yellow-500 flex-shrink-0" />
                      )}
                      {user.sources?.jumpcloud && (
                        <span
                          title={`JumpCloud — ${user.sources.jumpcloud.suspended ? 'Suspended' : user.sources.jumpcloud.active ? 'Active' : 'Inactive'} · MFA: ${user.sources.jumpcloud.mfa ? 'On' : 'Off'}`}
                          className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded flex-shrink-0"
                          style={{ background: 'rgba(59,130,246,0.12)', color: '#60a5fa', border: '1px solid rgba(59,130,246,0.25)' }}>
                          <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: user.sources.jumpcloud.active && !user.sources.jumpcloud.suspended ? '#34d399' : '#f87171' }} />
                          JumpCloud
                        </span>
                      )}
                      {user.sources?.google && (
                        <span
                          title={`Google Workspace — ${user.sources.google.suspended ? 'Suspended' : user.sources.google.active ? 'Active' : 'Inactive'} · MFA: ${user.sources.google.mfa ? 'On' : 'Off'}`}
                          className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded flex-shrink-0"
                          style={{ background: 'rgba(234,179,8,0.12)', color: '#fbbf24', border: '1px solid rgba(234,179,8,0.25)' }}>
                          <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: user.sources.google.active && !user.sources.google.suspended ? '#34d399' : '#f87171' }} />
                          Google
                        </span>
                      )}
                      {hasAnomaly(user) && (
                        <span title="Cross-source anomaly detected" className="flex-shrink-0 inline-flex">
                          <AlertTriangle size={11} style={{ color: '#f97316' }} />
                        </span>
                      )}
                    </div>
                    <div className="text-xs truncate" style={{ color: 'var(--text-3)' }}>{user.email}</div>
                    {(user.job_title || user.department) && (
                      <div className="text-xs truncate" style={{ color: 'var(--text-4)' }}>
                        {[user.job_title, user.department].filter(Boolean).join(' · ')}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <RiskBadge score={user.risk_score} />
                    <ChevronRight className="w-4 h-4 text-zinc-600" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        {totalPages > 1 && (
          <div
            className="flex-shrink-0 flex items-center justify-center gap-3 px-5 py-3"
            style={{ borderTop: '1px solid var(--hover-1)' }}
          >
            <button
              disabled={page <= 1}
              onClick={() => setPage(p => p - 1)}
              className="text-xs px-3 py-1.5 rounded-lg disabled:opacity-40 transition-colors"
              style={{ background: 'var(--surface-2)', border: '1px solid var(--border-mid)', color: 'var(--text-2)' }}
            >
              ← Prev
            </button>
            <span className="text-xs tabular-nums" style={{ color: 'var(--text-4)' }}>
              {page} / {totalPages} · {users.length} users
            </span>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage(p => p + 1)}
              className="text-xs px-3 py-1.5 rounded-lg disabled:opacity-40 transition-colors"
              style={{ background: 'var(--surface-2)', border: '1px solid var(--border-mid)', color: 'var(--text-2)' }}
            >
              Next →
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
