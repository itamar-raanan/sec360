import React, { useState, useMemo, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { formatDistanceToNow } from 'date-fns'
import {
  Monitor, ChevronRight, ArrowUp, ArrowDown, ChevronsUpDown,
  UserCheck, Download, X, CheckSquare, Square, Users,
} from 'lucide-react'
import apiClient from '../api/client'
import RiskBadge from '../components/shared/RiskBadge'
import EmptyState from '../components/shared/EmptyState'
import { SkeletonRows } from '../components/shared/Skeleton'
import FilterBar, { type FilterGroup } from '../components/shared/FilterBar'
import { usePanelStore } from '../store/panels'
import type { Endpoint } from '../types'

interface AuthUserDetail {
  id: string
  email: string
  role: string
  is_active: boolean
}

const relTime = (iso: string) => formatDistanceToNow(new Date(iso), { addSuffix: true })

const RISK_SCORE_RANGES: Record<string, [number, number]> = {
  low: [0, 25], medium: [26, 50], high: [51, 75], critical: [76, 100],
}

function osLabel(osVersion: string | null): string {
  if (!osVersion) return 'unknown'
  const v = osVersion.toLowerCase()
  if (v.includes('windows')) return 'windows'
  if (v.includes('mac') || v.includes('darwin')) return 'macos'
  if (v.includes('linux') || v.includes('ubuntu') || v.includes('centos') || v.includes('rhel') || v.includes('debian')) return 'linux'
  return 'other'
}

type SortField = 'name' | 'last_active' | 'risk_score' | 'compliance'
type SortDir   = 'asc' | 'desc'

interface Filters {
  search: string
  compliance: string[]
  os: string[]
  risk: string[]
  agent: string[]
  agentStatus: string[]
  owner: string[]
}

const EMPTY: Filters = { search: '', compliance: [], os: [], risk: [], agent: [], agentStatus: [], owner: [] }

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

// ── CSV export helper ──────────────────────────────────────────────────────────

function exportCSV(selected: Endpoint[]) {
  const headers = ['Hostname', 'IP', 'OS', 'Risk Score', 'Compliance', 'Owner', 'Last Seen']
  const rows = selected.map(ep => [
    ep.hostname,
    ep.ip_address ?? '',
    ep.os_version ?? '',
    String(ep.risk_score_override ?? ep.risk_score),
    ep.compliance_status?.status ?? '',
    ep.owner?.email ?? '',
    ep.last_seen ? new Date(ep.last_seen).toISOString() : '',
  ])
  const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `endpoints-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

// ── Assign owner modal ─────────────────────────────────────────────────────────

function AssignOwnerModal({ count, onAssign, onClose, error, isPending }: {
  count: number
  onAssign: (userId: string | null) => void
  onClose: () => void
  error?: string
  isPending?: boolean
}) {
  const [selected, setSelected] = useState<string>('__unassign__')
  const { data: users = [] } = useQuery<AuthUserDetail[]>({
    queryKey: ['auth-users-for-assign'],
    queryFn: () => apiClient.get('/settings/users').then(r => r.data),
  })

  const activeUsers = users.filter(u => u.is_active)

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
      onClick={onClose}>
      <div className="bg-zinc-950 border border-white/[0.08] rounded-2xl w-full max-w-sm shadow-2xl"
        onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/[0.06]">
          <div>
            <h2 className="text-sm font-semibold text-white">Assign owner</h2>
            <p className="text-xs text-zinc-500 mt-0.5">{count} endpoint{count !== 1 ? 's' : ''} selected</p>
          </div>
          <button onClick={onClose} style={{ color: 'var(--text-3)' }}
            onMouseEnter={e => (e.currentTarget.style.color = '#d4d4d8')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-3)')}>
            <X size={16} />
          </button>
        </div>
        <div className="px-5 py-4 space-y-3">
          {error && (
            <div className="flex items-start gap-2 bg-red-500/10 border border-red-500/20 text-red-400 text-xs px-3 py-2.5 rounded-lg">
              <span className="mt-px">⚠</span>
              <span>{error}</span>
            </div>
          )}
          <div>
            <label className="block text-xs text-zinc-400 mb-1.5">Select system user</label>
            <select value={selected} onChange={e => setSelected(e.target.value)}
              className="w-full bg-zinc-900 border border-white/[0.08] text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500">
              <option value="__unassign__">— Unassign owner —</option>
              {activeUsers.map(u => (
                <option key={u.id} value={u.id}>{u.email} ({u.role})</option>
              ))}
            </select>
          </div>
        </div>
        <div className="flex gap-2 px-5 py-4 border-t border-white/[0.06]">
          <button
            onClick={() => onAssign(selected === '__unassign__' ? null : selected)}
            disabled={isPending}
            className="flex items-center gap-1.5 text-white text-sm font-medium px-4 py-2 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ background: 'var(--accent)' }}
            onMouseEnter={e => { if (!isPending) e.currentTarget.style.opacity = '0.85' }}
            onMouseLeave={e => (e.currentTarget.style.opacity = '1')}>
            <UserCheck size={14} /> {isPending ? 'Saving…' : 'Apply'}
          </button>
          <button onClick={onClose} className="text-sm text-zinc-400 px-3 py-2"
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-1)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-2)')}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function Endpoints() {
  const [searchParams] = useSearchParams()
  const { openPanel } = usePanelStore()
  const qc = useQueryClient()

  const [filters, setFilters] = useState<Filters>(() => ({
    search:      '',
    compliance:  searchParams.get('compliance')  ? [searchParams.get('compliance')!]  : [],
    os:          searchParams.get('os')          ? [searchParams.get('os')!]          : [],
    risk:        searchParams.get('risk')        ? [searchParams.get('risk')!]        : [],
    agent:       searchParams.get('agent')       ? [searchParams.get('agent')!]       : [],
    agentStatus: searchParams.get('agentStatus') ? [searchParams.get('agentStatus')!] : [],
    owner:       searchParams.get('owner')       ? [searchParams.get('owner')!]       : [],
  }))

  // Sync URL params when navigating here from AI Insights deep links
  const prevParams = useRef(searchParams.toString())
  useEffect(() => {
    const paramsStr = searchParams.toString()
    if (paramsStr === prevParams.current) return
    prevParams.current = paramsStr
    setFilters(f => ({
      ...f,
      compliance:  searchParams.get('compliance')  ? [searchParams.get('compliance')!]  : [],
      os:          searchParams.get('os')          ? [searchParams.get('os')!]          : [],
      risk:        searchParams.get('risk')        ? [searchParams.get('risk')!]        : [],
      agent:       searchParams.get('agent')       ? [searchParams.get('agent')!]       : [],
      agentStatus: searchParams.get('agentStatus') ? [searchParams.get('agentStatus')!] : [],
      owner:       searchParams.get('owner')       ? [searchParams.get('owner')!]       : [],
    }))
  }, [searchParams])
  useEffect(() => { setPage(1) }, [filters])
  const [sortField, setSortField] = useState<SortField>('name')
  const [sortDir, setSortDir]     = useState<SortDir>('asc')
  const [page, setPage] = useState(1)

  // Bulk selection
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [showAssignModal, setShowAssignModal] = useState(false)
  const [bulkError, setBulkError] = useState('')

  const bulkAssign = useMutation({
    mutationFn: (body: { ids: string[]; owner_user_id: string | null }) =>
      apiClient.post('/endpoints/bulk', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['endpoints-all'] })
      setSelectedIds(new Set())
      setShowAssignModal(false)
      setBulkError('')
    },
    onError: (e: { response?: { data?: { detail?: string } } }) => {
      setBulkError(e?.response?.data?.detail ?? 'Failed to assign owner')
    },
  })

  function toggleSelect(id: string, e: React.MouseEvent) {
    e.stopPropagation()
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function toggleSelectAll() {
    if (selectedIds.size === endpoints.length) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(endpoints.map(ep => ep.id)))
    }
  }

  function handleSort(field: SortField) {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('asc') }
  }

  function toggleFilter<K extends keyof Omit<Filters, 'search'>>(key: K, val: string) {
    setFilters(f => {
      const arr = f[key] as string[]
      return { ...f, [key]: arr.includes(val) ? arr.filter(x => x !== val) : [...arr, val] }
    })
  }

  const activeFilterCount = Object.entries(filters).filter(
    ([k, v]) => k !== 'search' && Array.isArray(v) && (v as string[]).length > 0
  ).length

  const { data: raw = [], isLoading } = useQuery<Endpoint[]>({
    queryKey: ['endpoints-all'],
    queryFn: async () => (await apiClient.get('/endpoints?limit=2000&active_only=false')).data,
  })

  // Compute facet counts from raw (unfiltered) data
  const facetCounts = useMemo(() => {
    const risk:       Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 }
    const compliance: Record<string, number> = { compliant: 0, partial: 0, non_compliant: 0 }
    const os:         Record<string, number> = { windows: 0, macos: 0, linux: 0, other: 0 }
    const agent:       Record<string, number> = { has_s1: 0, no_s1: 0, has_dlp: 0, no_dlp: 0, has_gp: 0, no_gp: 0, has_wss: 0, no_wss: 0, disabled_agent: 0, no_vpn: 0 }
    const agentStatus: Record<string, number> = { s1_active: 0, s1_inactive: 0, dlp_active: 0, dlp_inactive: 0 }
    const owner:      Record<string, number> = { assigned: 0, unassigned: 0 }

    for (const ep of raw) {
      // risk
      for (const [level, [min, max]] of Object.entries(RISK_SCORE_RANGES)) {
        if (ep.risk_score != null && ep.risk_score >= min && ep.risk_score <= max) {
          risk[level] = (risk[level] ?? 0) + 1
        }
      }
      // compliance
      const cs = ep.compliance_status?.status
      if (cs) compliance[cs] = (compliance[cs] ?? 0) + 1
      // os
      const o = osLabel(ep.os_version ?? null)
      os[o] = (os[o] ?? 0) + 1
      // agents
      const agents = ep.agents ?? []
      const hasS1  = agents.some(a => a.product_name === 'sentinelone')
      const hasDlp = agents.some(a => a.product_name === 'symantec')
      const hasGp  = agents.some(a => a.product_name === 'globalprotect')
      const hasWss = agents.some(a => a.product_name === 'symantec_wss')
      if (hasS1) agent.has_s1++
      else agent.no_s1++
      if (hasDlp) agent.has_dlp++
      else agent.no_dlp++
      if (hasGp) agent.has_gp++
      else agent.no_gp++
      if (hasWss) agent.has_wss++
      else agent.no_wss++
      if (agents.some(a => a.status === 'inactive')) agent.disabled_agent++
      if (!hasGp && !hasWss) agent.no_vpn++
      // agent status
      const s1Agent  = agents.find(a => a.product_name === 'sentinelone')
      const dlpAgent = agents.find(a => a.product_name === 'symantec')
      if (s1Agent?.status === 'active') agentStatus.s1_active++
      else if (s1Agent) agentStatus.s1_inactive++
      if (dlpAgent?.status === 'active') agentStatus.dlp_active++
      else if (dlpAgent) agentStatus.dlp_inactive++
      // owner
      if (ep.owner_user_id) owner.assigned++
      else owner.unassigned++
    }

    return { risk, compliance, os, agent, agentStatus, owner }
  }, [raw])

  const endpoints = useMemo(() => {
    let list = [...raw]

    if (filters.search) {
      const q = filters.search.toLowerCase()
      list = list.filter(ep =>
        (ep.hostname ?? '').toLowerCase().includes(q) ||
        (ep.ip_address ?? '').toLowerCase().includes(q) ||
        (ep.username ?? '').toLowerCase().includes(q) ||
        (ep.owner?.email ?? '').toLowerCase().includes(q)
      )
    }
    if (filters.risk.length) {
      list = list.filter(ep => {
        const score = ep.risk_score_override ?? ep.risk_score ?? 0
        return filters.risk.some(r => {
          const [min, max] = RISK_SCORE_RANGES[r] ?? [0, 100]
          return score >= min && score <= max
        })
      })
    }
    if (filters.compliance.length) {
      list = list.filter(ep => filters.compliance.includes(ep.compliance_status?.status ?? ''))
    }
    if (filters.os.length) {
      list = list.filter(ep => filters.os.includes(osLabel(ep.os_version ?? null)))
    }
    if (filters.agent.length) {
      list = list.filter(ep => {
        const agents = ep.agents ?? []
        const hasS1  = agents.some(a => a.product_name === 'sentinelone')
        const hasDlp = agents.some(a => a.product_name === 'symantec')
        const hasGp  = agents.some(a => a.product_name === 'globalprotect')
        const hasWss = agents.some(a => a.product_name === 'symantec_wss')
        const hasDisabledAgent = agents.some(a => a.status === 'inactive')
        const agentMap: Record<string, boolean> = {
          has_s1: hasS1, no_s1: !hasS1,
          has_dlp: hasDlp, no_dlp: !hasDlp,
          has_gp: hasGp, no_gp: !hasGp,
          has_wss: hasWss, no_wss: !hasWss,
          no_vpn: !hasGp && !hasWss,
          disabled_agent: hasDisabledAgent,
        }
        return filters.agent.some(v => agentMap[v])
      })
    }
    if (filters.agentStatus.length) {
      list = list.filter(ep => {
        const agents   = ep.agents ?? []
        const s1Agent  = agents.find(a => a.product_name === 'sentinelone')
        const dlpAgent = agents.find(a => a.product_name === 'symantec')
        return filters.agentStatus.some(v => {
          if (v === 's1_active')    return s1Agent?.status  === 'active'
          if (v === 's1_inactive')  return s1Agent  != null && s1Agent.status  !== 'active'
          if (v === 'dlp_active')   return dlpAgent?.status === 'active'
          if (v === 'dlp_inactive') return dlpAgent != null && dlpAgent.status !== 'active'
          return false
        })
      })
    }
    if (filters.owner.length) {
      list = list.filter(ep => {
        const isAssigned = Boolean(ep.owner_user_id)
        return filters.owner.some(v => (v === 'assigned' && isAssigned) || (v === 'unassigned' && !isAssigned))
      })
    }

    const COMPLIANCE_RANK: Record<string, number> = { compliant: 0, partial: 1, non_compliant: 2 }
    list.sort((a, b) => {
      if (sortField === 'name') return (a.hostname ?? '').localeCompare(b.hostname ?? '', undefined, { sensitivity: 'base' })
      if (sortField === 'risk_score') return (a.risk_score_override ?? a.risk_score ?? 0) - (b.risk_score_override ?? b.risk_score ?? 0)
      if (sortField === 'compliance') {
        const ra = COMPLIANCE_RANK[a.compliance_status?.status ?? ''] ?? 3
        const rb = COMPLIANCE_RANK[b.compliance_status?.status ?? ''] ?? 3
        return ra - rb
      }
      const ta = a.last_seen ? new Date(a.last_seen).getTime() : -Infinity
      const tb = b.last_seen ? new Date(b.last_seen).getTime() : -Infinity
      return ta - tb
    })
    return sortDir === 'asc' ? list : list.reverse()
  }, [raw, filters, sortField, sortDir])

  const selectedEndpoints = endpoints.filter(ep => selectedIds.has(ep.id))

  const PAGE_SIZE = 50
  const totalPages = Math.ceil(endpoints.length / PAGE_SIZE)
  const pagedEndpoints = endpoints.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

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
      id: 'compliance', label: 'Compliance',
      selected: filters.compliance,
      onToggle: v => toggleFilter('compliance', v),
      onClear: () => setFilters(f => ({ ...f, compliance: [] })),
      options: [
        { value: 'non_compliant', label: 'Non-Compliant', count: facetCounts.compliance.non_compliant ?? 0 },
        { value: 'partial',       label: 'Partial',       count: facetCounts.compliance.partial       ?? 0 },
        { value: 'compliant',     label: 'Compliant',     count: facetCounts.compliance.compliant     ?? 0 },
      ],
    },
    {
      id: 'os', label: 'OS',
      selected: filters.os,
      onToggle: v => toggleFilter('os', v),
      onClear: () => setFilters(f => ({ ...f, os: [] })),
      options: [
        { value: 'windows', label: 'Windows', count: facetCounts.os.windows ?? 0 },
        { value: 'macos',   label: 'macOS',   count: facetCounts.os.macos   ?? 0 },
        { value: 'linux',   label: 'Linux',   count: facetCounts.os.linux   ?? 0 },
        { value: 'other',   label: 'Other',   count: facetCounts.os.other   ?? 0 },
      ],
    },
    {
      id: 'agent', label: 'Agents',
      selected: filters.agent,
      onToggle: v => toggleFilter('agent', v),
      onClear: () => setFilters(f => ({ ...f, agent: [] })),
      options: [
        { value: 'no_vpn',         label: 'No VPN',         count: facetCounts.agent.no_vpn         ?? 0 },
        { value: 'disabled_agent', label: 'Agent Disabled', count: facetCounts.agent.disabled_agent ?? 0 },
        { value: 'has_s1',  label: 'Has S1',      count: facetCounts.agent.has_s1  ?? 0 },
        { value: 'no_s1',   label: 'Missing S1',  count: facetCounts.agent.no_s1   ?? 0 },
        { value: 'has_dlp', label: 'Has DLP',      count: facetCounts.agent.has_dlp ?? 0 },
        { value: 'no_dlp',  label: 'Missing DLP', count: facetCounts.agent.no_dlp  ?? 0 },
        { value: 'has_gp',  label: 'Has GP',       count: facetCounts.agent.has_gp  ?? 0 },
        { value: 'no_gp',   label: 'Missing GP',  count: facetCounts.agent.no_gp   ?? 0 },
        { value: 'has_wss', label: 'Has WSS',      count: facetCounts.agent.has_wss ?? 0 },
        { value: 'no_wss',  label: 'Missing WSS', count: facetCounts.agent.no_wss  ?? 0 },
      ],
    },
    {
      id: 'agentStatus', label: 'Agent Status',
      selected: filters.agentStatus,
      onToggle: v => toggleFilter('agentStatus', v),
      onClear: () => setFilters(f => ({ ...f, agentStatus: [] })),
      options: [
        { value: 's1_active',    label: 'S1 Active',       count: facetCounts.agentStatus.s1_active    ?? 0 },
        { value: 's1_inactive',  label: 'S1 Inactive',     count: facetCounts.agentStatus.s1_inactive  ?? 0 },
        { value: 'dlp_active',   label: 'DLP Active',      count: facetCounts.agentStatus.dlp_active   ?? 0 },
        { value: 'dlp_inactive', label: 'DLP Inactive',    count: facetCounts.agentStatus.dlp_inactive ?? 0 },
      ],
    },
    {
      id: 'owner', label: 'Owner',
      selected: filters.owner,
      onToggle: v => toggleFilter('owner', v),
      onClear: () => setFilters(f => ({ ...f, owner: [] })),
      options: [
        { value: 'assigned',   label: 'Assigned',   count: facetCounts.owner.assigned   ?? 0 },
        { value: 'unassigned', label: 'Unassigned', count: facetCounts.owner.unassigned ?? 0 },
      ],
    },
  ]

  return (
    <div className="absolute inset-0 flex overflow-hidden">

      {/* List */}
      <div className="flex flex-col flex-1 min-w-0">

        {/* Toolbar */}
        <div
          className="flex-shrink-0 px-5 py-4 flex items-center gap-3"
          style={{ borderBottom: '1px solid var(--border)' }}
        >
          <button
            onClick={toggleSelectAll}
            className="text-zinc-500 flex-shrink-0"
            style={{ transition: 'color 150ms ease' }}
            onMouseEnter={e => (e.currentTarget.style.color = '#d4d4d8')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-3)')}
            title={selectedIds.size === endpoints.length ? 'Deselect all' : 'Select all'}
          >
            {selectedIds.size > 0 && selectedIds.size === endpoints.length
              ? <CheckSquare size={16} className="text-emerald-400" />
              : <Square size={16} />}
          </button>
          <h1 className="text-xl font-semibold text-white">Endpoints</h1>
        </div>

        {/* Filter bar */}
        <FilterBar
          search={filters.search}
          onSearchChange={v => setFilters(f => ({ ...f, search: v }))}
          searchPlaceholder="Search hostname, IP…"
          groups={filterGroups}
          activeCount={activeFilterCount}
          onClearAll={() => setFilters(EMPTY)}
          totalLabel={`${endpoints.length} endpoint${endpoints.length !== 1 ? 's' : ''}`}
        />

        {/* Sort bar */}
        <div
          className="flex-shrink-0 flex items-center justify-between px-5 py-2"
          style={{ borderBottom: '1px solid var(--hover-1)', background: 'rgba(0,0,0,0.2)' }}
        >
          <div className="flex items-center gap-4">
            <SortBtn label="Name"        field="name"        current={sortField} dir={sortDir} onClick={handleSort} />
            <SortBtn label="Last Active" field="last_active" current={sortField} dir={sortDir} onClick={handleSort} />
            <SortBtn label="Risk"        field="risk_score"  current={sortField} dir={sortDir} onClick={handleSort} />
            <SortBtn label="Compliance"  field="compliance"  current={sortField} dir={sortDir} onClick={handleSort} />
          </div>
        </div>

        {/* Rows */}
        <div className="flex-1 overflow-y-auto">
          {isLoading ? (
            <SkeletonRows count={12} cols={4} />
          ) : endpoints.length === 0 ? (
            <EmptyState
              icon={Monitor}
              title="No endpoints found"
              description={activeFilterCount > 0 ? 'No endpoints match your current filters.' : 'No endpoints have been synced yet.'}
              action={activeFilterCount > 0 ? { label: 'Clear filters', onClick: () => setFilters(EMPTY) } : undefined}
            />
          ) : (
            <div className="divide-y" style={{ borderColor: 'var(--hover-1)' }}>
              {pagedEndpoints.map(ep => {
                const agents     = ep.agents || []
                const hasS1      = agents.some(a => a.product_name === 'sentinelone')
                const hasSym     = agents.some(a => a.product_name === 'symantec')
                const hasGP      = agents.some(a => a.product_name === 'globalprotect')
                const hasWSS     = agents.some(a => a.product_name === 'symantec_wss')
                const s1Agent    = agents.find(a => a.product_name === 'sentinelone')
                const s1LastSeen = s1Agent?.last_seen ?? null
                const tagList    = ep.tags
                  ? String(ep.tags).split(',').map((t: string) => t.trim()).filter(Boolean)
                  : []
                const isInactive = !ep.last_seen && !s1LastSeen

                const isSelected = selectedIds.has(ep.id)
                return (
                  <div
                    key={ep.id}
                    onClick={() => openPanel('endpoint', ep.id, ep.hostname)}
                    className={`flex items-center gap-3 px-5 py-3.5 cursor-pointer ${isInactive ? 'opacity-60' : ''}`}
                    style={{
                      transition: 'background-color 80ms ease',
                      background: isSelected ? 'rgba(16,185,129,0.06)' : 'transparent',
                    }}
                    onMouseEnter={e => { if (!isSelected) e.currentTarget.style.background = 'var(--hover-2)' }}
                    onMouseLeave={e => { e.currentTarget.style.background = isSelected ? 'rgba(16,185,129,0.06)' : 'transparent' }}
                  >
                    <button
                      onClick={e => toggleSelect(ep.id, e)}
                      className="flex-shrink-0"
                      style={{ color: isSelected ? 'var(--accent)' : '#52525e', transition: 'color 150ms ease' }}
                      onMouseEnter={e => { e.stopPropagation(); if (!isSelected) e.currentTarget.style.color = '#d4d4d8' }}
                      onMouseLeave={e => { e.stopPropagation(); e.currentTarget.style.color = isSelected ? 'var(--accent)' : '#52525e' }}
                    >
                      {isSelected ? <CheckSquare size={15} /> : <Square size={15} />}
                    </button>
                    <Monitor className="w-4 h-4 text-zinc-500 flex-shrink-0" />

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-white truncate">{ep.hostname}</span>
                        {isInactive && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded border border-gray-600/40 text-zinc-600 flex-shrink-0">inactive</span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                        {ep.owner
                          ? <span className="text-xs text-zinc-400 truncate">{ep.owner.email}</span>
                          : <span className="text-xs text-yellow-600">Unassigned</span>
                        }
                        {ep.os_version && (
                          <span className="text-xs text-zinc-600 truncate hidden sm:block">{ep.os_version}</span>
                        )}
                      </div>
                      <div className="flex gap-1 mt-1 flex-wrap">
                        <span className={`text-xs px-1.5 py-0.5 rounded border ${hasS1 ? 'border-purple-500/30 text-purple-300 bg-purple-500/10' : 'border-red-500/20 text-red-400/60'}`}>
                          S1{hasS1 ? '' : ' ✗'}
                        </span>
                        <span className={`text-xs px-1.5 py-0.5 rounded border ${hasSym ? 'border-yellow-500/30 text-yellow-300 bg-yellow-500/10' : 'border-red-500/20 text-red-400/60'}`}>
                          DLP{hasSym ? '' : ' ✗'}
                        </span>
                        <span className={`text-xs px-1.5 py-0.5 rounded border ${hasGP ? 'border-emerald-500/30 text-emerald-300 bg-emerald-500/10' : 'border-red-500/20 text-red-400/60'}`}>
                          GP{hasGP ? '' : ' ✗'}
                        </span>
                        <span className={`text-xs px-1.5 py-0.5 rounded border ${hasWSS ? 'border-orange-500/30 text-orange-300 bg-orange-500/10' : 'border-red-500/20 text-red-400/60'}`}>
                          WSS{hasWSS ? '' : ' ✗'}
                        </span>
                        {tagList.slice(0, 2).map((tag: string) => (
                          <span key={tag} className="text-xs px-1.5 py-0.5 rounded border border-gray-600/50 text-zinc-500 bg-zinc-900/50">
                            {tag}
                          </span>
                        ))}
                        {tagList.length > 2 && (
                          <span className="text-xs text-zinc-600">+{tagList.length - 2}</span>
                        )}
                      </div>
                    </div>

                    <div className="flex flex-col items-end gap-1 flex-shrink-0">
                      <div className="flex items-center gap-2">
                        <RiskBadge score={ep.risk_score} />
                        <ChevronRight className="w-4 h-4 text-zinc-600" />
                      </div>
                      <div className="flex flex-col items-end gap-0.5">
                        {ep.last_seen && (
                          <span className="text-[10px] text-zinc-600 hidden sm:block">
                            JC: {relTime(ep.last_seen)}
                          </span>
                        )}
                        {s1LastSeen && (
                          <span className="text-[10px] text-emerald-600 hidden sm:block">
                            S1: {relTime(s1LastSeen)}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
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
              {page} / {totalPages} · {endpoints.length} endpoints
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

      {/* Floating bulk action bar */}
      {selectedIds.size > 0 && (
        <div
          className="absolute bottom-6 left-1/2 -translate-x-1/2 flex items-center gap-3 px-4 py-3 rounded-2xl z-30"
          style={{
            background: 'var(--surface-2)',
            border: '1px solid var(--border-lit)',
            boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
          }}
        >
          <span className="text-sm font-semibold text-white flex items-center gap-1.5">
            <Users size={14} className="text-emerald-400" />
            {selectedIds.size} selected
          </span>
          <div className="w-px h-4 bg-white/10" />
          <button
            onClick={() => setShowAssignModal(true)}
            className="flex items-center gap-1.5 text-sm font-medium px-3 py-1.5 rounded-lg"
            style={{ background: 'rgba(16,185,129,0.12)', color: '#34d399', border: '1px solid rgba(16,185,129,0.2)' }}
            onMouseEnter={e => (e.currentTarget.style.opacity = '0.75')}
            onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
          >
            <UserCheck size={13} /> Assign owner
          </button>
          <button
            onClick={() => exportCSV(selectedEndpoints)}
            className="flex items-center gap-1.5 text-sm font-medium px-3 py-1.5 rounded-lg"
            style={{ background: 'var(--border)', color: 'var(--text-2)', border: '1px solid var(--border-mid)' }}
            onMouseEnter={e => (e.currentTarget.style.opacity = '0.75')}
            onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
          >
            <Download size={13} /> Export CSV
          </button>
          <button onClick={() => setSelectedIds(new Set())}
            style={{ color: 'var(--text-4)', transition: 'color 150ms ease' }}
            onMouseEnter={e => (e.currentTarget.style.color = '#d4d4d8')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-4)')}>
            <X size={15} />
          </button>
        </div>
      )}

      {showAssignModal && (
        <AssignOwnerModal
          count={selectedIds.size}
          onAssign={userId => bulkAssign.mutate({ ids: Array.from(selectedIds), owner_user_id: userId })}
          onClose={() => { setShowAssignModal(false); setBulkError('') }}
          error={bulkError}
          isPending={bulkAssign.isPending}
        />
      )}
    </div>
  )
}
