import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { PieChart, Pie, Cell, Tooltip } from 'recharts'
import {
  ShieldCheck, ShieldAlert, ShieldOff, RefreshCw,
  Monitor, User, ChevronRight, X, Search, LockOpen,
  PackageX, Cpu, HardDrive, MousePointer, Settings2, Check, Ban,
} from 'lucide-react'
import apiClient from '../api/client'
import { usePanelStore } from '../store/panels'
import { useAuthStore } from '../store/auth'

// ─── Types ───────────────────────────────────────────────────────────────────

interface DashboardSummary {
  total: number; compliant: number; partial: number
  non_compliant: number; compliant_pct: number
}
interface DashboardIssues {
  no_edr: number; edr_outdated: number
  no_dlp: number; dlp_outdated: number
  no_wss: number; wss_outdated: number; no_network_security: number
  not_encrypted: number; no_device_control: number
}
interface OsBreakdown { os: string; total: number; compliant: number; non_compliant: number }
interface AgentCoverage {
  key: string; label: string; description: string
  has: number; missing: number; excluded: number; in_scope: number; coverage_pct: number
}
interface ComplianceDashboard {
  summary: DashboardSummary; issues: DashboardIssues
  os_breakdown: OsBreakdown[]; worst_offenders: any[]
  active_product_tags: Array<'S1' | 'DLP' | 'WSS'>
  agent_coverage: AgentCoverage[]; excluded_total: number
}
interface ComplianceEndpoint {
  endpoint_id: string; hostname: string; os_version: string | null
  owner_email: string | null; owner_name: string | null; status: string
  edr_installed: boolean; edr_version_ok: boolean
  dlp_installed: boolean; dlp_version_ok: boolean
  disk_encrypted: boolean | null; device_control_enabled: boolean | null
  failure_count: number; failures: string[]; last_evaluated: string | null
  agent_presence: Record<string, boolean>
  compliance_excluded: boolean; excluded_agents: string[]
  exclusion_reason: string | null; exclusion_changed_at: string | null
  exclusion_changed_by: string | null
}
interface ActiveFilter {
  type: 'status' | 'issue' | 'os' | 'agent' | 'scope'
  value: string
  label: string
  color: string
}

function filterKey(filter: ActiveFilter) {
  return `${filter.type}:${filter.value}`
}

// ─── Colours / labels ────────────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  compliant: '#10b981', partial: '#f59e0b', non_compliant: '#ef4444',
}
const ISSUE_META: Record<string, { label: string; color: string; icon: React.ElementType; desc: string }> = {
  no_edr:              { label: 'No EDR',             color: '#ef4444', icon: ShieldOff,    desc: 'SentinelOne agent not installed' },
  edr_outdated:        { label: 'EDR Outdated',        color: '#f97316', icon: PackageX,     desc: 'SentinelOne version below minimum' },
  no_dlp:              { label: 'No DLP',              color: '#a855f7', icon: LockOpen,     desc: 'Symantec DLP agent not installed' },
  dlp_outdated:        { label: 'DLP Outdated',        color: '#f59e0b', icon: Cpu,          desc: 'Symantec DLP version below minimum' },
  not_encrypted:       { label: 'Not Encrypted',       color: '#06b6d4', icon: HardDrive,    desc: 'Disk encryption not enabled (reported by S1)' },
  no_device_control:   { label: 'Device Control Off',  color: '#84cc16', icon: MousePointer, desc: 'S1 Device Control policy not enabled' },
  no_network_security: { label: 'No WSS',              color: '#eab308', icon: ShieldAlert,  desc: 'Symantec WSS agent not installed' },
  wss_outdated:        { label: 'WSS Outdated',        color: '#f59e0b', icon: PackageX,     desc: 'Symantec WSS version below minimum' },
}

const ISSUE_AGENT: Record<string, string> = {
  no_edr: 'sentinelone', edr_outdated: 'sentinelone', not_encrypted: 'sentinelone', no_device_control: 'sentinelone',
  no_dlp: 'symantec_dlp', dlp_outdated: 'symantec_dlp',
  no_network_security: 'symantec_wss', wss_outdated: 'symantec_wss',
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    compliant:     'bg-emerald-500/15 text-emerald-300 border-green-500/25',
    partial:       'bg-yellow-500/15 text-yellow-400 border-yellow-500/25',
    non_compliant: 'bg-red-500/15 text-red-400 border-red-500/25',
  }
  const label: Record<string, string> = {
    compliant: 'Compliant', partial: 'Partial', non_compliant: 'Non-Compliant',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${map[status] ?? 'bg-gray-700 text-zinc-400 border-gray-600'}`}>
      {label[status] ?? status}
    </span>
  )
}

function FailurePill({ label }: { label: string }) {
  return (
    <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 whitespace-nowrap">
      {label}
    </span>
  )
}

function AgentPill({ label, present, excluded }: { label: string; present: boolean; excluded: boolean }) {
  const tone = excluded
    ? 'border-amber-500/25 bg-amber-500/10 text-amber-300'
    : present
      ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300'
      : 'border-red-500/20 bg-red-500/[0.07] text-red-300'
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] ${tone}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {label}{excluded ? ' excluded' : present ? '' : ' missing'}
    </span>
  )
}

function ExclusionDialog({ endpoint, agents, onClose }: {
  endpoint: ComplianceEndpoint
  agents: AgentCoverage[]
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [excludeAll, setExcludeAll] = useState(endpoint.compliance_excluded)
  const [selectedAgents, setSelectedAgents] = useState<string[]>(endpoint.excluded_agents)
  const [reason, setReason] = useState(endpoint.exclusion_reason ?? '')

  const mutation = useMutation({
    mutationFn: () => apiClient.put(`/compliance/endpoints/${endpoint.endpoint_id}/exclusions`, {
      exclude_all: excludeAll,
      excluded_agents: excludeAll ? [] : selectedAgents,
      reason: excludeAll || selectedAgents.length ? reason : null,
    }),
    onSuccess: async () => {
      await Promise.all([
        qc.invalidateQueries({ queryKey: ['compliance-dashboard'] }),
        qc.invalidateQueries({ queryKey: ['compliance-endpoints'] }),
        qc.invalidateQueries({ queryKey: ['endpoints'] }),
      ])
      onClose()
    },
  })
  const hasExclusions = excludeAll || selectedAgents.length > 0
  const canSave = !hasExclusions || reason.trim().length > 0
  const error = (mutation.error as any)?.response?.data?.detail || (mutation.error as Error | null)?.message

  function toggleAgent(key: string) {
    setSelectedAgents(current => current.includes(key)
      ? current.filter(item => item !== key)
      : [...current, key])
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="compliance-scope-title"
        className="w-full max-w-lg rounded-2xl border border-white/[0.1] bg-zinc-950 shadow-2xl"
        onMouseDown={event => event.stopPropagation()}
      >
        <div className="flex items-start justify-between border-b border-white/[0.07] px-5 py-4">
          <div>
            <h2 id="compliance-scope-title" className="text-sm font-semibold text-white">Compliance scope</h2>
            <p className="mt-1 text-xs text-zinc-500">{endpoint.hostname}</p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded-lg p-1.5 text-zinc-500 hover:bg-white/[0.06] hover:text-white">
            <X size={16} />
          </button>
        </div>

        <div className="space-y-5 px-5 py-5">
          <label className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3.5 transition-colors ${excludeAll ? 'border-amber-500/35 bg-amber-500/[0.08]' : 'border-white/[0.08] hover:border-white/[0.14]'}`}>
            <input type="checkbox" checked={excludeAll} onChange={event => setExcludeAll(event.target.checked)} className="mt-0.5 accent-amber-500" />
            <span>
              <span className="block text-sm font-medium text-zinc-100">Exclude this endpoint completely</span>
              <span className="mt-0.5 block text-xs leading-5 text-zinc-500">Remove it from compliance totals, coverage, issue counts, and compliance-based risk.</span>
            </span>
          </label>

          <div className={excludeAll ? 'pointer-events-none opacity-40' : ''}>
            <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-500">Or exclude specific requirements</div>
            <div className="divide-y divide-white/[0.06] rounded-xl border border-white/[0.08]">
              {agents.map(agent => {
                const selected = selectedAgents.includes(agent.key)
                return (
                  <label key={agent.key} className="flex cursor-pointer items-center gap-3 px-3.5 py-3 hover:bg-white/[0.025]">
                    <input type="checkbox" checked={selected} onChange={() => toggleAgent(agent.key)} className="accent-amber-500" />
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm text-zinc-200">{agent.label}</span>
                      <span className="block truncate text-[11px] text-zinc-600">{agent.description}</span>
                    </span>
                    {selected && <span className="text-[10px] text-amber-300">Not scored</span>}
                  </label>
                )
              })}
            </div>
          </div>

          <div>
            <label htmlFor="compliance-exclusion-reason" className="mb-1.5 block text-xs font-medium text-zinc-400">
              Reason {hasExclusions && <span className="text-red-400">*</span>}
            </label>
            <textarea
              id="compliance-exclusion-reason"
              rows={3}
              value={reason}
              onChange={event => setReason(event.target.value)}
              placeholder="Example: lab endpoint approved until migration is complete"
              className="w-full resize-none rounded-xl border border-white/[0.09] bg-zinc-900 px-3 py-2.5 text-sm text-white placeholder:text-zinc-700 focus:border-emerald-500 focus:outline-none"
            />
            <p className="mt-1.5 text-[11px] text-zinc-600">The reason and your identity are retained in the audit log.</p>
          </div>
          {error && <div className="rounded-lg border border-red-500/20 bg-red-500/[0.08] px-3 py-2 text-xs text-red-300">{error}</div>}
        </div>

        <div className="flex items-center justify-between border-t border-white/[0.07] px-5 py-4">
          <button
            type="button"
            onClick={() => { setExcludeAll(false); setSelectedAgents([]); setReason('') }}
            disabled={!endpoint.compliance_excluded && endpoint.excluded_agents.length === 0}
            className="text-xs text-zinc-500 hover:text-zinc-200 disabled:cursor-not-allowed disabled:opacity-30"
          >
            Remove exclusions
          </button>
          <div className="flex gap-2">
            <button type="button" onClick={onClose} className="rounded-lg px-3 py-2 text-xs text-zinc-400 hover:bg-white/[0.05] hover:text-white">Cancel</button>
            <button
              type="button"
              onClick={() => mutation.mutate()}
              disabled={!canSave || mutation.isPending}
              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-2 text-xs font-semibold text-zinc-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {mutation.isPending ? <RefreshCw size={12} className="animate-spin" /> : <Check size={12} />}
              Save scope
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Left panel components ───────────────────────────────────────────────────

function KpiCard({
  value, label, sub, color, icon: Icon, active, onClick,
}: {
  value: string | number; label: string; sub?: string; color: string
  icon: React.ElementType; active: boolean; onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-xl p-4 border transition-[background-color,border-color,box-shadow] duration-150 ${
        active
          ? 'bg-zinc-900 border-emerald-500/50 ring-1 ring-emerald-500/30'
          : 'bg-zinc-950 border-white/[0.06] hover:border-white/[0.08] hover:bg-white/[0.04]/50'
      }`}
    >
      <div className="flex items-start gap-3">
        <div className={`p-2 rounded-lg bg-zinc-900/80 flex-shrink-0 ${color}`}>
          <Icon size={18} />
        </div>
        <div className="min-w-0">
          <div className="text-xl font-bold text-white leading-none">{value}</div>
          <div className="text-xs text-zinc-400 mt-1">{label}</div>
          {sub && <div className="text-xs text-zinc-600 mt-0.5 truncate">{sub}</div>}
        </div>
        {active && <ChevronRight size={14} className="ml-auto text-emerald-400 flex-shrink-0 mt-1" />}
      </div>
    </button>
  )
}

// ─── Right panel — endpoint list ──────────────────────────────────────────────

function EndpointList({ filters, agents, onRemoveFilter, onClearFilters }: {
  filters: ActiveFilter[]
  agents: AgentCoverage[]
  onRemoveFilter: (filter: ActiveFilter) => void
  onClearFilters: () => void
}) {
  const [search, setSearch] = useState('')
  const [editingScope, setEditingScope] = useState<ComplianceEndpoint | null>(null)
  const { openPanel } = usePanelStore()
  const { user } = useAuthStore()
  const canEditScope = user?.role === 'admin' || user?.role === 'analyst'

  const params = new URLSearchParams({ limit: '200' })
  const statuses = filters.filter(filter => filter.type === 'status').map(filter => filter.value)
  const issues = filters.filter(filter => filter.type === 'issue').map(filter => filter.value)
  const operatingSystems = filters.filter(filter => filter.type === 'os').map(filter => filter.value)
  const agentFilters = filters.filter(filter => filter.type === 'agent').map(filter => filter.value)
  const scopeFilter = filters.find(filter => filter.type === 'scope')?.value
  if (statuses.length) params.set('statuses', statuses.join(','))
  if (issues.length) params.set('issues', issues.join(','))
  if (operatingSystems.length) params.set('oses', operatingSystems.join(','))
  if (agentFilters.length) params.set('agents', agentFilters.join(','))
  if (scopeFilter) params.set('scope', scopeFilter)
  if (search) params.set('search', search)

  const filterSignature = filters.map(filterKey).sort().join('|')

  const { data: endpoints = [], isLoading } = useQuery<ComplianceEndpoint[]>({
    queryKey: ['compliance-endpoints', filterSignature || 'default', search],
    queryFn: () => apiClient.get(`/compliance/endpoints?${params.toString()}`).then(r => r.data),
  })

  const displayed = filters.length ? endpoints : endpoints.filter(e => e.status !== 'compliant')

  return (
    <div className="flex flex-1 overflow-hidden">
      {/* List */}
      <div className="flex flex-col w-full overflow-hidden">
        {/* List header */}
        <div className="flex-shrink-0 px-4 py-3 border-b border-white/[0.06] bg-zinc-950/80">
          <div className="flex items-center justify-between mb-2.5">
            <div className="flex items-center gap-2 min-w-0">
              <span className="text-sm font-semibold text-white truncate">
                {filters.length ? 'Filtered endpoints' : 'Non-Compliant Endpoints'}
              </span>
              <span className="text-xs text-zinc-500 flex-shrink-0">({displayed.length})</span>
            </div>
            {filters.length > 0 && (
              <button type="button" onClick={onClearFilters} className="text-[11px] text-zinc-500 transition-colors hover:text-zinc-200">
                Clear all
              </button>
            )}
          </div>
          {filters.length > 0 && (
            <div className="mb-2.5 flex flex-wrap gap-1.5">
              {filters.map(filter => (
                <button
                  key={filterKey(filter)}
                  type="button"
                  onClick={() => onRemoveFilter(filter)}
                  className="inline-flex max-w-full items-center gap-1.5 rounded-md border border-white/[0.08] bg-zinc-900 px-2 py-1 text-[10px] text-zinc-300 transition-colors hover:border-white/[0.16]"
                >
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: filter.color }} />
                  <span className="truncate">{filter.label}</span>
                  <X size={10} className="shrink-0 text-zinc-600" />
                </button>
              ))}
            </div>
          )}
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search hostname…"
              className="w-full bg-zinc-900 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg pl-7 pr-3 py-1.5 text-xs focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>

        {/* Rows */}
        <div className="flex-1 overflow-y-auto divide-y divide-gray-800/60">
          {isLoading ? (
            <div className="flex justify-center py-12">
              <div className="w-6 h-6 shimmer rounded-md" />
            </div>
          ) : displayed.length === 0 ? (
            <div className="flex flex-col items-center py-14 text-zinc-600">
              <ShieldCheck size={28} className="mb-2 text-emerald-400/40" />
              <p className="text-sm">{filters.length ? 'No endpoints match these filters' : 'All endpoints are compliant'}</p>
            </div>
          ) : (
            displayed.map(ep => (
              <div
                key={ep.endpoint_id}
                className="group flex w-full items-start gap-3 px-4 py-3 text-left"
                style={{ transition: 'background-color 150ms ease' }}
                onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.03)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                <button
                  type="button"
                  onClick={() => openPanel('endpoint', ep.endpoint_id, ep.hostname)}
                  className="flex min-w-0 flex-1 items-start gap-3 text-left"
                >
                  <Monitor size={14} className="mt-0.5 flex-shrink-0 text-zinc-500" />
                  <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium text-white truncate">{ep.hostname}</span>
                    {ep.compliance_excluded
                      ? <span className="rounded-full border border-amber-500/25 bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-300">Excluded</span>
                      : <StatusPill status={ep.status} />}
                  </div>
                  <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                    {ep.owner_email
                      ? <span className="text-xs text-zinc-500 flex items-center gap-1"><User size={10} />{ep.owner_email}</span>
                      : <span className="text-xs text-yellow-700">Unassigned</span>
                    }
                    {ep.os_version && <span className="text-xs text-zinc-700">· {ep.os_version.slice(0, 30)}</span>}
                  </div>
                  {ep.failures.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {ep.failures.map(f => <FailurePill key={f} label={f} />)}
                    </div>
                  )}
                  {agents.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {agents.map(agent => (
                        <AgentPill
                          key={agent.key}
                          label={agent.label}
                          present={Boolean(ep.agent_presence[agent.key])}
                          excluded={ep.excluded_agents.includes(agent.key)}
                        />
                      ))}
                    </div>
                  )}
                  </div>
                </button>
                {canEditScope && (
                  <button
                    type="button"
                    onClick={() => setEditingScope(ep)}
                    title="Edit compliance scope"
                    aria-label={`Edit compliance scope for ${ep.hostname}`}
                    className={`mt-0.5 rounded-lg p-1.5 transition-colors ${ep.compliance_excluded || ep.excluded_agents.length ? 'bg-amber-500/10 text-amber-300' : 'text-zinc-600 hover:bg-white/[0.06] hover:text-zinc-200'}`}
                  >
                    <Settings2 size={14} />
                  </button>
                )}
                <ChevronRight size={13} className="mt-1.5 flex-shrink-0 text-zinc-600 transition-colors group-hover:text-emerald-400" />
              </div>
            ))
          )}
        </div>
      </div>
      {editingScope && <ExclusionDialog endpoint={editingScope} agents={agents} onClose={() => setEditingScope(null)} />}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function Compliance() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [activeFilters, setActiveFilters] = useState<ActiveFilter[]>(() => {
    const initial: ActiveFilter[] = []
    const labelMap: Record<string, string> = { compliant: 'Compliant', partial: 'Partial', non_compliant: 'Non-Compliant' }
    const statuses = (searchParams.get('statuses') || searchParams.get('status') || '').split(',').filter(Boolean)
    const issues = (searchParams.get('issues') || searchParams.get('issue') || '').split(',').filter(Boolean)
    const operatingSystems = (searchParams.get('oses') || searchParams.get('os') || '').split(',').filter(Boolean)
    const agentFilters = (searchParams.get('agents') || '').split(',').filter(Boolean)
    const scope = searchParams.get('scope')
    statuses.forEach(value => {
      if (STATUS_COLORS[value]) initial.push({ type: 'status', value, label: labelMap[value] ?? value, color: STATUS_COLORS[value] })
    })
    issues.forEach(value => {
      if (ISSUE_META[value]) initial.push({ type: 'issue', value, label: ISSUE_META[value].label, color: ISSUE_META[value].color })
    })
    operatingSystems.forEach(value => initial.push({ type: 'os', value, label: value, color: STATUS_COLORS.partial }))
    agentFilters.forEach(value => initial.push({ type: 'agent', value, label: value.replace(':', ' · '), color: '#22d3ee' }))
    if (scope === 'excluded') initial.push({ type: 'scope', value: 'excluded', label: 'Excluded endpoints', color: '#f59e0b' })
    return initial
  })
  const qc = useQueryClient()

  const { data, isLoading, refetch, isRefetching } = useQuery<ComplianceDashboard>({
    queryKey: ['compliance-dashboard'],
    queryFn: () => apiClient.get('/compliance/dashboard').then(r => r.data),
  })

  const evaluateMutation = useMutation({
    mutationFn: () => apiClient.post('/compliance/evaluate').then(r => r.data),
    onSuccess: () => {
      setTimeout(() => {
        refetch()
        qc.invalidateQueries({ queryKey: ['compliance-endpoints'] })
      }, 2500)
    },
  })

  React.useEffect(() => {
    const next = new URLSearchParams()
    const statuses = activeFilters.filter(filter => filter.type === 'status').map(filter => filter.value)
    const issues = activeFilters.filter(filter => filter.type === 'issue').map(filter => filter.value)
    const operatingSystems = activeFilters.filter(filter => filter.type === 'os').map(filter => filter.value)
    const agentFilters = activeFilters.filter(filter => filter.type === 'agent').map(filter => filter.value)
    const scope = activeFilters.find(filter => filter.type === 'scope')?.value
    if (statuses.length) next.set('statuses', statuses.join(','))
    if (issues.length) next.set('issues', issues.join(','))
    if (operatingSystems.length) next.set('oses', operatingSystems.join(','))
    if (agentFilters.length) next.set('agents', agentFilters.join(','))
    if (scope) next.set('scope', scope)
    setSearchParams(next, { replace: true })
  }, [activeFilters, setSearchParams])

  function toggleFilter(filter: ActiveFilter) {
    setActiveFilters(current => current.some(item => filterKey(item) === filterKey(filter))
      ? current.filter(item => filterKey(item) !== filterKey(filter))
      : [...current, filter])
  }

  function isFilterActive(type: ActiveFilter['type'], value: string) {
    return activeFilters.some(filter => filter.type === type && filter.value === value)
  }

  if (isLoading) {
    return (
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="space-y-3 p-4"><div className="h-4 shimmer rounded" style={{ animationDelay: "0ms" }} /><div className="h-4 shimmer rounded" style={{ animationDelay: "40ms" }} /><div className="h-4 shimmer rounded" style={{ animationDelay: "80ms" }} /><div className="h-4 shimmer rounded" style={{ animationDelay: "120ms" }} /></div>
      </div>
    )
  }

  const s   = data?.summary  ?? { total: 0, compliant: 0, partial: 0, non_compliant: 0, compliant_pct: 0 }
  const iss = data?.issues ?? {
    no_edr: 0, edr_outdated: 0, no_dlp: 0, dlp_outdated: 0,
    no_wss: 0, wss_outdated: 0, no_network_security: 0,
    not_encrypted: 0, no_device_control: 0,
  }
  const osd = data?.os_breakdown ?? []
  const agentCoverage = data?.agent_coverage ?? []
  const excludedTotal = data?.excluded_total ?? 0
  const activeAgentKeys = new Set(agentCoverage.map(agent => agent.key))

  const pieData = [
    { name: 'Compliant',     value: s.compliant,     color: STATUS_COLORS.compliant },
    { name: 'Partial',       value: s.partial,        color: STATUS_COLORS.partial },
    { name: 'Non-Compliant', value: s.non_compliant,  color: STATUS_COLORS.non_compliant },
  ].filter(d => d.value > 0)

  return (
    <div className="compliance-layout absolute inset-0 flex overflow-hidden">

      {/* ── Left panel (sticky) ───────────────────────────────────────── */}
      <div className="compliance-overview w-[340px] flex-shrink-0 flex flex-col overflow-hidden border-r border-white/[0.06] bg-gray-950">
        {/* Header */}
        <div className="flex-shrink-0 px-5 pt-5 pb-3 flex items-center justify-between">
          <div>
            <h1 className="text-base font-bold text-white">Compliance</h1>
            <p className="text-xs text-zinc-500 mt-0.5">{s.total} endpoints evaluated</p>
          </div>
          <button
            onClick={() => evaluateMutation.mutate()}
            disabled={evaluateMutation.isPending || isRefetching}
            className="flex items-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300 bg-emerald-500/10 border border-emerald-500/15 px-2.5 py-1.5 rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw size={12} className={(evaluateMutation.isPending || isRefetching) ? 'animate-spin' : ''} />
            Re-evaluate
          </button>
        </div>

        <div className="compliance-overview-scroll flex-1 overflow-y-auto px-4 pb-5 space-y-4">
          {/* KPI cards */}
          <div className="space-y-2">
            <KpiCard
              value={`${s.compliant_pct}%`}
              label="Compliance Rate"
              sub={`${s.compliant} of ${s.total} compliant`}
              color="text-emerald-300"
              icon={ShieldCheck}
              active={isFilterActive('status', 'compliant')}
              onClick={() => toggleFilter({ type: 'status', value: 'compliant', label: 'Compliant', color: STATUS_COLORS.compliant })}
            />
            <div className="grid grid-cols-2 gap-2">
              <KpiCard
                value={s.non_compliant}
                label="Non-Compliant"
                color="text-red-400"
                icon={ShieldOff}
                active={isFilterActive('status', 'non_compliant')}
                onClick={() => toggleFilter({ type: 'status', value: 'non_compliant', label: 'Non-Compliant', color: STATUS_COLORS.non_compliant })}
              />
              <KpiCard
                value={s.partial}
                label="Partial"
                color="text-yellow-400"
                icon={ShieldAlert}
                active={isFilterActive('status', 'partial')}
                onClick={() => toggleFilter({ type: 'status', value: 'partial', label: 'Partial', color: STATUS_COLORS.partial })}
              />
            </div>
            {excludedTotal > 0 && (
              <button
                type="button"
                onClick={() => toggleFilter({ type: 'scope', value: 'excluded', label: 'Excluded endpoints', color: '#f59e0b' })}
                className={`flex w-full items-center gap-3 rounded-xl border px-4 py-3 text-left transition-colors ${isFilterActive('scope', 'excluded') ? 'border-amber-500/40 bg-amber-500/[0.08]' : 'border-white/[0.06] bg-zinc-950 hover:border-white/[0.12]'}`}
              >
                <Ban size={17} className="text-amber-300" />
                <span className="flex-1 text-xs text-zinc-400">Excluded endpoints</span>
                <span className="text-sm font-semibold text-white">{excludedTotal}</span>
              </button>
            )}
          </div>

          {agentCoverage.length > 0 && (
            <div className="rounded-xl card p-4">
              <div className="mb-1 text-xs font-semibold uppercase tracking-wider text-zinc-400">Agent coverage</div>
              <p className="mb-3 text-[11px] leading-4 text-zinc-600">Connected endpoint agents are active compliance requirements.</p>
              <div className="space-y-3">
                {agentCoverage.map(agent => {
                  const hasValue = `${agent.key}:has`
                  const missingValue = `${agent.key}:missing`
                  return (
                    <div key={agent.key}>
                      <div className="mb-1.5 flex items-center justify-between gap-2">
                        <span className="truncate text-xs font-medium text-zinc-300">{agent.label}</span>
                        <span className="text-[11px] font-semibold text-zinc-400">{agent.coverage_pct}%</span>
                      </div>
                      <div className="mb-2 h-1 overflow-hidden rounded-full bg-zinc-900">
                        <div className="h-full rounded-full bg-emerald-400 transition-[width] duration-500" style={{ width: `${Math.min(agent.coverage_pct, 100)}%` }} />
                      </div>
                      <div className="grid grid-cols-2 gap-1.5">
                        <button
                          type="button"
                          onClick={() => toggleFilter({ type: 'agent', value: hasValue, label: `${agent.label} · Has`, color: STATUS_COLORS.compliant })}
                          className={`rounded-lg border px-2 py-1.5 text-left transition-colors ${isFilterActive('agent', hasValue) ? 'border-emerald-500/35 bg-emerald-500/10' : 'border-white/[0.06] hover:bg-white/[0.04]'}`}
                        >
                          <span className="block text-[10px] text-zinc-600">Has</span>
                          <span className="text-xs font-semibold text-emerald-300">{agent.has}</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => toggleFilter({ type: 'agent', value: missingValue, label: `${agent.label} · Missing`, color: STATUS_COLORS.non_compliant })}
                          className={`rounded-lg border px-2 py-1.5 text-left transition-colors ${isFilterActive('agent', missingValue) ? 'border-red-500/35 bg-red-500/[0.08]' : 'border-white/[0.06] hover:bg-white/[0.04]'}`}
                        >
                          <span className="block text-[10px] text-zinc-600">Missing</span>
                          <span className="text-xs font-semibold text-red-300">{agent.missing}</span>
                        </button>
                      </div>
                      {agent.excluded > 0 && <div className="mt-1.5 text-[10px] text-amber-400/80">{agent.excluded} excluded from scoring</div>}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Donut + legend */}
          <div className="rounded-xl card p-4">
            <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-3">Distribution</div>
            <div className="flex items-center gap-4">
              <div className="flex-shrink-0">
                <PieChart width={110} height={110}>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={34} outerRadius={52}
                    paddingAngle={2} dataKey="value">
                    {pieData.map((e, i) => <Cell key={i} fill={e.color} />)}
                  </Pie>
                  <Tooltip
                    content={({ active, payload }) =>
                      active && payload?.[0] ? (
                        <div className="bg-zinc-900 border border-white/[0.08] rounded px-2 py-1 text-xs text-white">
                          {payload[0].name}: {payload[0].value}
                        </div>
                      ) : null
                    }
                  />
                </PieChart>
              </div>
              <div className="flex-1 space-y-2 min-w-0">
                {[
                  { key: 'compliant',     label: 'Compliant',     count: s.compliant },
                  { key: 'partial',       label: 'Partial',       count: s.partial },
                  { key: 'non_compliant', label: 'Non-Compliant', count: s.non_compliant },
                ].map(({ key, label, count }) => (
                  <button
                    key={key}
                    onClick={() => toggleFilter({ type: 'status', value: key, label, color: STATUS_COLORS[key] })}
                    className={`w-full text-left rounded-lg px-2 py-1.5 transition-colors ${
                      isFilterActive('status', key) ? 'bg-zinc-900 ring-1 ring-inset ring-gray-600' : 'hover:bg-white/[0.04]/60'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 min-w-0">
                        <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: STATUS_COLORS[key] }} />
                        <span className="text-xs text-zinc-400 truncate">{label}</span>
                      </div>
                      <span className="text-xs font-semibold text-white ml-2">{count}</span>
                    </div>
                    <div className="mt-1 h-1 bg-zinc-900 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-[width] duration-500"
                        style={{ width: s.total ? `${count / s.total * 100}%` : '0%', backgroundColor: STATUS_COLORS[key] }}
                      />
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Issues — interactive rows */}
          <div className="rounded-xl card p-4">
            <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-3">Issues Breakdown</div>
            <div className="space-y-1">
              {Object.entries(ISSUE_META).filter(([key]) => activeAgentKeys.has(ISSUE_AGENT[key])).map(([key, meta]) => {
                const count = (iss as any)[key] as number ?? 0
                const pct = s.total > 0 ? count / s.total * 100 : 0
                const isActive = isFilterActive('issue', key)
                return (
                  <button
                    key={key}
                    onClick={() => toggleFilter({ type: 'issue', value: key, label: meta.label, color: meta.color })}
                    className={`w-full text-left rounded-lg px-3 py-2.5 transition-colors group ${
                      isActive ? 'bg-zinc-900 ring-1 ring-inset ring-gray-600' : 'hover:bg-white/[0.04]/60'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 mb-1.5">
                      <meta.icon size={13} style={{ color: meta.color }} className="flex-shrink-0" />
                      <span className="text-xs text-zinc-300 flex-1 truncate">{meta.label}</span>
                      <span className="text-xs font-semibold text-white">{count}</span>
                      <span className="text-xs text-zinc-600">{Math.round(pct)}%</span>
                      {isActive && <ChevronRight size={11} className="text-emerald-400 flex-shrink-0" />}
                    </div>
                    <div className="h-1 bg-zinc-900 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-[width] duration-500"
                        style={{ width: `${pct}%`, backgroundColor: meta.color }}
                      />
                    </div>
                  </button>
                )
              })}
            </div>
          </div>

          {/* OS breakdown — clickable cards */}
          {osd.length > 0 && (
            <div className="rounded-xl card p-4">
              <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-3">By OS</div>
              <div className="space-y-1">
                {osd.map(os => {
                  const pct = os.total > 0 ? Math.round(os.compliant / os.total * 100) : 0
                  const barColor = pct >= 80 ? STATUS_COLORS.compliant : pct >= 50 ? STATUS_COLORS.partial : STATUS_COLORS.non_compliant
                  const isActive = isFilterActive('os', os.os)
                  return (
                    <button
                      key={os.os}
                      onClick={() => toggleFilter({ type: 'os', value: os.os, label: os.os, color: barColor })}
                      className={`w-full text-left rounded-lg px-3 py-2.5 transition-colors ${
                        isActive ? 'bg-zinc-900 ring-1 ring-inset ring-gray-600' : 'hover:bg-white/[0.04]/60'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-xs text-zinc-300 font-medium">{os.os}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold" style={{ color: barColor }}>{pct}%</span>
                          <span className="text-xs text-zinc-600">{os.total}</span>
                          {isActive && <ChevronRight size={11} className="text-emerald-400" />}
                        </div>
                      </div>
                      <div className="h-1 bg-zinc-900 rounded-full overflow-hidden">
                        <div className="h-full rounded-full transition-[width] duration-500" style={{ width: `${pct}%`, backgroundColor: barColor }} />
                      </div>
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {/* Active filter hint */}
          {activeFilters.length > 0 && (
            <button
              onClick={() => setActiveFilters([])}
              className="w-full flex items-center justify-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-300 py-1 transition-colors"
            >
              <X size={11} /> Clear {activeFilters.length} filters
            </button>
          )}
        </div>
      </div>

      {/* ── Right panel (endpoint list) ───────────────────────────────── */}
      <div className="compliance-results flex-1 flex overflow-hidden">
        <EndpointList
          filters={activeFilters}
          agents={agentCoverage}
          onRemoveFilter={toggleFilter}
          onClearFilters={() => setActiveFilters([])}
        />
      </div>
    </div>
  )
}
