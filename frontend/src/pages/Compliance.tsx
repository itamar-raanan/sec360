import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { PieChart, Pie, Cell, Tooltip } from 'recharts'
import {
  ShieldCheck, ShieldAlert, ShieldOff, RefreshCw,
  Monitor, User, ChevronRight, X, Search, LockOpen,
  PackageX, Cpu, HardDrive, MousePointer,
} from 'lucide-react'
import apiClient from '../api/client'
import { usePanelStore } from '../store/panels'

// ─── Types ───────────────────────────────────────────────────────────────────

interface DashboardSummary {
  total: number; compliant: number; partial: number
  non_compliant: number; compliant_pct: number
}
interface DashboardIssues {
  no_edr: number; edr_outdated: number
  no_dlp: number; dlp_outdated: number
  not_encrypted: number; no_device_control: number
}
interface OsBreakdown { os: string; total: number; compliant: number; non_compliant: number }
interface ComplianceDashboard {
  summary: DashboardSummary; issues: DashboardIssues
  os_breakdown: OsBreakdown[]; worst_offenders: any[]
}
interface ComplianceEndpoint {
  endpoint_id: string; hostname: string; os_version: string | null
  owner_email: string | null; owner_name: string | null; status: string
  edr_installed: boolean; edr_version_ok: boolean
  dlp_installed: boolean; dlp_version_ok: boolean
  disk_encrypted: boolean | null; device_control_enabled: boolean | null
  failure_count: number; failures: string[]; last_evaluated: string | null
}
interface ActiveFilter {
  type: 'status' | 'issue' | 'os'
  value: string
  label: string
  color: string
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

function EndpointList({ filter }: { filter: ActiveFilter | null }) {
  const [search, setSearch] = useState('')
  const { openPanel } = usePanelStore()

  // Reset search when filter changes
  React.useEffect(() => { setSearch('') }, [filter?.value])

  const params = new URLSearchParams({ limit: '200' })
  if (filter?.type === 'status') params.set('status', filter.value)
  if (filter?.type === 'issue')  params.set('issue', filter.value)
  if (filter?.type === 'os')     params.set('os', filter.value)
  if (search) params.set('search', search)

  const { data: endpoints = [], isLoading } = useQuery<ComplianceEndpoint[]>({
    queryKey: ['compliance-endpoints', filter?.value ?? 'default', search],
    queryFn: () => {
      // default: show all non-compliant + partial
      const p = filter ? params : new URLSearchParams({ limit: '200' })
      if (!filter) {
        // no filter → show problematic endpoints only (not compliant)
        // we'll fetch all and filter client-side, or just use status=non_compliant,partial
        // API doesn't support OR status, so fetch without status filter but show all
      }
      if (search) p.set('search', search)
      return apiClient.get(`/compliance/endpoints?${p.toString()}`).then(r => r.data)
    },
  })

  const displayed = filter
    ? endpoints
    : endpoints.filter(e => e.status !== 'compliant')

  return (
    <div className="flex flex-1 overflow-hidden">
      {/* List */}
      <div className="flex flex-col w-full overflow-hidden">
        {/* List header */}
        <div className="flex-shrink-0 px-4 py-3 border-b border-white/[0.06] bg-zinc-950/80">
          <div className="flex items-center justify-between mb-2.5">
            <div className="flex items-center gap-2 min-w-0">
              {filter ? (
                <>
                  <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: filter.color }} />
                  <span className="text-sm font-semibold text-white truncate">{filter.label}</span>
                </>
              ) : (
                <span className="text-sm font-semibold text-white">Non-Compliant Endpoints</span>
              )}
              <span className="text-xs text-zinc-500 flex-shrink-0">({displayed.length})</span>
            </div>
          </div>
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
              <p className="text-sm">All endpoints are compliant</p>
            </div>
          ) : (
            displayed.map(ep => (
              <button
                key={ep.endpoint_id}
                onClick={() => openPanel('endpoint', ep.endpoint_id, ep.hostname)}
                className="w-full text-left flex items-start gap-3 px-4 py-3 group"
                style={{ transition: 'background-color 150ms ease' }}
                onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.03)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                <Monitor size={14} className="text-zinc-500 mt-0.5 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium text-white truncate">{ep.hostname}</span>
                    <StatusPill status={ep.status} />
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
                </div>
                <ChevronRight size={13} className="text-zinc-600 group-hover:text-emerald-400 flex-shrink-0 mt-0.5" style={{ transition: 'color 150ms ease' }} />
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function Compliance() {
  const [searchParams] = useSearchParams()
  const [activeFilter, setActiveFilter] = useState<ActiveFilter | null>(() => {
    const issue  = searchParams.get('issue')
    const status = searchParams.get('status')
    const os     = searchParams.get('os')
    if (issue  && ISSUE_META[issue])  return { type: 'issue',  value: issue,  label: ISSUE_META[issue].label,  color: ISSUE_META[issue].color }
    if (status && STATUS_COLORS[status]) {
      const labelMap: Record<string, string> = { compliant: 'Compliant', partial: 'Partial', non_compliant: 'Non-Compliant' }
      return { type: 'status', value: status, label: labelMap[status] ?? status, color: STATUS_COLORS[status] }
    }
    if (os) return { type: 'os', value: os, label: os, color: STATUS_COLORS.partial }
    return null
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

  function toggleFilter(f: ActiveFilter) {
    setActiveFilter(prev => (prev?.value === f.value && prev?.type === f.type) ? null : f)
  }

  if (isLoading) {
    return (
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="space-y-3 p-4"><div className="h-4 shimmer rounded" style={{ animationDelay: "0ms" }} /><div className="h-4 shimmer rounded" style={{ animationDelay: "40ms" }} /><div className="h-4 shimmer rounded" style={{ animationDelay: "80ms" }} /><div className="h-4 shimmer rounded" style={{ animationDelay: "120ms" }} /></div>
      </div>
    )
  }

  const s   = data?.summary  ?? { total: 0, compliant: 0, partial: 0, non_compliant: 0, compliant_pct: 0 }
  const iss = data?.issues   ?? { no_edr: 0, edr_outdated: 0, no_dlp: 0, dlp_outdated: 0, not_encrypted: 0, no_device_control: 0 }
  const osd = data?.os_breakdown ?? []

  const pieData = [
    { name: 'Compliant',     value: s.compliant,     color: STATUS_COLORS.compliant },
    { name: 'Partial',       value: s.partial,        color: STATUS_COLORS.partial },
    { name: 'Non-Compliant', value: s.non_compliant,  color: STATUS_COLORS.non_compliant },
  ].filter(d => d.value > 0)

  return (
    <div className="absolute inset-0 flex overflow-hidden">

      {/* ── Left panel (sticky) ───────────────────────────────────────── */}
      <div className="w-[340px] flex-shrink-0 flex flex-col overflow-hidden border-r border-white/[0.06] bg-gray-950">
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

        <div className="flex-1 overflow-y-auto px-4 pb-5 space-y-4">
          {/* KPI cards */}
          <div className="space-y-2">
            <KpiCard
              value={`${s.compliant_pct}%`}
              label="Compliance Rate"
              sub={`${s.compliant} of ${s.total} compliant`}
              color="text-emerald-300"
              icon={ShieldCheck}
              active={activeFilter?.value === 'compliant'}
              onClick={() => toggleFilter({ type: 'status', value: 'compliant', label: 'Compliant', color: STATUS_COLORS.compliant })}
            />
            <div className="grid grid-cols-2 gap-2">
              <KpiCard
                value={s.non_compliant}
                label="Non-Compliant"
                color="text-red-400"
                icon={ShieldOff}
                active={activeFilter?.value === 'non_compliant'}
                onClick={() => toggleFilter({ type: 'status', value: 'non_compliant', label: 'Non-Compliant', color: STATUS_COLORS.non_compliant })}
              />
              <KpiCard
                value={s.partial}
                label="Partial"
                color="text-yellow-400"
                icon={ShieldAlert}
                active={activeFilter?.value === 'partial'}
                onClick={() => toggleFilter({ type: 'status', value: 'partial', label: 'Partial', color: STATUS_COLORS.partial })}
              />
            </div>
          </div>

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
                      activeFilter?.value === key ? 'bg-zinc-900 ring-1 ring-inset ring-gray-600' : 'hover:bg-white/[0.04]/60'
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
              {Object.entries(ISSUE_META).map(([key, meta]) => {
                const count = (iss as any)[key] as number ?? 0
                const pct = s.total > 0 ? count / s.total * 100 : 0
                const isActive = activeFilter?.type === 'issue' && activeFilter.value === key
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
                  const isActive = activeFilter?.type === 'os' && activeFilter.value === os.os
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
          {activeFilter && (
            <button
              onClick={() => setActiveFilter(null)}
              className="w-full flex items-center justify-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-300 py-1 transition-colors"
            >
              <X size={11} /> Clear filter
            </button>
          )}
        </div>
      </div>

      {/* ── Right panel (endpoint list) ───────────────────────────────── */}
      <div className="flex-1 flex overflow-hidden">
        <EndpointList filter={activeFilter} />
      </div>
    </div>
  )
}
