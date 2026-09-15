import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import {
  Monitor, CheckCircle, XCircle, AlertTriangle,
  User, Mail, Clock, Cpu, Wifi, Building2,
  Shield, ShieldOff, Hash, Tag,
  Sliders, X, Check, LayoutList, Server, Lock, ChevronDown, RefreshCw,
} from 'lucide-react'
import apiClient from '../../api/client'
import RiskBadge from '../shared/RiskBadge'
import { SkeletonDetailPanel } from '../shared/Skeleton'
import StatusBadge from '../shared/StatusBadge'
import NoteBox from '../shared/NoteBox'
import { useAuthStore } from '../../store/auth'
import type { Endpoint } from '../../types'
import { useEndpointProductTags } from '../../hooks/useEndpointProductTags'
import { useConnectedIntegrations } from '../../hooks/useConnectedIntegrations'
import { primaryEndpointActivity } from '../../utils/endpointActivity'

interface AgentDetail {
  installed: boolean
  status: string | null
  version: string | null
  last_seen: string | null
  disk_encrypted: boolean | null
  encryption_status: string | null
  device_control_enabled: boolean | null
  agent_group: string | null
  agent_state: string | null
}

interface EndpointDetail extends Endpoint {
  sentinelone: AgentDetail
  symantec_dlp: AgentDetail
  symantec_wss: AgentDetail
}

type Tab = 'overview' | 'agents' | 'security'

const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: 'overview',  label: 'Overview', icon: LayoutList },
  { id: 'agents',    label: 'Agents',   icon: Server },
  { id: 'security',  label: 'Security', icon: Lock },
]

function relTime(ts: string | null | undefined): string {
  if (!ts) return 'Never'
  try { return formatDistanceToNow(new Date(ts), { addSuffix: true }) }
  catch { return 'Unknown' }
}

function InfoRow({ icon: Icon, label, value, mono = false, colorClass }: {
  icon: React.ElementType; label: string; value: React.ReactNode; mono?: boolean; colorClass?: string
}) {
  return (
    <div className="flex items-start gap-3 px-4 py-2.5">
      <Icon className="w-3.5 h-3.5 text-zinc-500 flex-shrink-0 mt-0.5" />
      <span className="text-xs text-zinc-500 w-24 flex-shrink-0 pt-px">{label}</span>
      <span className={`text-sm break-all ${mono ? 'font-mono' : ''} ${colorClass ?? 'text-zinc-200'}`}>{value}</span>
    </div>
  )
}

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest px-1">
      {children}
    </div>
  )
}

function RiskOverrideSection({ endpointId, current, note }: {
  endpointId: string
  current: number | null
  note: string | null
}) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [value, setValue] = useState(current != null ? String(Math.round(current)) : '')
  const [noteVal, setNoteVal] = useState(note ?? '')

  const mutation = useMutation({
    mutationFn: (body: { override: number | null; note: string | null }) =>
      apiClient.patch(`/endpoints/${endpointId}/risk-override`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['endpoint-detail', endpointId] })
      qc.invalidateQueries({ queryKey: ['endpoints-all'] })
      setOpen(false)
    },
  })

  const handleSave = () => {
    const parsed = value === '' ? null : Number(value)
    if (parsed !== null && (isNaN(parsed) || parsed < 0 || parsed > 100)) return
    mutation.mutate({ override: parsed, note: noteVal || null })
  }

  const handleClear = () => {
    setValue('')
    setNoteVal('')
    mutation.mutate({ override: null, note: null })
  }

  return (
    <div className="rounded-lg border border-white/[0.08] overflow-hidden"
      style={{ background: current != null ? 'rgba(245,158,11,0.05)' : 'var(--surface-inset)' }}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-3.5 py-2.5 text-left"
      >
        <div className="flex items-center gap-2">
          <Sliders size={13} className={current != null ? 'text-amber-400' : 'text-zinc-500'} />
          <span className="text-xs font-medium text-zinc-300">Risk override</span>
          {current != null && (
            <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/20 font-medium">
              {Math.round(current)} overriding computed
            </span>
          )}
        </div>
        <span className="text-zinc-600 text-xs">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div className="border-t border-white/[0.06] px-3.5 py-3 space-y-2.5">
          <div className="flex items-center gap-2">
            <div className="flex-1">
              <label className="block text-[10px] text-zinc-500 mb-1">Override score (0–100)</label>
              <input
                type="number" min={0} max={100} value={value}
                onChange={e => setValue(e.target.value)}
                placeholder="Leave blank to clear"
                className="w-full bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-1.5 text-sm font-mono focus:outline-none focus:border-amber-500"
              />
            </div>
          </div>
          <div>
            <label className="block text-[10px] text-zinc-500 mb-1">Note (reason)</label>
            <input
              type="text" value={noteVal} onChange={e => setNoteVal(e.target.value)}
              placeholder="e.g. Approved exception — CEO laptop"
              className="w-full bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-amber-500"
            />
          </div>
          <div className="flex gap-2 pt-0.5">
            <button onClick={handleSave} disabled={mutation.isPending}
              className="flex items-center gap-1 text-xs font-medium px-3 py-1.5 rounded-lg"
              style={{ background: 'rgba(245,158,11,0.15)', color: '#fbbf24', border: '1px solid rgba(245,158,11,0.25)' }}>
              <Check size={11} /> {mutation.isPending ? 'Saving…' : 'Save'}
            </button>
            {current != null && (
              <button onClick={handleClear} disabled={mutation.isPending}
                className="flex items-center gap-1 text-xs font-medium px-3 py-1.5 rounded-lg"
                style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)' }}>
                <X size={11} /> Clear override
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

interface ComplianceAgentOption {
  key: string
  label: string
  description: string
}

function ComplianceScopeControl({ endpoint }: { endpoint: EndpointDetail }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [excludeAll, setExcludeAll] = useState(Boolean(endpoint.compliance_excluded))
  const [excludedAgents, setExcludedAgents] = useState<string[]>(endpoint.excluded_agents ?? [])
  const [reason, setReason] = useState(endpoint.compliance_exclusion_reason ?? '')
  const { data } = useQuery<{ agent_coverage: ComplianceAgentOption[] }>({
    queryKey: ['compliance-dashboard'],
    queryFn: () => apiClient.get('/compliance/dashboard').then(response => response.data),
  })
  const agents = data?.agent_coverage ?? []
  const hasExclusion = excludeAll || excludedAgents.length > 0
  const persistedExclusion = Boolean(endpoint.compliance_excluded) || Boolean(endpoint.excluded_agents?.length)

  const mutation = useMutation({
    mutationFn: (payload: { exclude_all: boolean; excluded_agents: string[]; reason: string | null }) =>
      apiClient.put(`/compliance/endpoints/${endpoint.id}/exclusions`, payload),
    onSuccess: async (_response, payload) => {
      setExcludeAll(payload.exclude_all)
      setExcludedAgents(payload.excluded_agents)
      setReason(payload.reason ?? '')
      await Promise.all([
        qc.invalidateQueries({ queryKey: ['endpoint-detail', endpoint.id] }),
        qc.invalidateQueries({ queryKey: ['endpoints-all'] }),
        qc.invalidateQueries({ queryKey: ['compliance-dashboard'] }),
        qc.invalidateQueries({ queryKey: ['compliance-endpoints'] }),
      ])
      setOpen(false)
    },
  })
  const error = (mutation.error as any)?.response?.data?.detail || (mutation.error as Error | null)?.message

  function toggleAgent(key: string) {
    setExcludedAgents(current => current.includes(key)
      ? current.filter(item => item !== key)
      : [...current, key])
  }

  function save() {
    mutation.mutate({
      exclude_all: excludeAll,
      excluded_agents: excludeAll ? [] : excludedAgents,
      reason: hasExclusion ? reason.trim() : null,
    })
  }

  return (
    <div className={`overflow-hidden rounded-xl border ${persistedExclusion ? 'border-amber-500/30 bg-amber-500/[0.06]' : 'border-white/[0.09] bg-zinc-900/60'}`}>
      <button
        type="button"
        onClick={() => setOpen(current => !current)}
        className="flex w-full items-center gap-3 px-3.5 py-3 text-left transition-colors hover:bg-white/[0.035] active:scale-[0.99]"
        aria-expanded={open}
      >
        <span className={`flex h-8 w-8 items-center justify-center rounded-lg ${persistedExclusion ? 'bg-amber-500/15 text-amber-300' : 'bg-emerald-500/10 text-emerald-300'}`}>
          {persistedExclusion ? <ShieldOff size={15} /> : <Shield size={15} />}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-xs font-semibold text-zinc-200">Compliance scope</span>
          <span className={`mt-0.5 block truncate text-[11px] ${persistedExclusion ? 'text-amber-300/80' : 'text-zinc-500'}`}>
            {endpoint.compliance_excluded
              ? 'Endpoint excluded from compliance'
              : endpoint.excluded_agents?.length
                ? `${endpoint.excluded_agents.length} agent requirement${endpoint.excluded_agents.length === 1 ? '' : 's'} excluded`
                : 'Included in all connected-agent checks'}
          </span>
        </span>
        <span className="text-[10px] font-medium text-zinc-500">Manage</span>
        <ChevronDown size={13} className={`text-zinc-500 transition-transform duration-150 ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="space-y-3 border-t border-white/[0.07] px-3.5 py-3.5">
          <label className={`flex cursor-pointer items-start gap-2.5 rounded-lg border px-3 py-2.5 ${excludeAll ? 'border-amber-500/30 bg-amber-500/[0.08]' : 'border-white/[0.07]'}`}>
            <input type="checkbox" checked={excludeAll} onChange={event => setExcludeAll(event.target.checked)} className="mt-0.5 accent-amber-500" />
            <span>
              <span className="block text-xs font-medium text-zinc-200">Exclude endpoint completely</span>
              <span className="mt-0.5 block text-[10px] leading-4 text-zinc-500">Remove it from compliance coverage and compliance-based risk.</span>
            </span>
          </label>

          {agents.length > 0 && (
            <div className={excludeAll ? 'pointer-events-none opacity-40' : ''}>
              <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-600">Specific agent exceptions</div>
              <div className="divide-y divide-white/[0.05] rounded-lg border border-white/[0.07]">
                {agents.map(agent => (
                  <label key={agent.key} className="flex cursor-pointer items-center gap-2.5 px-3 py-2">
                    <input type="checkbox" checked={excludedAgents.includes(agent.key)} onChange={() => toggleAgent(agent.key)} className="accent-amber-500" />
                    <span className="min-w-0 flex-1 truncate text-xs text-zinc-300">{agent.label}</span>
                    <span className={`text-[10px] ${endpoint.compliance_status?.agent_presence?.[agent.key] ? 'text-emerald-400' : 'text-red-400'}`}>
                      {endpoint.compliance_status?.agent_presence?.[agent.key] ? 'Present' : 'Missing'}
                    </span>
                  </label>
                ))}
              </div>
            </div>
          )}

          <div>
            <label htmlFor={`compliance-reason-${endpoint.id}`} className="mb-1 block text-[10px] font-medium text-zinc-500">
              Reason {hasExclusion && <span className="text-red-400">*</span>}
            </label>
            <textarea
              id={`compliance-reason-${endpoint.id}`}
              rows={2}
              value={reason}
              onChange={event => setReason(event.target.value)}
              placeholder="Why is this exception approved?"
              className="w-full resize-none rounded-lg border border-white/[0.08] bg-zinc-950 px-3 py-2 text-xs text-zinc-200 placeholder:text-zinc-700 focus:border-emerald-500 focus:outline-none"
            />
          </div>
          {error && <div className="rounded-lg border border-red-500/20 bg-red-500/[0.08] px-3 py-2 text-[11px] text-red-300">{error}</div>}

          <div className="flex items-center justify-between gap-2 pt-0.5">
            <button
              type="button"
              onClick={() => mutation.mutate({ exclude_all: false, excluded_agents: [], reason: null })}
              disabled={!persistedExclusion || mutation.isPending}
              className="text-[11px] text-zinc-500 hover:text-zinc-200 disabled:cursor-not-allowed disabled:opacity-30"
            >
              Remove exclusions
            </button>
            <button
              type="button"
              onClick={save}
              disabled={mutation.isPending || (hasExclusion && !reason.trim())}
              className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-[11px] font-semibold text-zinc-950 hover:bg-emerald-400 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40"
            >
              {mutation.isPending ? <RefreshCw size={11} className="animate-spin" /> : <Check size={11} />}
              Save scope
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function AgentBlock({ label, detail, simple = false, showStateGroup = false }: { label: string; detail: AgentDetail; simple?: boolean; showStateGroup?: boolean }) {
  const isActive    = detail.installed && detail.status === 'active'
  const isInstalled = detail.installed

  if (simple) {
    return (
      <div className={`rounded-lg border ${
        isInstalled ? 'bg-emerald-500/5 border-green-500/20' : 'bg-zinc-900/60 border-white/[0.08]/50'
      }`}>
        <div className="flex items-center justify-between px-3.5 py-2.5">
          <div className="flex items-center gap-2">
            {isInstalled
              ? <Shield className="w-3.5 h-3.5 text-emerald-300" />
              : <ShieldOff className="w-3.5 h-3.5 text-zinc-500" />}
            <span className="text-xs font-semibold text-white">{label}</span>
          </div>
          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
            isInstalled ? 'text-emerald-300 bg-emerald-500/15 border-green-500/30'
            : 'text-zinc-500 bg-gray-700/30 border-gray-600/30'
          }`}>
            {isInstalled ? 'Installed' : 'Not Installed'}
          </span>
        </div>
        {isInstalled && (
          <div className="border-t border-white/[0.08]/40 px-3.5 py-2">
            <div className="text-zinc-500 text-[10px] mb-0.5">Version</div>
            <div className="text-zinc-200 font-mono text-[11px]">{detail.version || '—'}</div>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className={`rounded-lg border ${
      isActive ? 'bg-emerald-500/5 border-green-500/20'
      : isInstalled ? 'bg-yellow-500/5 border-yellow-500/20'
      : 'bg-zinc-900/60 border-white/[0.08]/50'
    }`}>
      <div className="flex items-center justify-between px-3.5 py-2.5">
        <div className="flex items-center gap-2">
          {isActive
            ? <Shield className="w-3.5 h-3.5 text-emerald-300" />
            : isInstalled
              ? <Shield className="w-3.5 h-3.5 text-yellow-400" />
              : <ShieldOff className="w-3.5 h-3.5 text-zinc-500" />}
          <span className="text-xs font-semibold text-white">{label}</span>
        </div>
        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
          isActive    ? 'text-emerald-300 bg-emerald-500/15 border-green-500/30'
          : isInstalled ? 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30'
          : 'text-zinc-500 bg-gray-700/30 border-gray-600/30'
        }`}>
          {isInstalled ? (isActive ? 'Active' : 'Inactive') : 'Not Installed'}
        </span>
      </div>

      {isInstalled ? (
        <div className="border-t border-white/[0.08]/40 divide-y divide-gray-700/30">
          <div className="grid grid-cols-2 gap-0 text-xs">
            <div className="px-3.5 py-2">
              <div className="text-zinc-500 text-[10px] mb-0.5">Version</div>
              <div className="text-zinc-200 font-mono text-[11px]">{detail.version || '—'}</div>
            </div>
            <div className="px-3.5 py-2 border-l border-white/[0.08]/30">
              <div className="text-zinc-500 text-[10px] mb-0.5">Last Seen</div>
              <div className="text-zinc-200 text-[11px]">{relTime(detail.last_seen)}</div>
            </div>
          </div>
          {showStateGroup && (
            <div className="grid grid-cols-2 gap-0 text-xs border-t border-white/[0.08]/30">
              <div className="px-3.5 py-2">
                <div className="text-zinc-500 text-[10px] mb-0.5">State</div>
                {detail.agent_state ? (
                  <div className={`text-[11px] font-medium ${
                    detail.agent_state.toLowerCase() === 'enabled'
                      ? 'text-emerald-300'
                      : detail.agent_state.toLowerCase() === 'disabled'
                        ? 'text-red-400'
                        : 'text-yellow-400'
                  }`}>{detail.agent_state}</div>
                ) : (
                  <div className="text-zinc-600 text-[11px]">—</div>
                )}
              </div>
              <div className="px-3.5 py-2 border-l border-white/[0.08]/30">
                <div className="text-zinc-500 text-[10px] mb-0.5">Group</div>
                {detail.agent_group ? (
                  <div className="text-zinc-200 text-[11px]">{detail.agent_group}</div>
                ) : (
                  <div className="text-zinc-600 text-[11px]">—</div>
                )}
              </div>
            </div>
          )}
          {(!showStateGroup && detail.agent_group) && (
            <div className="grid grid-cols-2 gap-0 text-xs border-t border-white/[0.08]/30">
              <div className="px-3.5 py-2 col-span-2">
                <div className="text-zinc-500 text-[10px] mb-0.5">Group</div>
                <div className="text-emerald-300 text-[11px]">{detail.agent_group}</div>
              </div>
            </div>
          )}
          {(detail.disk_encrypted !== null || detail.device_control_enabled !== null) && (
            <div className="grid grid-cols-2 gap-0 text-xs border-t border-white/[0.08]/30">
              {detail.disk_encrypted !== null && detail.disk_encrypted !== undefined && (
                <div className="px-3.5 py-2">
                  <div className="text-zinc-500 text-[10px] mb-0.5">Disk</div>
                  <div className={`text-[11px] font-medium ${detail.disk_encrypted ? 'text-emerald-300' : 'text-red-400'}`}>
                    {detail.disk_encrypted ? 'Encrypted' : 'Not Encrypted'}
                    {detail.encryption_status === 'not_applicable' ? ' (N/A)' : ''}
                  </div>
                </div>
              )}
              {detail.device_control_enabled !== null && detail.device_control_enabled !== undefined && (
                <div className={`px-3.5 py-2 ${detail.disk_encrypted !== null ? 'border-l border-white/[0.08]/30' : 'col-span-2'}`}>
                  <div className="text-zinc-500 text-[10px] mb-0.5">Device Control</div>
                  <div className={`text-[11px] font-medium ${detail.device_control_enabled ? 'text-emerald-300' : 'text-red-400'}`}>
                    {detail.device_control_enabled ? 'Enabled' : 'Disabled'}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      ) : (
        <div className="border-t border-white/[0.08]/30 px-3.5 py-2.5 flex items-center gap-1.5 text-xs text-zinc-500">
          <AlertTriangle className="w-3.5 h-3.5 text-zinc-600 flex-shrink-0" />
          Agent not found on this endpoint
        </div>
      )}
    </div>
  )
}

export function EndpointDetailPanel({ endpointId }: { endpointId: string }) {
  const { user } = useAuthStore()
  const { enabled: productEnabled, tags: activeProductTags } = useEndpointProductTags()
  const { connected } = useConnectedIntegrations()
  const [activeTab, setActiveTab] = useState<Tab>('overview')

  const { data: ep, isLoading, error } = useQuery<EndpointDetail>({
    queryKey: ['endpoint-detail', endpointId],
    queryFn: async () => (await apiClient.get(`/endpoints/${endpointId}`)).data,
  })

  if (isLoading) return <SkeletonDetailPanel />

  if (error || !ep) return (
    <div className="p-5 text-sm text-red-400">Failed to load endpoint details</div>
  )

  const ipList: string[] = ep.all_ips
    ? ep.all_ips.split(',').map(s => s.trim()).filter(Boolean)
    : ep.ip_address ? [ep.ip_address] : []

  const tagList = ep.tags
    ? String(ep.tags).split(',').map(t => t.trim()).filter(Boolean)
    : []

  const cs = ep.compliance_status
  const primaryActivity = primaryEndpointActivity(ep, connected, activeProductTags)
  const lastActivitySources = [
    ...(primaryActivity
      ? [{ label: primaryActivity.label, color: 'text-emerald-500', val: primaryActivity.lastSeen }]
      : []),
    ...(connected.has('sentinelone') && productEnabled('S1') && ep.source !== 'sentinelone'
      ? [{ label: 'SentinelOne', color: 'text-emerald-500', val: ep.sentinelone?.last_seen ?? null, fallback: ep.sentinelone?.installed ? 'No data' : 'Not installed' }]
      : []),
    ...(connected.has('symantec_dlp') && productEnabled('DLP') && ep.source !== 'symantec'
      ? [{ label: 'DLP', color: 'text-yellow-600', val: ep.symantec_dlp?.last_seen ?? null, fallback: ep.symantec_dlp?.installed ? 'No data' : 'Not installed' }]
      : []),
    ...(connected.has('sentinelone') && productEnabled('WSS')
      ? [{ label: 'WSS', color: 'text-orange-500', val: ep.symantec_wss?.last_seen ?? null, fallback: ep.symantec_wss?.installed ? 'No data' : 'Not installed' }]
      : []),
    ...(connected.has('puppet') && ep.puppet_managed && ep.source !== 'puppet'
      ? [{ label: 'Puppet', color: 'text-amber-500', val: ep.puppet_last_seen }]
      : []),
  ]

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex-shrink-0 border-b border-white/[0.06] px-5 py-3.5 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <Monitor className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span className="text-white font-semibold text-sm truncate">{ep.hostname}</span>
          {ep.source && ep.source !== 'jumpcloud' && (
            <span className="text-[10px] px-1.5 py-0.5 rounded border border-gray-600/40 text-zinc-500 flex-shrink-0">
              {ep.source}
            </span>
          )}
          {connected.has('puppet') && ep.puppet_managed && ep.source !== 'puppet' && (
            <span className="flex-shrink-0 rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-300">
              Puppet
            </span>
          )}
        </div>
        <div className="flex items-center gap-2.5 flex-shrink-0">
          <RiskBadge score={ep.risk_score_override ?? ep.risk_score} />
          {ep.risk_score_override != null && (
            <span className="text-[10px] text-amber-400" title="Risk score is overridden">⚑</span>
          )}
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex-shrink-0 flex border-b border-white/[0.06] px-4 gap-0.5 bg-black/20">
        {TABS.map(tab => {
          const Icon = tab.icon
          const isActive = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium transition-colors duration-150 border-b-2 -mb-px ${
                isActive
                  ? 'text-emerald-400 border-emerald-500'
                  : 'text-zinc-500 border-transparent hover:text-zinc-300'
              }`}
            >
              <Icon size={12} />
              {tab.label}
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">

        {(user?.role === 'admin' || user?.role === 'analyst') && (
          <ComplianceScopeControl endpoint={ep} />
        )}

        {/* ── OVERVIEW TAB ── */}
        {activeTab === 'overview' && (
          <>
            <div className="space-y-1.5">
              <SectionHeader>Identity</SectionHeader>
              <div className="bg-zinc-900/70 rounded-xl border border-white/[0.08]/50 divide-y divide-gray-700/40">
                <InfoRow icon={Monitor} label="Hostname" value={ep.hostname} mono />
                {ep.username && <InfoRow icon={User} label="Username" value={ep.username} />}
                {ep.owner ? (
                  <>
                    <InfoRow icon={User}     label="Owner"     value={ep.owner.full_name} />
                    <InfoRow icon={Mail}     label="Email"    value={ep.owner.email} colorClass="text-emerald-300" />
                    {ep.owner.department && <InfoRow icon={Building2} label="Department" value={ep.owner.department} />}
                  </>
                ) : (
                  <div className="flex items-center gap-3 px-4 py-2.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-yellow-500 flex-shrink-0 mt-0.5" />
                    <span className="text-xs text-yellow-600">No owner linked</span>
                  </div>
                )}
              </div>
            </div>

            <div className="space-y-1.5">
              <SectionHeader>System</SectionHeader>
              <div className="bg-zinc-900/70 rounded-xl border border-white/[0.08]/50 divide-y divide-gray-700/40">
                <InfoRow icon={Cpu} label="OS Version" value={ep.os_version || '—'} />
                {ep.serial_number && <InfoRow icon={Hash} label="Serial" value={ep.serial_number} mono />}
                {ipList.length > 0 ? (
                  <div className="flex items-start gap-3 px-4 py-2.5">
                    <Wifi className="w-3.5 h-3.5 text-zinc-500 flex-shrink-0 mt-0.5" />
                    <span className="text-xs text-zinc-500 w-24 flex-shrink-0 pt-px">IPv4</span>
                    <div className="flex flex-col gap-0.5">
                      {ipList.map(ip => <span key={ip} className="text-sm text-zinc-200 font-mono">{ip}</span>)}
                    </div>
                  </div>
                ) : (
                  <InfoRow icon={Wifi} label="IPv4" value="—" />
                )}
                {ep.external_ip && <InfoRow icon={Wifi} label="External IP" value={ep.external_ip} mono />}
                {ep.last_reboot && <InfoRow icon={Clock} label="Last Reboot" value={relTime(ep.last_reboot)} />}
              </div>
            </div>

            <div className="space-y-1.5">
              <SectionHeader>Last Activity</SectionHeader>
              <div className="bg-zinc-900/70 rounded-xl border border-white/[0.08]/50 divide-y divide-gray-700/40">
                {lastActivitySources.map(({ label, color, val, fallback }) => (
                  <div key={label} className="flex items-center gap-3 px-4 py-2.5">
                    <Clock className={`w-3.5 h-3.5 ${color} flex-shrink-0`} />
                    <span className="text-xs text-zinc-500 w-24 flex-shrink-0">{label}</span>
                    <span className={`text-sm ${val ? 'text-zinc-200' : 'text-zinc-600'}`}>
                      {val ? relTime(val) : (fallback ?? 'No data')}
                    </span>
                  </div>
                ))}
                {lastActivitySources.length === 0 && (
                  <div className="px-4 py-3 text-xs text-zinc-600">
                    No connected integration activity
                  </div>
                )}
              </div>
            </div>

            {tagList.length > 0 && (
              <div className="space-y-1.5">
                <SectionHeader><span className="flex items-center gap-1"><Tag className="w-2.5 h-2.5" /> Tags</span></SectionHeader>
                <div className="flex flex-wrap gap-1.5 px-1">
                  {tagList.map(tag => (
                    <span key={tag} className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/15 text-emerald-300">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <NoteBox
              entityType="endpoint"
              entityId={endpointId}
              currentUserEmail={user?.email ?? ''}
              currentUserRole={user?.role ?? 'viewer'}
            />
          </>
        )}

        {/* ── AGENTS TAB ── */}
        {activeTab === 'agents' && (
          <div className="space-y-3">
            {productEnabled('S1') && <AgentBlock label="SentinelOne EDR" detail={ep.sentinelone} />}
            {productEnabled('DLP') && <AgentBlock label="Symantec DLP" detail={ep.symantec_dlp} showStateGroup />}
            {productEnabled('WSS') && <AgentBlock label="Symantec WSS Agent" detail={ep.symantec_wss} simple />}
            {activeProductTags.length === 0 && <div className="py-8 text-center text-xs text-zinc-500">No endpoint products are enabled in Platform Settings.</div>}
          </div>
        )}

        {/* ── SECURITY TAB ── */}
        {activeTab === 'security' && (
          <>
            {cs ? (
              <div className="space-y-1.5">
                <SectionHeader>Compliance</SectionHeader>
                <div className="bg-zinc-900/70 rounded-xl border border-white/[0.08]/50 p-3.5 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-zinc-400">Overall Status</span>
                    <StatusBadge status={cs.status} />
                  </div>
                  <div className="grid grid-cols-2 gap-1.5 text-xs border-t border-white/[0.08]/50 pt-3">
                    {([
                      ...(productEnabled('S1') ? [
                        { label: 'EDR Installed', ok: cs.edr_installed },
                        { label: 'EDR Up to Date', ok: cs.edr_version_ok },
                      ] : []),
                      ...(productEnabled('DLP') ? [
                        { label: 'DLP Installed', ok: cs.dlp_installed },
                        { label: 'DLP Up to Date', ok: cs.dlp_version_ok },
                      ] : []),
                      ...(productEnabled('WSS') ? [
                        { label: 'WSS Installed', ok: cs.wss_installed },
                        ...(cs.wss_installed ? [{ label: 'WSS Up to Date', ok: cs.wss_version_ok }] : []),
                      ] : []),
                      ...(productEnabled('S1') && cs.disk_encrypted !== null && cs.disk_encrypted !== undefined
                        ? [{ label: 'Disk Encrypted', ok: cs.disk_encrypted }] : []),
                      ...(productEnabled('S1') && cs.device_control_enabled !== null && cs.device_control_enabled !== undefined
                        ? [{ label: 'Device Control', ok: cs.device_control_enabled }] : []),
                    ] as { label: string; ok: boolean }[]).map(({ label, ok }) => (
                      <div key={label} className={`flex items-center gap-1.5 ${ok ? 'text-emerald-300' : 'text-red-400'}`}>
                        {ok ? <CheckCircle className="w-3 h-3 flex-shrink-0" /> : <XCircle className="w-3 h-3 flex-shrink-0" />}
                        <span>{label}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-white/[0.08] p-4 text-center text-xs text-zinc-500">
                No compliance data evaluated yet
              </div>
            )}

            {(user?.role === 'admin' || user?.role === 'analyst') && (
              <RiskOverrideSection
                endpointId={endpointId}
                current={ep.risk_score_override ?? null}
                note={ep.risk_score_note ?? null}
              />
            )}
          </>
        )}
      </div>
    </div>
  )
}
