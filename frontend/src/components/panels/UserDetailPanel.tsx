import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import {
  Monitor, CheckCircle, XCircle,
  AlertTriangle, Clock, Wifi, Building2, UserCheck, Briefcase, Phone, LayoutList, Server,
} from 'lucide-react'
import apiClient from '../../api/client'
import RiskBadge from '../shared/RiskBadge'
import { SkeletonDetailPanel } from '../shared/Skeleton'
import StatusBadge from '../shared/StatusBadge'
import NoteBox from '../shared/NoteBox'
import { useAuthStore } from '../../store/auth'
import type { UserIdentity } from '../../types'
import { useEndpointProductTags } from '../../hooks/useEndpointProductTags'
import { usePanelStore } from '../../store/panels'

const PRODUCT_LABELS: Record<string, string> = {
  sentinelone: 'SentinelOne', symantec: 'Symantec DLP',
  symantec_wss: 'Symantec WSS',
  jumpcloud: 'JumpCloud', other: 'Other',
}

const PRODUCT_COLORS: Record<string, string> = {
  sentinelone: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
  symantec: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
  symantec_wss: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  jumpcloud: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
  other: 'bg-gray-500/15 text-zinc-300 border-gray-500/30',
}

function SourceBadge({
  name, color, bg, border, active, suspended, mfa, lastSeen, orgUnit,
}: {
  name: string; color: string; bg: string; border: string
  active: boolean; suspended: boolean; mfa: boolean
  lastSeen?: string | null; orgUnit?: string | null
}) {
  const statusLabel = suspended ? 'Suspended' : active ? 'Active' : 'Inactive'
  const dotColor    = suspended ? '#f87171' : active ? '#34d399' : '#f87171'
  return (
    <div className="rounded-lg p-2.5 flex flex-col gap-1.5"
      style={{ background: bg, border: `1px solid ${border}` }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: dotColor }} />
          <span className="text-[13px] font-semibold" style={{ color }}>{name}</span>
        </div>
        <span className="text-[11px] font-medium" style={{ color: dotColor }}>{statusLabel}</span>
      </div>
      <div className="flex items-center gap-3 flex-wrap" style={{ color: 'var(--text-3)' }}>
        <span className="text-[11px]">
          MFA: <span style={{ color: mfa ? '#34d399' : '#f87171' }}>{mfa ? 'Enabled' : 'Disabled'}</span>
        </span>
        {orgUnit && orgUnit !== '/' && (
          <span className="text-[11px]">Org: {orgUnit}</span>
        )}
        {lastSeen && lastSeen !== '1970-01-01T00:00:00.000Z' && (
          <span className="text-[11px]">
            Last seen: {formatDistanceToNow(new Date(lastSeen), { addSuffix: true })}
          </span>
        )}
      </div>
    </div>
  )
}

function AgentPill({ product, status }: { product: string; status: string }) {
  const color = PRODUCT_COLORS[product] || PRODUCT_COLORS.other
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border ${color}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${status === 'active' ? 'bg-emerald-400' : 'bg-red-400'}`} />
      {PRODUCT_LABELS[product] || product}
    </span>
  )
}

function ComplianceCheck({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className={`flex items-center gap-1 ${ok ? 'text-emerald-300' : 'text-red-400'}`}>
      {ok ? <CheckCircle className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
      <span>{label}</span>
    </div>
  )
}

type UserTab = 'overview' | 'endpoints'

function ProfileRow({ icon: Icon, label, value, mono = false }: {
  icon: React.ElementType
  label: string
  value: React.ReactNode
  mono?: boolean
}) {
  return (
    <div className="entity-info-row">
      <Icon className="entity-info-icon" />
      <span className="entity-info-label">{label}</span>
      <span className={`entity-info-value ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  )
}

export function UserDetailPanel({ userId, onTitleChange }: { userId: string; onTitleChange?: (title: string) => void }) {
  const { user: authUser } = useAuthStore()
  const { openPanel } = usePanelStore()
  const { enabled: productEnabled } = useEndpointProductTags()
  const [activeTab, setActiveTab] = React.useState<UserTab>('overview')
  const { data: identity, isLoading, error } = useQuery<UserIdentity>({
    queryKey: ['user-identity', userId],
    queryFn: async () => (await apiClient.get(`/users/${userId}/identity`)).data,
  })

  React.useEffect(() => {
    if (identity?.full_name) onTitleChange?.(identity.full_name)
  }, [identity?.full_name, onTitleChange])

  if (isLoading) return <SkeletonDetailPanel />

  if (error || !identity) {
    return <div className="p-6 text-red-400 text-sm">Failed to load identity profile</div>
  }

  const endpointSequence = identity.endpoints.map(endpoint => ({ id: endpoint.id, title: endpoint.hostname }))

  return (
    <div className="entity-detail-shell h-full flex flex-col overflow-hidden">
      <section className="entity-profile-hero">
        <div className="entity-avatar">
          {identity.full_name.split(' ').map(name => name[0]).join('').slice(0, 2).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <h3>{identity.full_name}</h3>
          <p>{identity.email}</p>
          <div className="entity-profile-meta">
            {identity.job_title && <span>{identity.job_title}</span>}
            {identity.department && <span>{identity.department}</span>}
          </div>
        </div>
        <StatusBadge status={identity.employment_status} />
      </section>

      <div className="entity-summary-strip entity-summary-strip--user">
        <div className="entity-summary-item"><span>Risk</span><RiskBadge score={identity.risk_score} /></div>
        <div className="entity-summary-item"><span>Endpoints</span><strong>{identity.total_endpoints}</strong></div>
        <div className="entity-summary-item">
          <span>MFA</span>
          <strong data-tone={identity.mfa_enabled ? 'success' : 'danger'}>{identity.mfa_enabled ? 'Enabled' : 'Disabled'}</strong>
        </div>
        <div className="entity-summary-item">
          <span>Last login</span>
          <strong>{identity.last_login ? formatDistanceToNow(new Date(identity.last_login), { addSuffix: true }) : 'Never'}</strong>
        </div>
      </div>

      <div className="entity-detail-tabs" role="tablist" aria-label="User details">
        <button type="button" role="tab" aria-selected={activeTab === 'overview'} className={activeTab === 'overview' ? 'is-active' : ''} onClick={() => setActiveTab('overview')}>
          <LayoutList size={13} /> Overview
        </button>
        <button type="button" role="tab" aria-selected={activeTab === 'endpoints'} className={activeTab === 'endpoints' ? 'is-active' : ''} onClick={() => setActiveTab('endpoints')}>
          <Server size={13} /> Endpoints <span className="entity-tab-count">{identity.total_endpoints}</span>
        </button>
      </div>

      <div key={activeTab} className="entity-detail-scroll detail-tab-stage flex-1 overflow-y-auto space-y-5">
        {activeTab === 'overview' && (
          <>
            <section className="space-y-1.5">
              <div className="entity-section-heading">Profile and identity</div>
              <div className="entity-glass-card entity-divide-y">
                {identity.job_title && <ProfileRow icon={Briefcase} label="Title" value={identity.job_title} />}
                {identity.department && <ProfileRow icon={Building2} label="Department" value={identity.department} />}
                {identity.phone && <ProfileRow icon={Phone} label="Phone" value={identity.phone} mono />}
                {identity.manager && <ProfileRow icon={UserCheck} label="Manager" value={identity.manager} />}
                {identity.last_login && <ProfileRow icon={Clock} label="Last login" value={formatDistanceToNow(new Date(identity.last_login), { addSuffix: true })} />}
                {identity.sources && Object.keys(identity.sources).length > 0 && (
                  <div className="entity-info-row entity-info-row--top">
                    <Wifi className="entity-info-icon" />
                    <span className="entity-info-label">Sources</span>
                    <div className="flex min-w-0 flex-1 flex-col gap-2">
                      {identity.sources.jumpcloud && (
                        <SourceBadge name="JumpCloud" color="#60a5fa" bg="rgba(59,130,246,0.10)" border="rgba(59,130,246,0.22)" active={identity.sources.jumpcloud.active && !identity.sources.jumpcloud.suspended} suspended={identity.sources.jumpcloud.suspended} mfa={identity.sources.jumpcloud.mfa} lastSeen={identity.sources.jumpcloud.last_seen} />
                      )}
                      {identity.sources.google && (
                        <SourceBadge name="Google Workspace" color="#f1bd65" bg="rgba(241,189,101,0.09)" border="rgba(241,189,101,0.22)" active={identity.sources.google.active && !identity.sources.google.suspended} suspended={identity.sources.google.suspended} mfa={identity.sources.google.mfa} lastSeen={identity.sources.google.last_login} orgUnit={identity.sources.google.org_unit} />
                      )}
                    </div>
                  </div>
                )}
              </div>
            </section>

            <section className="space-y-1.5">
              <div className="entity-section-heading">Agent coverage</div>
              <div className="entity-coverage-grid">
                {[
                  ...(productEnabled('S1') ? [{ label: 'SentinelOne', count: identity.endpoints_with_sentinelone }] : []),
                  ...(productEnabled('DLP') ? [{ label: 'Symantec DLP', count: identity.endpoints_with_symantec }] : []),
                  ...(productEnabled('WSS') ? [{ label: 'Symantec WSS', count: identity.endpoints_with_wss }] : []),
                ].map(({ label, count }) => {
                  const ok = identity.total_endpoints > 0 && count === identity.total_endpoints
                  const percentage = identity.total_endpoints > 0 ? Math.round((count / identity.total_endpoints) * 100) : 0
                  return (
                    <article key={label} className="entity-coverage-card" data-complete={ok}>
                      <div><span>{label}</span><strong>{count}/{identity.total_endpoints}</strong></div>
                      <div className="entity-coverage-track"><span style={{ width: `${percentage}%` }} /></div>
                      <small>{percentage}% covered</small>
                    </article>
                  )
                })}
              </div>
            </section>

            <NoteBox entityType="user" entityId={userId} currentUserEmail={authUser?.email ?? ''} currentUserRole={authUser?.role ?? 'viewer'} />
          </>
        )}

        {activeTab === 'endpoints' && (
          <section className="space-y-2">
            <div className="entity-section-heading">Linked endpoints ({identity.total_endpoints})</div>
            {identity.endpoints.length === 0 ? (
              <div className="entity-glass-card entity-empty-detail">No endpoints linked — run correlation to link devices.</div>
            ) : identity.endpoints.map(ep => (
              <button key={ep.id} type="button" onClick={() => openPanel('endpoint', ep.id, ep.hostname, endpointSequence)} className="entity-endpoint-card">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-2.5">
                    <span className="entity-endpoint-icon"><Monitor size={15} /></span>
                    <div className="min-w-0"><strong className="truncate">{ep.hostname}</strong><span>{ep.os_version || 'Unknown operating system'}</span></div>
                  </div>
                  <RiskBadge score={ep.risk_score} />
                </div>
                <div className="entity-endpoint-facts">
                  {ep.ip_address && <span>IP <code>{ep.ip_address}</code></span>}
                  {ep.username && <span>User <strong>{ep.username}</strong></span>}
                  {ep.last_seen && <span>Seen <strong>{formatDistanceToNow(new Date(ep.last_seen), { addSuffix: true })}</strong></span>}
                </div>
                {ep.agents.filter(agent => ((agent.product_name !== 'sentinelone' || productEnabled('S1')) && (agent.product_name !== 'symantec' || productEnabled('DLP')) && (agent.product_name !== 'symantec_wss' || productEnabled('WSS')))).length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">{ep.agents.filter(agent => ((agent.product_name !== 'sentinelone' || productEnabled('S1')) && (agent.product_name !== 'symantec' || productEnabled('DLP')) && (agent.product_name !== 'symantec_wss' || productEnabled('WSS')))).map(agent => <AgentPill key={agent.id} product={agent.product_name} status={agent.status} />)}</div>
                ) : (
                  <div className="flex items-center gap-1.5 text-xs text-red-400"><AlertTriangle className="h-3.5 w-3.5" />No security agents installed</div>
                )}
                {ep.compliance && (
                  <div className="entity-endpoint-checks">
                    {productEnabled('S1') && <ComplianceCheck label="EDR installed" ok={ep.compliance.edr_installed} />}
                    {productEnabled('S1') && <ComplianceCheck label="EDR up to date" ok={ep.compliance.edr_version_ok} />}
                    {productEnabled('DLP') && <ComplianceCheck label="DLP installed" ok={ep.compliance.dlp_installed} />}
                    {productEnabled('DLP') && <ComplianceCheck label="DLP up to date" ok={ep.compliance.dlp_version_ok} />}
                    {productEnabled('WSS') && <ComplianceCheck label="WSS installed" ok={ep.compliance.wss_installed} />}
                    {productEnabled('WSS') && <ComplianceCheck label="WSS up to date" ok={ep.compliance.wss_version_ok} />}
                    {productEnabled('S1') && ep.compliance.disk_encrypted != null && <ComplianceCheck label="Disk encrypted" ok={ep.compliance.disk_encrypted} />}
                    {productEnabled('S1') && ep.compliance.device_control_enabled != null && <ComplianceCheck label="Device control" ok={ep.compliance.device_control_enabled} />}
                  </div>
                )}
              </button>
            ))}
          </section>
        )}
      </div>
    </div>
  )
}
