import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import {
  Monitor, CheckCircle, XCircle,
  AlertTriangle, Clock, Wifi, Building2, UserCheck, Briefcase, Phone,
} from 'lucide-react'
import apiClient from '../../api/client'
import RiskBadge from '../shared/RiskBadge'
import { SkeletonDetailPanel } from '../shared/Skeleton'
import StatusBadge from '../shared/StatusBadge'
import NoteBox from '../shared/NoteBox'
import { useAuthStore } from '../../store/auth'
import type { UserIdentity } from '../../types'

const PRODUCT_LABELS: Record<string, string> = {
  sentinelone: 'SentinelOne', symantec: 'Symantec DLP',
  jumpcloud: 'JumpCloud', other: 'Other',
}

const PRODUCT_COLORS: Record<string, string> = {
  sentinelone: 'bg-emerald-500/15 text-purple-300 border-emerald-500/30',
  symantec: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
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
      <div className="flex items-center gap-3 flex-wrap" style={{ color: '#a1a1aa' }}>
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

export function UserDetailPanel({ userId }: { userId: string }) {
  const { user: authUser } = useAuthStore()
  const { data: identity, isLoading, error } = useQuery<UserIdentity>({
    queryKey: ['user-identity', userId],
    queryFn: async () => (await apiClient.get(`/users/${userId}/identity`)).data,
  })

  if (isLoading) return <SkeletonDetailPanel />

  if (error || !identity) {
    return <div className="p-6 text-red-400 text-sm">Failed to load identity profile</div>
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <div className="flex-shrink-0 border-b border-white/[0.06] px-5 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-emerald-600 flex items-center justify-center text-white font-semibold text-sm flex-shrink-0">
            {identity.full_name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase()}
          </div>
          <div>
            <div className="text-white font-semibold text-sm">{identity.full_name}</div>
            <div className="text-xs text-zinc-400">{identity.email}</div>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        <div className="grid grid-cols-2 gap-2">
          <div className="bg-zinc-900 rounded-lg p-3">
            <div className="text-xs text-zinc-400 mb-1.5">Risk Score</div>
            <RiskBadge score={identity.risk_score} />
          </div>
          <div className="bg-zinc-900 rounded-lg p-3">
            <div className="text-xs text-zinc-400 mb-1.5">Status</div>
            <StatusBadge status={identity.employment_status} />
          </div>
          <div className="bg-zinc-900 rounded-lg p-3">
            <div className="text-xs text-zinc-400 mb-0.5">Endpoints</div>
            <div className="text-white font-bold text-lg">{identity.total_endpoints}</div>
          </div>
          <div className="bg-zinc-900 rounded-lg p-3">
            <div className="text-xs text-zinc-400 mb-1.5">MFA</div>
            <div className={`flex items-center gap-1 text-sm font-medium ${identity.mfa_enabled ? 'text-emerald-300' : 'text-red-400'}`}>
              {identity.mfa_enabled ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
              {identity.mfa_enabled ? 'Enabled' : 'Disabled'}
            </div>
          </div>
        </div>

        <div className="space-y-1.5">
          <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">Profile</div>
          <div className="bg-zinc-900 rounded-lg divide-y divide-gray-700/60">
            {identity.job_title && (
              <div className="flex items-center gap-3 px-4 py-2.5">
                <Briefcase className="w-4 h-4 text-zinc-500 flex-shrink-0" />
                <span className="text-xs text-zinc-400 w-20 flex-shrink-0">Title</span>
                <span className="text-sm text-white">{identity.job_title}</span>
              </div>
            )}
            {identity.department && (
              <div className="flex items-center gap-3 px-4 py-2.5">
                <Building2 className="w-4 h-4 text-zinc-500 flex-shrink-0" />
                <span className="text-xs text-zinc-400 w-20 flex-shrink-0">Department</span>
                <span className="text-sm text-white">{identity.department}</span>
              </div>
            )}
            {identity.phone && (
              <div className="flex items-center gap-3 px-4 py-2.5">
                <Phone className="w-4 h-4 text-zinc-500 flex-shrink-0" />
                <span className="text-xs text-zinc-400 w-20 flex-shrink-0">Phone</span>
                <span className="text-sm text-white font-mono">{identity.phone}</span>
              </div>
            )}
            {identity.manager && (
              <div className="flex items-center gap-3 px-4 py-2.5">
                <UserCheck className="w-4 h-4 text-zinc-500 flex-shrink-0" />
                <span className="text-xs text-zinc-400 w-20 flex-shrink-0">Manager</span>
                <span className="text-sm text-white">{identity.manager}</span>
              </div>
            )}
            {identity.last_login && (
              <div className="flex items-center gap-3 px-4 py-2.5">
                <Clock className="w-4 h-4 text-zinc-500 flex-shrink-0" />
                <span className="text-xs text-zinc-400 w-20 flex-shrink-0">Last login</span>
                <span className="text-sm text-white">
                  {formatDistanceToNow(new Date(identity.last_login), { addSuffix: true })}
                </span>
              </div>
            )}
            {identity.sources && Object.keys(identity.sources).length > 0 && (
              <div className="flex items-start gap-3 px-4 py-2.5">
                <Wifi className="w-4 h-4 text-zinc-500 flex-shrink-0 mt-0.5" />
                <span className="text-xs text-zinc-400 w-20 flex-shrink-0 mt-0.5">Sources</span>
                <div className="flex flex-col gap-2 flex-1">
                  {identity.sources.jumpcloud && (
                    <SourceBadge
                      name="JumpCloud"
                      color="#60a5fa"
                      bg="rgba(59,130,246,0.12)"
                      border="rgba(59,130,246,0.25)"
                      active={identity.sources.jumpcloud.active && !identity.sources.jumpcloud.suspended}
                      suspended={identity.sources.jumpcloud.suspended}
                      mfa={identity.sources.jumpcloud.mfa}
                      lastSeen={identity.sources.jumpcloud.last_seen}
                    />
                  )}
                  {identity.sources.google && (
                    <SourceBadge
                      name="Google Workspace"
                      color="#fbbf24"
                      bg="rgba(234,179,8,0.12)"
                      border="rgba(234,179,8,0.25)"
                      active={identity.sources.google.active && !identity.sources.google.suspended}
                      suspended={identity.sources.google.suspended}
                      mfa={identity.sources.google.mfa}
                      lastSeen={identity.sources.google.last_login}
                      orgUnit={identity.sources.google.org_unit}
                    />
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="space-y-1.5">
          <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">Agent Coverage</div>
          <div className="grid grid-cols-2 gap-2">
            {[
              { label: 'SentinelOne', count: identity.endpoints_with_sentinelone },
              { label: 'Symantec DLP', count: identity.endpoints_with_symantec },
            ].map(({ label, count }) => {
              const ok = identity.total_endpoints > 0 && count === identity.total_endpoints
              return (
                <div key={label} className={`rounded-lg p-3 border ${ok ? 'bg-emerald-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
                  <div className="text-xs text-zinc-400 mb-0.5">{label}</div>
                  <div className={`text-lg font-bold ${ok ? 'text-emerald-300' : 'text-red-400'}`}>
                    {count}/{identity.total_endpoints}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        <NoteBox
          entityType="user"
          entityId={userId}
          currentUserEmail={authUser?.email ?? ''}
          currentUserRole={authUser?.role ?? 'viewer'}
        />

        <div className="space-y-1.5">
          <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">
            Endpoints ({identity.total_endpoints})
          </div>
          {identity.endpoints.length === 0 ? (
            <div className="text-sm text-zinc-500 text-center py-6 bg-zinc-900 rounded-lg">
              No endpoints linked — run correlation to link devices
            </div>
          ) : (
            <div className="space-y-2">
              {identity.endpoints.map(ep => (
                <div key={ep.id} className="bg-zinc-900 rounded-lg p-4 space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <Monitor className="w-4 h-4 text-zinc-400 flex-shrink-0" />
                      <span className="text-sm font-medium text-white truncate">{ep.hostname}</span>
                    </div>
                    <RiskBadge score={ep.risk_score} />
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                    {ep.ip_address && <div className="text-zinc-400">IP: <span className="text-zinc-200 font-mono">{ep.ip_address}</span></div>}
                    {ep.os_version && <div className="text-zinc-400 truncate">OS: <span className="text-zinc-200">{ep.os_version}</span></div>}
                    {ep.username && <div className="text-zinc-400">User: <span className="text-zinc-200">{ep.username}</span></div>}
                    {ep.last_seen && <div className="text-zinc-400">Seen: <span className="text-zinc-200">{formatDistanceToNow(new Date(ep.last_seen), { addSuffix: true })}</span></div>}
                  </div>
                  {ep.agents.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {ep.agents.map(a => <AgentPill key={a.id} product={a.product_name} status={a.status} />)}
                    </div>
                  ) : (
                    <div className="flex items-center gap-1.5 text-xs text-red-400">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      No security agents installed
                    </div>
                  )}
                  {ep.compliance && (
                    <div className="border-t border-white/[0.08] pt-2.5 grid grid-cols-2 gap-y-1 gap-x-4 text-xs">
                      <ComplianceCheck label="EDR installed"  ok={ep.compliance.edr_installed} />
                      <ComplianceCheck label="EDR up to date" ok={ep.compliance.edr_version_ok} />
                      <ComplianceCheck label="DLP installed"  ok={ep.compliance.dlp_installed} />
                      <ComplianceCheck label="DLP up to date" ok={ep.compliance.dlp_version_ok} />
                      {ep.compliance.disk_encrypted !== null && ep.compliance.disk_encrypted !== undefined && (
                        <ComplianceCheck label="Disk encrypted" ok={ep.compliance.disk_encrypted} />
                      )}
                      {ep.compliance.device_control_enabled !== null && ep.compliance.device_control_enabled !== undefined && (
                        <ComplianceCheck label="Device control" ok={ep.compliance.device_control_enabled} />
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
