import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Activity, AlertTriangle, ArrowRight, CheckCircle2, CircleAlert,
  Database, HardDrive, Monitor, MousePointer, Plug, Radar,
  Server, Shield, ShieldCheck, ShieldOff, Wifi,
} from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { formatDistanceToNow } from 'date-fns'
import RiskBadge from '../components/shared/RiskBadge'
import EmptyState from '../components/shared/EmptyState'
import { usePanelStore } from '../store/panels'
import { fetchUsers } from '../api/users'
import { fetchEndpoints } from '../api/endpoints'
import { fetchComplianceDashboard } from '../api/compliance'
import { fetchRiskSummary, fetchRiskyUsers, fetchRiskyEndpoints } from '../api/risk'
import { fetchSuspiciousActivity } from '../api/activity'
import { fetchIntegrations } from '../api/integrations'

const STATUS_COLORS = ['#10b981', '#d6a72d', '#e35454']

const INTEGRATION_ICONS: Record<string, React.ElementType> = {
  jumpcloud: Server,
  sentinelone: Shield,
  symantec_dlp: Database,
  google_workspace: Wifi,
}

type AttentionItem = {
  id: string
  label: string
  context: string
  count: number
  severity: 'critical' | 'high' | 'warning'
  href: string
  icon: React.ElementType
}

const SEVERITY: Record<AttentionItem['severity'], { color: string; label: string }> = {
  critical: { color: '#e35454', label: 'Critical' },
  high: { color: '#e98345', label: 'High' },
  warning: { color: '#d6a72d', label: 'Review' },
}

function SectionHeading({ context, title, action, onAction }: {
  context: string
  title: string
  action?: string
  onAction?: () => void
}) {
  return (
    <div className="flex items-end justify-between gap-4 px-5 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
      <div>
        <h2 className="text-[15px] font-semibold tracking-[-0.02em]" style={{ color: 'var(--text-1)' }}>{title}</h2>
        <p className="mt-1 text-[12px]" style={{ color: 'var(--text-3)' }}>{context}</p>
      </div>
      {action && onAction && (
        <button onClick={onAction} className="ui-text-action">
          {action}<ArrowRight size={12} />
        </button>
      )}
    </div>
  )
}

function Metric({ label, value, note, tone = 'default', onClick }: {
  label: string
  value: React.ReactNode
  note: string
  tone?: 'default' | 'danger' | 'warning'
  onClick: () => void
}) {
  const color = tone === 'danger' ? '#e35454' : tone === 'warning' ? '#e98345' : 'var(--text-1)'
  return (
    <button onClick={onClick} className="group min-w-0 py-4 text-left ui-metric">
      <div className="flex items-center gap-2">
        <span className="text-[12px] font-medium" style={{ color: 'var(--text-3)' }}>{label}</span>
        <ArrowRight size={11} className="opacity-0 -translate-x-1 transition-[transform,opacity] group-hover:opacity-100 group-hover:translate-x-0" style={{ color: 'var(--accent)' }} />
      </div>
      <div className="mt-2 text-[28px] leading-none font-semibold tracking-[-0.045em] tabular-nums" style={{ color }}>{value}</div>
      <p className="mt-2 text-[11px] truncate" style={{ color: 'var(--text-4)' }}>{note}</p>
    </button>
  )
}

function CoverageRow({ label, detail, value, total, href, onOpen }: {
  label: string
  detail: string
  value: number
  total: number
  href: string
  onOpen: (href: string) => void
}) {
  const pct = total ? Math.round((value / total) * 100) : 0
  const color = pct >= 95 ? '#10b981' : pct >= 80 ? '#d6a72d' : '#e35454'
  return (
    <button onClick={() => onOpen(href)} className="ui-data-row group w-full grid grid-cols-[minmax(0,1fr)_76px_42px] items-center gap-4 px-5 py-3 text-left">
      <div className="min-w-0">
        <div className="text-[13px] font-medium" style={{ color: 'var(--text-2)' }}>{label}</div>
        <div className="text-[11px] mt-0.5" style={{ color: 'var(--text-3)' }}>{detail}</div>
      </div>
      <div className="h-1 overflow-hidden rounded-full" style={{ background: 'var(--surface-3)' }}>
        <div className="h-full rounded-full transition-[width] duration-500" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="tabular-nums text-[12px] text-right" style={{ color }}>{pct}%</span>
    </button>
  )
}

function ChartTooltip({ active, payload }: { active?: boolean; payload?: { name: string; value: number; fill?: string }[] }) {
  if (!active || !payload?.length) return null
  return (
    <div className="ui-float-surface px-3 py-2 text-xs">
      {payload.map(item => (
        <div key={item.name} className="flex items-center gap-3 py-0.5">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: item.fill }} />
          <span style={{ color: 'var(--text-3)' }}>{item.name}</span>
          <span className="ml-auto tabular-nums" style={{ color: 'var(--text-1)' }}>{item.value}</span>
        </div>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const navigate = useNavigate()
  const { openPanel } = usePanelStore()

  const users = useQuery({ queryKey: ['users', 'total'], queryFn: () => fetchUsers({ limit: 1 }) })
  const endpoints = useQuery({ queryKey: ['endpoints', 'total'], queryFn: () => fetchEndpoints({ limit: 1 }) })
  const unassigned = useQuery({ queryKey: ['endpoints', 'unassigned'], queryFn: () => fetchEndpoints({ unassigned: true, limit: 1 } as Parameters<typeof fetchEndpoints>[0]) })
  const compliance = useQuery({ queryKey: ['compliance', 'dashboard'], queryFn: fetchComplianceDashboard })
  const risk = useQuery({ queryKey: ['risk', 'summary'], queryFn: fetchRiskSummary })
  const riskyUsers = useQuery({ queryKey: ['risk', 'users', 'top'], queryFn: () => fetchRiskyUsers({ min_score: 50, limit: 5 }) })
  const riskyEndpoints = useQuery({ queryKey: ['risk', 'endpoints', 'top'], queryFn: () => fetchRiskyEndpoints({ min_score: 75, limit: 5 }) })
  const integrations = useQuery({ queryKey: ['integrations'], queryFn: fetchIntegrations })
  const activityConnected = (integrations.data ?? []).some(item =>
    item.is_enabled
    && item.status === 'connected'
    && ['adfs', 'active_directory', 'google_workspace'].includes(item.integration_type)
  )
  const suspicious = useQuery({
    queryKey: ['activity', 'suspicious'],
    queryFn: () => fetchSuspiciousActivity(6),
    enabled: activityConnected,
  })

  const totalEndpoints = endpoints.data?.total ?? 0
  const summary = compliance.data?.summary
  const issues = compliance.data?.issues
  const activeProductTags = new Set(compliance.data?.active_product_tags ?? ['S1', 'DLP', 'WSS'])
  const criticalRisk = (risk.data?.users.critical ?? 0) + (risk.data?.endpoints.critical ?? 0)
  const enabledIntegrations = integrations.data?.filter(item => item.is_enabled) ?? []
  const healthyIntegrations = enabledIntegrations.filter(item => item.status === 'connected').length
  const integrationErrors = enabledIntegrations.filter(item => item.status === 'error')
  const latestSync = enabledIntegrations
    .map(item => item.last_sync ? new Date(item.last_sync) : null)
    .filter((date): date is Date => Boolean(date))
    .sort((a, b) => b.getTime() - a.getTime())[0]

  const attention = ([
    { id: 'critical-risk', label: 'Critical-risk entities', context: 'Users and endpoints requiring immediate investigation', count: criticalRisk, severity: 'critical', href: '/endpoints?risk=critical', icon: Radar },
    { id: 'non-compliant', label: 'Non-compliant endpoints', context: 'Devices outside the required security baseline', count: summary?.non_compliant ?? 0, severity: 'critical', href: '/compliance?status=non_compliant', icon: ShieldOff },
    { id: 'missing-edr', label: 'Missing EDR coverage', context: 'Endpoints without an active SentinelOne agent', count: issues?.no_edr ?? 0, severity: 'critical', href: '/compliance?issue=no_edr', icon: ShieldOff },
    { id: 'missing-dlp', label: 'Missing DLP coverage', context: 'Endpoints without Symantec DLP protection', count: issues?.no_dlp ?? 0, severity: 'high', href: '/compliance?issue=no_dlp', icon: Database },
    { id: 'missing-wss', label: 'Missing WSS coverage', context: 'Endpoints outside web security enforcement', count: issues?.no_network_security ?? issues?.no_wss ?? 0, severity: 'high', href: '/compliance?issue=no_network_security', icon: Wifi },
    { id: 'unencrypted', label: 'Disk encryption disabled', context: 'Endpoints reporting unencrypted storage', count: issues?.no_disk_encryption ?? issues?.not_encrypted ?? 0, severity: 'high', href: '/compliance?issue=not_encrypted', icon: HardDrive },
    { id: 'device-control', label: 'Device control disabled', context: 'Peripheral controls are not enforced', count: issues?.no_device_control ?? 0, severity: 'warning', href: '/compliance?issue=no_device_control', icon: MousePointer },
    { id: 'integration-errors', label: 'Integration health degraded', context: integrationErrors.map(item => item.display_name).join(', ') || 'One or more data sources need attention', count: integrationErrors.length, severity: 'warning', href: '/integrations', icon: Plug },
  ] satisfies AttentionItem[]).filter(item => {
    if (item.id === 'missing-edr' || item.id === 'unencrypted' || item.id === 'device-control') return activeProductTags.has('S1') && item.count > 0
    if (item.id === 'missing-dlp') return activeProductTags.has('DLP') && item.count > 0
    if (item.id === 'missing-wss') return activeProductTags.has('WSS') && item.count > 0
    return item.count > 0
  })

  const complianceData = summary ? [
    { name: 'Compliant', value: summary.compliant },
    { name: 'Partial', value: summary.partial },
    { name: 'Non-compliant', value: summary.non_compliant },
  ] : []

  const coverage = {
    edr: totalEndpoints - (issues?.no_edr ?? 0),
    dlp: totalEndpoints - (issues?.no_dlp ?? 0),
    wss: totalEndpoints - (issues?.no_wss ?? 0),
  }

  const isLoading = users.isLoading || endpoints.isLoading || compliance.isLoading || risk.isLoading
  const hasError = users.isError || endpoints.isError || compliance.isError || risk.isError

  return (
    <div className="absolute inset-0 overflow-y-auto">
      <div className="mx-auto w-full max-w-[1540px] px-4 py-5 sm:px-6 lg:px-8 lg:py-7">
        <section className="flex flex-col gap-5 border-b pb-6 sm:flex-row sm:items-end sm:justify-between" style={{ borderColor: 'var(--border)' }}>
          <div>
            <h1 className="ui-page-title">
              Security overview
            </h1>
            <p className="ui-page-description">
              {attention.length ? `${attention.length} active conditions prioritized from current control and source evidence.` : 'No active conditions exceed the configured control baselines.'}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="ui-status-chip">
            <span className="status-pulse" data-status={enabledIntegrations.length > 0 && healthyIntegrations === enabledIntegrations.length ? 'healthy' : 'warning'} />
              {healthyIntegrations}/{enabledIntegrations.length || 0} sources healthy
            </span>
            <span className="ui-status-chip tabular-nums">
              {latestSync ? `Fresh ${formatDistanceToNow(latestSync, { addSuffix: true })}` : 'No completed sync'}
            </span>
            <button onClick={() => navigate('/endpoints?risk=critical')} className="ui-primary-button">
              Review risk <ArrowRight size={13} />
            </button>
          </div>
        </section>

        {hasError && (
          <div className="mt-5 flex items-center gap-3 border-l-2 border-red-500 px-4 py-3 text-[13px]" style={{ background: 'rgba(227,84,84,0.06)', color: 'var(--text-2)' }}>
            <CircleAlert size={15} className="text-red-400" />
            Some dashboard data could not be loaded. Available results are shown below.
          </div>
        )}

        <section className="grid grid-cols-2 border-b sm:grid-cols-4 sm:divide-x" style={{ borderColor: 'var(--border)' }} aria-label="Security metrics">
          <Metric label="Identities" value={isLoading ? '—' : users.data?.total ?? 0} note="Tracked users" onClick={() => navigate('/users')} />
          <Metric label="Active endpoints" value={isLoading ? '—' : totalEndpoints} note={`${unassigned.data?.total ?? 0} without owner`} onClick={() => navigate('/endpoints')} />
          <Metric label="Non-compliant" value={isLoading ? '—' : summary?.non_compliant ?? 0} note={`${summary?.partial ?? 0} partially compliant`} tone="danger" onClick={() => navigate('/compliance?status=non_compliant')} />
          <Metric label="Critical risk" value={isLoading ? '—' : criticalRisk} note={`${risk.data?.users.critical ?? 0} users · ${risk.data?.endpoints.critical ?? 0} endpoints`} tone="warning" onClick={() => navigate('/endpoints?risk=critical')} />
        </section>

        <div className="mt-6 grid grid-cols-1 gap-5 lg:grid-cols-[minmax(0,1.55fr)_minmax(300px,0.75fr)]">
          <section className="ui-command-surface overflow-hidden">
            <SectionHeading context="Priority queue" title={`${attention.length} active conditions`} action="Open compliance" onAction={() => navigate('/compliance')} />
            {attention.length ? (
              <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {attention.slice(0, 7).map((item, index) => {
                  const Icon = item.icon
                  const severity = SEVERITY[item.severity]
                  return (
                    <button key={item.id} onClick={() => navigate(item.href)} className="ui-data-row group grid w-full grid-cols-[28px_minmax(0,1fr)_auto] items-center gap-3 px-5 py-3 text-left" style={{ animationDelay: `${index * 35}ms` }}>
                      <span className="flex h-7 w-7 items-center justify-center" style={{ color: severity.color }}>
                        <Icon size={13} strokeWidth={1.8} />
                      </span>
                      <span className="min-w-0">
                        <span className="flex items-center gap-2">
                          <span className="truncate text-[13px] font-medium" style={{ color: 'var(--text-1)' }}>{item.label}</span>
                          <span className="hidden text-[11px] font-medium sm:inline" style={{ color: severity.color }}>{severity.label}</span>
                        </span>
                        <span className="mt-0.5 block truncate text-[11px]" style={{ color: 'var(--text-4)' }}>{item.context}</span>
                      </span>
                      <span className="flex items-center gap-3">
                        <span className="tabular-nums text-[16px] font-semibold" style={{ color: severity.color }}>{item.count}</span>
                        <ArrowRight size={13} className="-translate-x-1 opacity-0 transition-[transform,opacity] group-hover:translate-x-0 group-hover:opacity-100" style={{ color: 'var(--text-3)' }} />
                      </span>
                    </button>
                  )
                })}
              </div>
            ) : (
              <EmptyState icon={ShieldCheck} title="No active conditions" description="Current controls are within their configured baselines" size="sm" />
            )}
          </section>

          <section className="ui-command-surface overflow-hidden">
            <SectionHeading context="Control posture" title="Compliance coverage" action="Details" onAction={() => navigate('/compliance')} />
            {summary?.total ? (
              <>
                <div className="relative h-[210px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={complianceData} dataKey="value" cx="50%" cy="50%" innerRadius={68} outerRadius={84} paddingAngle={2} startAngle={90} endAngle={-270}>
                        {complianceData.map((item, index) => <Cell key={item.name} fill={STATUS_COLORS[index]} stroke="transparent" />)}
                      </Pie>
                      <Tooltip content={<ChartTooltip />} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                    <span className="tabular-nums text-[30px] font-semibold tracking-[-0.05em]" style={{ color: 'var(--text-1)' }}>{summary.compliant_pct}%</span>
                    <span className="mt-1 text-[12px]" style={{ color: 'var(--text-3)' }}>Compliant</span>
                  </div>
                </div>
                <div className="grid grid-cols-3 border-t" style={{ borderColor: 'var(--border)' }}>
                  {complianceData.map((item, index) => (
                    <button key={item.name} onClick={() => navigate(`/compliance?status=${item.name.toLowerCase().replace('-', '_')}`)} className="ui-data-row px-2 py-3 text-center">
                      <span className="block tabular-nums text-[15px]" style={{ color: STATUS_COLORS[index] }}>{item.value}</span>
                      <span className="mt-1 block text-[11px]" style={{ color: 'var(--text-3)' }}>{item.name}</span>
                    </button>
                  ))}
                </div>
              </>
            ) : (
              <EmptyState icon={ShieldCheck} title="No compliance data" description="Run an evaluation to calculate posture" size="sm" action={{ label: 'Open compliance', onClick: () => navigate('/compliance') }} />
            )}
          </section>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.72fr)]">
          <section className="ui-command-surface overflow-hidden">
            <SectionHeading context="Coverage" title="Security control deployment" action="View endpoints" onAction={() => navigate('/endpoints')} />
            {activeProductTags.has('S1') && <CoverageRow label="SentinelOne EDR" detail="Installed endpoint protection" value={coverage.edr} total={totalEndpoints} href="/endpoints?agent=has_s1" onOpen={navigate} />}
            {activeProductTags.has('DLP') && <CoverageRow label="Symantec DLP" detail="Data loss prevention agent" value={coverage.dlp} total={totalEndpoints} href="/endpoints?agent=has_dlp" onOpen={navigate} />}
            {activeProductTags.has('WSS') && <CoverageRow label="Symantec WSS" detail="Web security service agent" value={coverage.wss} total={totalEndpoints} href="/endpoints?agent=has_wss" onOpen={navigate} />}
          </section>

          <section className="ui-command-surface overflow-hidden">
            <SectionHeading context="Data plane" title="Integration freshness" action="Manage" onAction={() => navigate('/integrations')} />
            {enabledIntegrations.length ? enabledIntegrations.slice(0, 5).map(item => {
              const Icon = INTEGRATION_ICONS[item.integration_type] ?? Plug
              const status = item.status === 'connected' ? 'healthy' : item.status === 'error' ? 'error' : 'warning'
              return (
                <button key={item.id} onClick={() => navigate('/integrations')} className="ui-data-row grid w-full grid-cols-[28px_minmax(0,1fr)_auto] items-center gap-3 px-5 py-3 text-left">
                  <span className="flex h-7 w-7 items-center justify-center" style={{ color: 'var(--text-3)' }}><Icon size={13} /></span>
                  <span className="min-w-0">
                    <span className="block truncate text-[12px] font-medium" style={{ color: 'var(--text-2)' }}>{item.display_name}</span>
                    <span className="mt-0.5 block text-[11px]" style={{ color: 'var(--text-3)' }}>{item.last_sync ? formatDistanceToNow(new Date(item.last_sync), { addSuffix: true }) : 'Never synchronized'}</span>
                  </span>
                  <span className="flex items-center gap-2 text-[11px] capitalize" style={{ color: 'var(--text-3)' }}><span className="status-pulse" data-status={status} />{item.status}</span>
                </button>
              )
            }) : <EmptyState icon={Plug} title="No active sources" description="Enable an integration to begin collecting data" size="sm" action={{ label: 'Configure', onClick: () => navigate('/integrations') }} />}
          </section>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-2">
          <section className="ui-command-surface overflow-hidden">
            <SectionHeading context="Risk watchlist" title="Entities requiring attention" action="Open endpoints" onAction={() => navigate('/endpoints?risk=critical')} />
            <div className="grid grid-cols-1 sm:grid-cols-2 sm:divide-x" style={{ borderColor: 'var(--border)' }}>
              <div>
                <p className="ui-context px-5 pb-2 pt-4">Users</p>
                {riskyUsers.data?.data.length ? riskyUsers.data.data.map(user => (
                  <button key={user.id} onClick={() => openPanel('user', user.id, user.full_name)} className="ui-data-row flex w-full items-center gap-3 px-5 py-2.5 text-left">
                    <span className="flex h-7 w-7 items-center justify-center rounded-[5px] text-[11px] font-semibold" style={{ background: 'var(--surface-3)', color: 'var(--text-2)' }}>{user.full_name[0]}</span>
                    <span className="min-w-0 flex-1"><span className="block truncate text-[12px] font-medium" style={{ color: 'var(--text-2)' }}>{user.full_name}</span><span className="block truncate text-[11px]" style={{ color: 'var(--text-3)' }}>{user.department || user.email}</span></span>
                    <RiskBadge score={user.risk_score} />
                  </button>
                )) : <EmptyState icon={CheckCircle2} title="No high-risk users" size="sm" />}
              </div>
              <div>
                <p className="ui-context px-5 pb-2 pt-4">Endpoints</p>
                {riskyEndpoints.data?.data.length ? riskyEndpoints.data.data.map(endpoint => (
                  <button key={endpoint.id} onClick={() => openPanel('endpoint', endpoint.id, endpoint.hostname)} className="ui-data-row flex w-full items-center gap-3 px-5 py-2.5 text-left">
                    <span className="flex h-7 w-7 items-center justify-center" style={{ color: '#e35454' }}><Monitor size={13} /></span>
                    <span className="min-w-0 flex-1"><span className="block truncate text-[12px] font-medium" style={{ color: 'var(--text-2)' }}>{endpoint.hostname}</span><span className="block truncate text-[11px]" style={{ color: 'var(--text-3)' }}>{endpoint.os_version || endpoint.ip_address || 'Unknown OS'}</span></span>
                    <RiskBadge score={endpoint.risk_score} />
                  </button>
                )) : <EmptyState icon={CheckCircle2} title="No critical endpoints" size="sm" />}
              </div>
            </div>
          </section>

          <section className="ui-command-surface overflow-hidden">
            <SectionHeading context="Signals" title="Suspicious activity" action={activityConnected ? 'Open timeline' : undefined} onAction={activityConnected ? () => navigate('/activity?is_suspicious=true') : undefined} />
            {!activityConnected ? (
              <EmptyState icon={Plug} title="Activity is locked" description="Connect ADFS, Active Directory, or Google Workspace to enable the activity timeline" size="sm" />
            ) : suspicious.data?.length ? suspicious.data.map(event => (
              <button key={event.id} onClick={() => event.user?.id ? openPanel('user', event.user.id, event.user.full_name) : navigate('/activity')} className="ui-data-row grid w-full grid-cols-[28px_minmax(0,1fr)_auto] items-center gap-3 px-5 py-3 text-left">
                <span className="flex h-7 w-7 items-center justify-center" style={{ color: '#e35454' }}><Activity size={13} /></span>
                <span className="min-w-0"><span className="block truncate text-[12px] font-medium" style={{ color: 'var(--text-2)' }}>{event.user?.full_name || 'Unattributed activity'}</span><span className="block truncate text-[11px] capitalize" style={{ color: 'var(--text-3)' }}>{event.event_type.replace('_', ' ')} · {event.country || event.ip_address || 'Unknown source'}</span></span>
                <span className="whitespace-nowrap tabular-nums text-[11px]" style={{ color: 'var(--text-3)' }}>{formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}</span>
              </button>
            )) : <EmptyState icon={CheckCircle2} title="No suspicious activity" description="No events are flagged in the current monitoring window" size="sm" />}
          </section>
        </div>

        <p className="mt-6 flex items-center gap-2 text-[11px]" style={{ color: 'var(--text-3)' }}>
          <AlertTriangle size={11} /> Counts reflect active inventory and the latest completed source observations.
        </p>
      </div>
    </div>
  )
}
