import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Users, Monitor, AlertTriangle, ShieldAlert,
  AlertCircle, CheckCircle2, Plug,
  Server, Shield, Database, Globe, UserCheck,
  ShieldOff, HardDrive, MousePointer, Wifi,
} from 'lucide-react'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer,
} from 'recharts'
import StatCard from '../components/shared/StatCard'
import RiskBadge from '../components/shared/RiskBadge'
import EmptyState from '../components/shared/EmptyState'
import { usePanelStore } from '../store/panels'
import { fetchUsers } from '../api/users'
import { fetchEndpoints } from '../api/endpoints'
import { fetchComplianceDashboard } from '../api/compliance'
import { fetchRiskSummary, fetchRiskyUsers, fetchRiskyEndpoints } from '../api/risk'
import { fetchSuspiciousActivity } from '../api/activity'
import { fetchIntegrations } from '../api/integrations'
import { formatDistanceToNow } from 'date-fns'

const COMPLIANCE_COLORS = ['#10b981', '#eab308', '#ef4444']
const RISK_COLORS       = ['#10b981', '#eab308', '#f97316', '#ef4444']
const RISK_LABELS       = ['Low', 'Medium', 'High', 'Critical']

const ChartTooltip = ({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; fill?: string; color?: string }[]; label?: string }) =>
  active && payload?.length ? (
    <div className="rounded-xl px-3.5 py-2.5 text-[12px]"
      style={{ background: 'var(--surface-3)', border: '1px solid var(--border-lit)', boxShadow: '0 8px 32px rgba(0,0,0,0.6)', backdropFilter: 'blur(8px)' }}>
      {label && <p className="font-semibold mb-1.5" style={{ color: 'var(--text-1)' }}>{label}</p>}
      {payload.map((p, i) => (
        <div key={i} className="flex items-center gap-2.5 py-0.5">
          <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: p.fill || p.color || '#10b981' }} />
          <span style={{ color: 'var(--text-3)' }}>{p.name}</span>
          <span className="ml-auto font-bold tabular-nums" style={{ color: 'var(--text-1)' }}>{p.value}</span>
        </div>
      ))}
    </div>
  ) : null

function CoverageBar({ label, value, total, color, onClick }: { label: string; value: number; total: number; color: string; onClick?: () => void }) {
  const pct = total > 0 ? Math.round(value / total * 100) : 0
  return (
    <div className={onClick ? 'cursor-pointer group' : ''} onClick={onClick}>
      <div className="flex justify-between items-center mb-1">
        <span className="text-xs transition-[color] duration-150" style={{ color: "var(--text-3)" }}>{label}</span>
        <span className="text-xs font-semibold tabular-nums" style={{ color: "var(--text-1)" }}>{pct}% <span className="text-gray-500 font-normal">({value}/{total})</span></span>
      </div>
      <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "var(--surface-3)" }}>
        <div className="h-full rounded-full transition-[width] duration-500" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
    </div>
  )
}

const INTEGRATION_ICON_MAP: Record<string, React.ElementType> = {
  jumpcloud: Server, sentinelone: Shield, symantec_dlp: Database, google_workspace: Globe, hibob: UserCheck,
}

const COMPLIANCE_STATUS_MAP: Record<string, string> = {
  'Compliant': 'compliant', 'Partial': 'partial', 'Non-Compliant': 'non_compliant',
}

export default function Dashboard() {
  const navigate = useNavigate()
  const { openPanel } = usePanelStore()

  const { data: usersData }         = useQuery({ queryKey: ['users', 'total'],           queryFn: () => fetchUsers({ limit: 1 }) })
  const { data: endpointsData }     = useQuery({ queryKey: ['endpoints', 'total'],       queryFn: () => fetchEndpoints({ limit: 1 }) })
  const { data: unassignedData }    = useQuery({ queryKey: ['endpoints', 'unassigned'],  queryFn: () => fetchEndpoints({ unassigned: true, limit: 1 } as Parameters<typeof fetchEndpoints>[0]) })
  const { data: complianceDash }    = useQuery({ queryKey: ['compliance', 'dashboard'],  queryFn: fetchComplianceDashboard })
  const { data: riskSummary }       = useQuery({ queryKey: ['risk', 'summary'],          queryFn: fetchRiskSummary })
  const { data: riskyUsers }        = useQuery({ queryKey: ['risk', 'users', 'top'],     queryFn: () => fetchRiskyUsers({ min_score: 50, limit: 5 }) })
  const { data: criticalEndpoints } = useQuery({ queryKey: ['risk', 'endpoints', 'top'], queryFn: () => fetchRiskyEndpoints({ min_score: 75, limit: 5 }) })
  const { data: suspiciousActivity }= useQuery({ queryKey: ['activity', 'suspicious'],   queryFn: () => fetchSuspiciousActivity(8) })
  const { data: integrations }      = useQuery({ queryKey: ['integrations'],             queryFn: fetchIntegrations })

  const totalEndpoints = endpointsData?.total ?? 0
  const criticalCount  = (riskSummary?.users.critical ?? 0) + (riskSummary?.endpoints.critical ?? 0)

  // Use dashboard summary for all compliance stats
  const complianceSummary = complianceDash?.summary

  // Compliance pie data
  const compliancePieData = complianceSummary ? [
    { name: 'Compliant',     value: complianceSummary.compliant },
    { name: 'Partial',       value: complianceSummary.partial },
    { name: 'Non-Compliant', value: complianceSummary.non_compliant },
  ] : []

  // Risk bar data
  const riskBarData = riskSummary ? [
    { name: 'Low',      users: riskSummary.users.low      ?? 0, endpoints: riskSummary.endpoints.low      ?? 0 },
    { name: 'Medium',   users: riskSummary.users.medium   ?? 0, endpoints: riskSummary.endpoints.medium   ?? 0 },
    { name: 'High',     users: riskSummary.users.high     ?? 0, endpoints: riskSummary.endpoints.high     ?? 0 },
    { name: 'Critical', users: riskSummary.users.critical ?? 0, endpoints: riskSummary.endpoints.critical ?? 0 },
  ] : []

  // User risk pie (for High-Risk Users panel)
  const userRiskPieData = riskSummary ? [
    { name: 'Low',      value: riskSummary.users.low      ?? 0 },
    { name: 'Medium',   value: riskSummary.users.medium   ?? 0 },
    { name: 'High',     value: riskSummary.users.high     ?? 0 },
    { name: 'Critical', value: riskSummary.users.critical ?? 0 },
  ].filter(d => d.value > 0) : []

  // Coverage numbers
  const edrInstalled = totalEndpoints - (complianceDash?.issues.no_edr       ?? 0)
  const dlpInstalled = totalEndpoints - (complianceDash?.issues.no_dlp       ?? 0)
  const wssInstalled = totalEndpoints - (complianceDash?.issues.no_wss       ?? 0)
  const edrVersionOk = edrInstalled   - (complianceDash?.issues.edr_outdated ?? 0)
  const dlpVersionOk = dlpInstalled   - (complianceDash?.issues.dlp_outdated ?? 0)
  const wssVersionOk = wssInstalled   - (complianceDash?.issues.wss_outdated ?? 0)

  return (
    <div className="absolute inset-0 overflow-y-auto p-6">
    <div className="space-y-5">

      {/* ── Stat cards ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          title="Total Users" value={usersData?.total ?? '—'}
          icon={Users} iconColor="text-green-400" subtitle="Tracked identities"
          onClick={() => navigate('/users')}
          style={{ animationDelay: '0ms' }}
        />
        <StatCard
          title="Total Endpoints" value={endpointsData?.total ?? '—'}
          icon={Monitor} iconColor="text-green-400" subtitle="Managed devices"
          onClick={() => navigate('/endpoints')}
          style={{ animationDelay: '50ms' }}
        />
        <StatCard
          title="Non-Compliant" value={complianceSummary?.non_compliant ?? '—'}
          icon={AlertTriangle} iconColor="text-red-400"
          subtitle={complianceSummary ? `${complianceSummary.partial} partial · ${complianceSummary.compliant_pct}% compliant` : undefined}
          onClick={() => navigate('/compliance?status=non_compliant')}
          style={{ animationDelay: '100ms' }}
        />
        <StatCard
          title="Critical Risk" value={criticalCount || '—'}
          icon={ShieldAlert} iconColor="text-orange-400"
          subtitle={riskSummary ? `${riskSummary.users.critical ?? 0} users · ${riskSummary.endpoints.critical ?? 0} endpoints` : undefined}
          onClick={() => navigate('/endpoints?risk=critical')}
          style={{ animationDelay: '150ms' }}
        />
      </div>

      {/* ── Charts row ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Compliance donut */}
        <div className="rounded-xl p-5 card flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[13px] font-semibold tracking-tight" style={{ color: "var(--text-1)" }}>Compliance Status</h3>
            <button onClick={() => navigate('/compliance')} className="text-xs font-medium transition-[color] duration-150" style={{ color: "var(--accent)" }}>View all →</button>
          </div>
          {complianceSummary && complianceSummary.total > 0 ? (
            <div className="flex flex-col flex-1">
              <div className="relative flex-1 min-h-[160px]">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={compliancePieData}
                      cx="50%" cy="50%"
                      innerRadius={58} outerRadius={82}
                      paddingAngle={2} dataKey="value"
                      onClick={(d) => navigate(`/compliance?status=${COMPLIANCE_STATUS_MAP[d.name] ?? ''}`)}
                      className="cursor-pointer"
                    >
                      {compliancePieData.map((_, i) => (
                        <Cell key={i} fill={COMPLIANCE_COLORS[i]} stroke="transparent" />
                      ))}
                    </Pie>
                    <Tooltip content={<ChartTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
                {/* centre label */}
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className={`text-2xl font-semibold tabular-nums ${complianceSummary.compliant_pct >= 80 ? 'text-green-400' : complianceSummary.compliant_pct >= 60 ? 'text-yellow-400' : 'text-red-400'}`}>
                    {complianceSummary.compliant_pct}%
                  </span>
                  <span className="text-xs mt-0.5" style={{ color: "var(--text-4)" }}>compliant</span>
                </div>
              </div>
              <div className="space-y-1.5 mt-1">
                {compliancePieData.map((d, i) => (
                  <button
                    key={d.name}
                    onClick={() => navigate(`/compliance?status=${COMPLIANCE_STATUS_MAP[d.name] ?? ''}`)}
                    className="w-full flex items-center justify-between px-2 py-1.5 rounded-lg transition-[background-color] duration-150" onMouseEnter={(e) => (e.currentTarget.style.background = "var(--hover-1)")} onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                  >
                    <div className="flex items-center gap-2">
                      <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ backgroundColor: COMPLIANCE_COLORS[i] }} />
                      <span className="text-xs transition-[color] duration-150" style={{ color: "var(--text-3)" }}>{d.name}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold tabular-nums" style={{ color: "var(--text-1)" }}>{d.value}</span>
                      <span className="text-xs text-gray-600 w-8 text-right tabular-nums">{Math.round(d.value / complianceSummary.total * 100)}%</span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <EmptyState icon={CheckCircle2} title="No compliance data" description="Run an evaluation to see results" size="sm" action={{ label: 'Go to Compliance', onClick: () => navigate('/compliance') }} />
          )}
        </div>

        {/* Risk distribution bar */}
        <div className="rounded-xl p-5 card flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[13px] font-semibold tracking-tight" style={{ color: "var(--text-1)" }}>Risk Distribution</h3>
            <div className="flex items-center gap-3 text-xs" style={{ color: "var(--text-4)" }}>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm inline-block" style={{ background: '#059669' }} />Users</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm inline-block" style={{ background: '#10b981' }} />Endpoints</span>
            </div>
          </div>
          {riskBarData.some(d => d.users + d.endpoints > 0) ? (
            <div className="flex flex-col flex-1">
            <div className="flex-1 min-h-[160px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskBarData} barGap={3} barCategoryGap="28%">
                <defs>
                  <linearGradient id="usersGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#059669" stopOpacity={1} />
                    <stop offset="100%" stopColor="#059669" stopOpacity={0.6} />
                  </linearGradient>
                  <linearGradient id="endpointsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#10b981" stopOpacity={1} />
                    <stop offset="100%" stopColor="#10b981" stopOpacity={0.6} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" tick={{ fill: '#52525e', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#52525e', fontSize: 10 }} axisLine={false} tickLine={false} width={24} />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)', radius: 6 }} />
                <Bar dataKey="users"     name="Users"     fill="url(#usersGrad)"     radius={[4,4,0,0]} className="cursor-pointer"
                  onClick={(d) => navigate(`/users?risk=${d.name.toLowerCase()}`)} />
                <Bar dataKey="endpoints" name="Endpoints" fill="url(#endpointsGrad)" radius={[4,4,0,0]} className="cursor-pointer"
                  onClick={(d) => navigate(`/endpoints?risk=${d.name.toLowerCase()}`)} />
              </BarChart>
            </ResponsiveContainer>
            </div>
            {riskSummary && (
              <div className="grid grid-cols-4 gap-1 mt-2">
                {RISK_LABELS.map((label, i) => (
                  <button key={label} onClick={() => navigate(`/users?risk=${label.toLowerCase()}`)}
                    className="flex flex-col items-center py-1.5 rounded-lg transition-[background-color] duration-150"
                    onMouseEnter={e => (e.currentTarget.style.background = "var(--hover-1)")}
                    onMouseLeave={e => (e.currentTarget.style.background = "transparent")}>
                    <span className="text-xs font-bold tabular-nums" style={{ color: "var(--text-1)" }}>
                      {(riskSummary.users[label.toLowerCase() as keyof typeof riskSummary.users] ?? 0) + (riskSummary.endpoints[label.toLowerCase() as keyof typeof riskSummary.endpoints] ?? 0)}
                    </span>
                    <span className="text-[10px] mt-0.5 font-semibold" style={{ color: RISK_COLORS[i] }}>{label}</span>
                  </button>
                ))}
              </div>
            )}
            </div>
          ) : (
            <EmptyState icon={ShieldAlert} title="No risk data" size="sm" />
          )}
        </div>

        {/* Security coverage */}
        <div className="rounded-xl p-5 card">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[13px] font-semibold tracking-tight" style={{ color: "var(--text-1)" }}>Security Coverage</h3>
            <button onClick={() => navigate('/endpoints')} className="text-xs font-medium transition-[color] duration-150" style={{ color: "var(--accent)" }}>View →</button>
          </div>
          {totalEndpoints > 0 ? (
            <div className="space-y-4">
              <div className="space-y-3">
                <p className="text-[10px] font-semibold uppercase tracking-widest" style={{ color: "var(--text-4)" }}>EDR · SentinelOne</p>
                <CoverageBar label="Installed"  value={edrInstalled} total={totalEndpoints} color="#10b981" onClick={() => navigate('/endpoints?agent=has_s1')} />
                <CoverageBar label="Up to date" value={edrVersionOk} total={edrInstalled}   color="#059669" onClick={() => navigate('/endpoints?agent=has_s1')} />
              </div>
              <div className="pt-4 space-y-3" style={{ borderTop: "1px solid var(--border)" }}>
                <p className="text-[10px] font-semibold uppercase tracking-widest" style={{ color: "var(--text-4)" }}>DLP · Symantec</p>
                <CoverageBar label="Installed"  value={dlpInstalled} total={totalEndpoints} color="#10b981" onClick={() => navigate('/endpoints?agent=has_dlp')} />
                <CoverageBar label="Up to date" value={dlpVersionOk} total={dlpInstalled}   color="#059669" onClick={() => navigate('/endpoints?agent=has_dlp')} />
              </div>
              <div className="pt-4 space-y-3" style={{ borderTop: "1px solid var(--border)" }}>
                <p className="text-[10px] font-semibold uppercase tracking-widest" style={{ color: "var(--text-4)" }}>Proxy · Symantec WSS</p>
                <CoverageBar label="Installed"  value={wssInstalled} total={totalEndpoints} color="#10b981" onClick={() => navigate('/endpoints?agent=has_wss')} />
                <CoverageBar label="Up to date" value={wssVersionOk} total={wssInstalled}   color="#059669" onClick={() => navigate('/endpoints?agent=has_wss')} />
              </div>
              <button
                onClick={() => navigate('/endpoints?owner=unassigned')}
                className="w-full pt-3 flex justify-between items-center transition-[opacity] duration-150 hover:opacity-75" style={{ borderTop: "1px solid var(--border)" }}
              >
                <span className="text-xs" style={{ color: "var(--text-4)" }}>Unassigned endpoints</span>
                <span className="text-sm font-semibold text-orange-400 tabular-nums">{unassignedData?.total ?? '—'}</span>
              </button>
            </div>
          ) : (
            <EmptyState icon={Monitor} title="No endpoints yet" description="Connect an integration to sync devices" size="sm" action={{ label: 'Integrations', onClick: () => navigate('/integrations') }} />
          )}
        </div>
      </div>

      {/* ── Top Issues ────────────────────────────────────────────────────── */}
      {complianceDash && (() => {
        const iss = complianceDash.issues
        const issues = [
          { key: 'no_edr',       label: 'Missing EDR',         count: iss.no_edr ?? 0,                                             icon: ShieldOff,     color: '#ef4444', href: '/compliance?issue=no_edr' },
          { key: 'no_dlp',       label: 'Missing DLP',         count: iss.no_dlp ?? 0,                                             icon: ShieldOff,     color: '#f97316', href: '/compliance?issue=no_dlp' },
          { key: 'no_network',   label: 'No Network Security', count: iss.no_network_security ?? 0,                                icon: Wifi,          color: '#eab308', href: '/compliance?issue=no_network_security' },
          { key: 'no_disk_enc',  label: 'Disk Not Encrypted',  count: iss.no_disk_encryption ?? iss.not_encrypted ?? 0,           icon: HardDrive,     color: '#f97316', href: '/compliance?issue=not_encrypted' },
          { key: 'no_dev_ctrl',  label: 'Device Control Off',  count: iss.no_device_control ?? 0,                                 icon: MousePointer,  color: '#eab308', href: '/compliance?issue=no_device_control' },
          { key: 'edr_outdated', label: 'EDR Outdated',        count: iss.edr_outdated ?? 0,                                      icon: AlertTriangle, color: '#f97316', href: '/compliance?issue=edr_outdated' },
        ].filter(i => i.count > 0)

        if (issues.length === 0) return null
        return (
          <div className="rounded-xl p-5 card">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <AlertTriangle size={14} className="text-orange-400" />
                <h3 className="text-[13px] font-semibold tracking-tight" style={{ color: 'var(--text-1)' }}>Top Security Issues</h3>
                <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-orange-500/15 text-orange-400 border border-orange-500/20 font-medium">
                  {issues.length} active
                </span>
              </div>
              <button onClick={() => navigate('/compliance')} className="text-xs font-medium transition-[color] duration-150" style={{ color: 'var(--accent)' }}>View all →</button>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-2">
              {issues.map(issue => {
                const Icon = issue.icon
                return (
                  <button
                    key={issue.key}
                    onClick={() => navigate(issue.href)}
                    className="flex flex-col gap-2 p-3 rounded-xl text-left pressable transition-[background-color,border-color] duration-150"
                    style={{ background: 'var(--surface-3)', border: `1px solid var(--border)` }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = `${issue.color}40` }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)' }}
                  >
                    <div className="flex items-center justify-between">
                      <div className="w-6 h-6 rounded-lg flex items-center justify-center" style={{ background: `${issue.color}18` }}>
                        <Icon size={12} style={{ color: issue.color }} />
                      </div>
                      <span className="text-lg font-bold tabular-nums leading-none" style={{ color: issue.color }}>
                        {issue.count}
                      </span>
                    </div>
                    <span className="text-[11px] font-medium leading-tight" style={{ color: 'var(--text-3)' }}>{issue.label}</span>
                  </button>
                )
              })}
            </div>
          </div>
        )
      })()}

      {/* ── Lists row ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 items-start">

        {/* High-risk users with risk pie */}
        <div className="rounded-xl p-5 card">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[13px] font-semibold tracking-tight" style={{ color: "var(--text-1)" }}>High-Risk Users</h3>
            <button onClick={() => navigate('/users')} className="text-xs font-medium transition-[color] duration-150" style={{ color: "var(--accent)" }}>View all →</button>
          </div>

          {/* mini pie + counts */}
          {userRiskPieData.length > 0 && (
            <div className="flex items-center gap-3 mb-4 pb-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <ResponsiveContainer width={80} height={80}>
                <PieChart>
                  <Pie data={userRiskPieData} cx="50%" cy="50%" innerRadius={22} outerRadius={38}
                    paddingAngle={2} dataKey="value"
                    onClick={(d) => navigate(`/users?risk=${d.name.toLowerCase()}`)} className="cursor-pointer">
                    {userRiskPieData.map((d) => (
                      <Cell key={d.name} fill={RISK_COLORS[RISK_LABELS.indexOf(d.name)]} stroke="transparent" />
                    ))}
                  </Pie>
                  <Tooltip content={<ChartTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 flex-1">
                {RISK_LABELS.map((label, i) => {
                  const val = riskSummary?.users[label.toLowerCase() as keyof typeof riskSummary.users] ?? 0
                  return (
                    <button key={label} onClick={() => navigate(`/users?risk=${label.toLowerCase()}`)}
                      className="flex items-center gap-1.5 hover:opacity-80 transition-opacity">
                      <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: RISK_COLORS[i] }} />
                      <span className="text-xs" style={{ color: "var(--text-3)" }}>{label}</span>
                      <span className="text-xs font-semibold ml-auto tabular-nums" style={{ color: "var(--text-1)" }}>{val}</span>
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {/* user list */}
          <div className="space-y-0.5">
            {riskyUsers?.data.length ? riskyUsers.data.map(u => (
              <button key={u.id} onClick={() => openPanel('user', u.id, u.full_name)}
                className="w-full flex items-center gap-3 px-2 py-2 rounded-lg cursor-pointer text-left pressable transition-[background-color] duration-150" style={{ color: "inherit" }} onMouseEnter={(e) => (e.currentTarget.style.background = "var(--hover-1)")} onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0" style={{ background: "linear-gradient(135deg,#059669,#0d9488)", color: "#fff" }}>
                  {u.full_name[0]}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-[13px] font-medium truncate" style={{ color: "var(--text-1)" }}>{u.full_name}</div>
                  <div className="text-xs truncate" style={{ color: "var(--text-4)" }}>{u.department || u.email}</div>
                </div>
                <RiskBadge score={u.risk_score} />
              </button>
            )) : (
              <EmptyState icon={CheckCircle2} title="No high-risk users" description="All users are within safe risk thresholds" size="sm" />
            )}
          </div>
        </div>

        {/* Critical endpoints */}
        <div className="rounded-xl p-5 card">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[13px] font-semibold tracking-tight" style={{ color: "var(--text-1)" }}>Critical Endpoints</h3>
            <button onClick={() => navigate('/endpoints')} className="text-xs font-medium transition-[color] duration-150" style={{ color: "var(--accent)" }}>View all →</button>
          </div>
          <div className="space-y-0.5">
            {criticalEndpoints?.data.length ? criticalEndpoints.data.map(ep => (
              <button key={ep.id} onClick={() => openPanel('endpoint', ep.id, ep.hostname)}
                className="w-full flex items-center gap-3 px-2 py-2 rounded-lg cursor-pointer text-left pressable transition-[background-color] duration-150" style={{ color: "inherit" }} onMouseEnter={(e) => (e.currentTarget.style.background = "var(--hover-1)")} onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}>
                <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: "rgba(239,68,68,0.12)" }}>
                  <Monitor size={13} className="text-red-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-[13px] font-medium truncate" style={{ color: "var(--text-1)" }}>{ep.hostname}</div>
                  <div className="text-xs truncate" style={{ color: "var(--text-4)" }}>{ep.os_version || ep.ip_address || '—'}</div>
                </div>
                <RiskBadge score={ep.risk_score} />
              </button>
            )) : (
              <EmptyState icon={CheckCircle2} title="No critical endpoints" description="No endpoints are above the critical risk threshold" size="sm" />
            )}
          </div>
        </div>

        {/* Integration status */}
        <div className="rounded-xl p-5 card">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[13px] font-semibold tracking-tight" style={{ color: "var(--text-1)" }}>Integration Status</h3>
            <button onClick={() => navigate('/integrations')} className="text-xs font-medium transition-[color] duration-150" style={{ color: "var(--accent)" }}>Manage →</button>
          </div>
          <div className="space-y-1">
            {integrations?.length ? integrations.map(intg => (
              <button key={intg.id} onClick={() => navigate('/integrations')}
                className="w-full flex items-center gap-3 px-2 py-2.5 rounded-lg text-left pressable transition-[background-color] duration-150">
                {(() => { const IC = INTEGRATION_ICON_MAP[intg.integration_type] ?? Plug; return <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: 'var(--surface-3)' }}><IC size={14} style={{ color: 'var(--text-3)' }} /></div> })()}
                <div className="flex-1 min-w-0">
                  <div className="text-[13px] font-medium" style={{ color: "var(--text-1)" }}>{intg.display_name}</div>
                  <div className="text-xs" style={{ color: "var(--text-4)" }}>
                    {intg.last_sync
                      ? `Synced ${formatDistanceToNow(new Date(intg.last_sync), { addSuffix: true })}`
                      : 'Never synced'}
                  </div>
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0 tabular-nums">
                  <span className={`w-2 h-2 rounded-full ${
                    intg.status === 'connected'         ? 'bg-green-500' :
                    intg.status === 'error'             ? 'bg-red-500'   :
                    intg.credentials_configured         ? 'bg-yellow-500' : 'bg-gray-600'
                  }`} />
                  <span className={`text-xs capitalize ${
                    intg.status === 'connected' ? 'text-green-400' :
                    intg.status === 'error'     ? 'text-red-400'   : 'text-gray-500'
                  }`}>
                    {intg.status}
                  </span>
                </div>
              </button>
            )) : (
              <EmptyState icon={Plug} title="No integrations" description="Connect a data source to start syncing" size="sm" action={{ label: 'Add integration', onClick: () => navigate('/integrations') }} />
            )}
          </div>
        </div>
      </div>

      {/* ── Suspicious activity ────────────────────────────────────────────── */}
      <div className="rounded-xl p-5 card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-[13px] font-semibold tracking-tight" style={{ color: "var(--text-1)" }}>Suspicious Activity</h3>
          <button onClick={() => navigate('/activity')} className="text-xs font-medium transition-[color] duration-150" style={{ color: "var(--accent)" }}>View all →</button>
        </div>
        {suspiciousActivity?.length ? (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-2">
            {suspiciousActivity.map(e => (
              <button key={e.id}
                onClick={() => e.user?.id ? openPanel('user', e.user.id, e.user.full_name) : navigate('/activity')}
                className="flex items-start gap-2.5 p-3 rounded-lg text-left w-full pressable transition-[background-color,border-color] duration-150" style={{ background: "rgba(239,68,68,0.05)", border: "1px solid rgba(239,68,68,0.1)" }} onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(239,68,68,0.09)"; e.currentTarget.style.borderColor = "rgba(239,68,68,0.2)" }} onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(239,68,68,0.05)"; e.currentTarget.style.borderColor = "rgba(239,68,68,0.1)" }}>
                <AlertCircle size={14} className="text-red-400 mt-0.5 flex-shrink-0" />
                <div className="min-w-0">
                  <div className="text-[13px] font-medium truncate" style={{ color: "var(--text-1)" }}>{e.user?.full_name || 'Unknown'}</div>
                  <div className="text-xs mt-0.5 truncate" style={{ color: "var(--text-3)" }}>{e.event_type} · {e.country || e.ip_address || '—'}</div>
                  <div className="text-xs mt-0.5" style={{ color: "#36363f" }}>{formatDistanceToNow(new Date(e.timestamp), { addSuffix: true })}</div>
                  {Boolean(e.details?.flag) && (
                    <span className="mt-1 inline-block text-xs rounded px-1.5 py-0.5" style={{ background: "rgba(239,68,68,0.1)", color: "#f87171", border: "1px solid rgba(239,68,68,0.2)" }}>
                      {String(e.details!.flag).replace('_', ' ')}
                    </span>
                  )}
                </div>
              </button>
            ))}
          </div>
        ) : (
          <EmptyState icon={CheckCircle2} title="No suspicious activity" description="No flagged events in the current monitoring window" size="sm" />
        )}
      </div>

    </div>
    </div>
  )
}
