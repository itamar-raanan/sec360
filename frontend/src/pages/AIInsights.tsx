import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Brain,
  Sparkles,
  Play,
  ChevronDown,
  ChevronRight,
  X,
  RotateCcw,
  Users,
  Monitor,
  ShieldAlert,
  Database,
  Wrench,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Loader2,
  ArrowRight,
} from 'lucide-react'
import {
  fetchInsights,
  fetchInsightStats,
  dismissInsight,
  undismissInsight,
  runAnalysis,
} from '../api/ai'
import type { AIInsight } from '../api/ai'

const PAGE_SIZE = 50

// ── Category definitions ─────────────────────────────────────────────────────

const CATEGORIES = [
  {
    id: 'user',
    label: 'User Compliance',
    icon: Users,
    types: ['users_no_mfa', 'stale_accounts', 'unmanaged_device_access', 'suspended_user_active', 'mfa_changes'],
  },
  {
    id: 'endpoint',
    label: 'Endpoint Compliance',
    icon: Monitor,
    types: [
      'endpoints_missing_edr',
      'endpoints_missing_encryption',
      'endpoints_missing_dlp',
      'endpoints_missing_vpn',
      'inactive_agents',
      'non_compliant_endpoints',
      'partial_compliance_endpoints',
    ],
  },
  {
    id: 'access',
    label: 'Access Control',
    icon: ShieldAlert,
    types: ['suspended_user_active', 'auth_brute_force', 'after_hours_logins', 'risky_oauth'],
  },
  {
    id: 'data',
    label: 'Data Security',
    icon: Database,
    types: ['bulk_cloud_access', 'mfa_changes', 'risky_oauth', 'cloud_threat_incidents'],
  },
]

// ── Recommended actions ───────────────────────────────────────────────────────

const RECOMMENDED_ACTIONS: Record<string, string> = {
  users_no_mfa: 'Enforce MFA via JumpCloud policy. Require enrollment within 48h for all active users.',
  stale_accounts: 'Review and disable accounts with no activity in 60+ days. Reduces attack surface.',
  endpoints_missing_edr: 'Deploy SentinelOne to unprotected endpoints via JumpCloud MDM policy.',
  endpoints_missing_encryption: 'Enable FileVault (macOS) or BitLocker (Windows) via MDM policy.',
  endpoints_missing_dlp: 'Deploy Symantec DLP agent. Required for PII/financial data compliance.',
  endpoints_missing_vpn: 'Deploy GlobalProtect agent for network policy enforcement.',
  inactive_agents: 'Investigate offline agents — may indicate unmanaged devices or agent tampering.',
  non_compliant_endpoints: 'Quarantine non-compliant endpoints until remediated.',
  partial_compliance_endpoints: 'Review missing controls per endpoint and create remediation tickets.',
  unmanaged_device_access: 'Enroll devices in MDM or block access from unmanaged devices via Conditional Access.',
  suspended_user_active: 'Revoke all sessions immediately. Audit what the user accessed.',
  auth_brute_force: 'Block source IP. Review if account was compromised. Enforce stronger password policy.',
  after_hours_logins: 'Verify with the user. Consider Conditional Access policies for off-hours.',
  risky_oauth: 'Review OAuth grant. Revoke if not approved by IT.',
  mfa_changes: 'Confirm MFA change was authorized. Re-enable immediately if unauthorized.',
  bulk_cloud_access: 'Investigate for data exfiltration. Review user activity timeline.',
}

// ── Deep-link destinations ────────────────────────────────────────────────────
// Each insight type maps to a page + query-string that pre-filters to the
// exact population the insight describes.

interface InsightDest {
  href: string        // full path including search params
  label: string       // button label shown to the user
}

const INSIGHT_DESTINATIONS: Record<string, InsightDest> = {
  // User compliance
  users_no_mfa:                 { href: '/users?mfa=disabled&status=active',             label: 'View users without MFA' },
  stale_accounts:               { href: '/users?status=active',                           label: 'View active users' },
  unmanaged_device_access:      { href: '/users?status=active',                           label: 'View active users' },
  suspended_user_active:        { href: '/activity?is_suspicious=true',                   label: 'View suspicious activity' },
  mfa_changes:                  { href: '/activity?event_type=user_account',              label: 'View account events' },

  // Endpoint compliance
  endpoints_missing_edr:        { href: '/compliance?issue=no_edr',                       label: 'View endpoints missing EDR' },
  endpoints_missing_encryption: { href: '/compliance?issue=not_encrypted',                label: 'View unencrypted endpoints' },
  endpoints_missing_dlp:        { href: '/compliance?issue=no_dlp',                       label: 'View endpoints missing DLP' },
  endpoints_missing_vpn:        { href: '/endpoints?agent=no_vpn',                        label: 'View endpoints missing VPN' },
  inactive_agents:              { href: '/endpoints?compliance=non_compliant',             label: 'View non-compliant endpoints' },
  non_compliant_endpoints:      { href: '/endpoints?compliance=non_compliant',             label: 'View non-compliant endpoints' },
  partial_compliance_endpoints: { href: '/endpoints?compliance=partial',                   label: 'View partial compliance' },

  // Access control / behavioral
  auth_brute_force:             { href: '/activity?event_type=access_eval&is_suspicious=true', label: 'View brute-force events' },
  after_hours_logins:           { href: '/activity?event_type=login',                     label: 'View login events' },
  risky_oauth:                  { href: '/activity?event_type=oauth_grant&is_suspicious=true', label: 'View risky OAuth grants' },

  // Data security
  bulk_cloud_access:            { href: '/activity?event_type=cloud_access',              label: 'View cloud access events' },
}

// ── Severity config ───────────────────────────────────────────────────────────

const SEV_CONFIG: Record<
  AIInsight['severity'],
  { accent: string; bg: string; border: string; label: string }
> = {
  critical: {
    accent: '#ef4444',
    bg: 'rgba(239,68,68,0.10)',
    border: 'rgba(239,68,68,0.20)',
    label: 'Critical',
  },
  high: {
    accent: '#f97316',
    bg: 'rgba(249,115,22,0.10)',
    border: 'rgba(249,115,22,0.20)',
    label: 'High',
  },
  warning: {
    accent: '#f59e0b',
    bg: 'rgba(245,158,11,0.10)',
    border: 'rgba(245,158,11,0.20)',
    label: 'Warning',
  },
  info: {
    accent: '#3b82f6',
    bg: 'rgba(59,130,246,0.10)',
    border: 'rgba(59,130,246,0.20)',
    label: 'Info',
  },
}

// ── Insight type labels ───────────────────────────────────────────────────────

const TYPE_LABELS: Record<string, string> = {
  users_no_mfa:                 'No MFA',
  stale_accounts:               'Stale Accounts',
  endpoints_missing_edr:        'Missing EDR',
  endpoints_missing_encryption: 'Missing Encryption',
  endpoints_missing_dlp:        'Missing DLP',
  endpoints_missing_vpn:        'Missing VPN',
  inactive_agents:              'Inactive Agents',
  non_compliant_endpoints:      'Non-Compliant',
  partial_compliance_endpoints: 'Partial Compliance',
  unmanaged_device_access:      'Unmanaged Devices',
  suspended_user_active:        'Suspended User Active',
  auth_brute_force:             'Brute Force',
  after_hours_logins:           'After-Hours Login',
  risky_oauth:                  'Risky OAuth',
  mfa_changes:                  'MFA Changed',
  bulk_cloud_access:            'Bulk Cloud Access',
  cloud_threat_incidents:       'Cloud Threat',
}

function typeLabel(t: string): string {
  return TYPE_LABELS[t] ?? t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

// ── Relative time ─────────────────────────────────────────────────────────────

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.floor(h / 24)
  return `${d}d ago`
}

// ── Affected entity chip helpers ──────────────────────────────────────────────

function entityLabel(entity: Record<string, unknown>): string {
  return (
    (entity.name as string) ||
    (entity.hostname as string) ||
    (entity.email as string) ||
    (entity.user as string) ||
    String(entity.id ?? entity.endpoint_id ?? '—')
  )
}

function AffectedChips({ items }: { items: Record<string, unknown>[] }) {
  const MAX = 5
  const visible = items.slice(0, MAX)
  const overflow = items.length - MAX

  return (
    <div className="flex flex-wrap gap-1.5 mt-2">
      {visible.map((item, i) => (
        <span
          key={i}
          className="inline-flex items-center text-[11px] font-medium px-2 py-0.5 rounded-full"
          style={{
            background: 'var(--surface-3)',
            border: '1px solid var(--border)',
            color: 'var(--text-3)',
          }}
        >
          {entityLabel(item)}
        </span>
      ))}
      {overflow > 0 && (
        <span
          className="inline-flex items-center text-[11px] px-2 py-0.5 rounded-full"
          style={{
            background: 'var(--surface-3)',
            border: '1px solid var(--border)',
            color: 'var(--text-4)',
          }}
        >
          +{overflow} more
        </span>
      )}
    </div>
  )
}

// ── Evidence renderer ─────────────────────────────────────────────────────────

function renderEvidenceValue(k: string, v: unknown): React.ReactNode {
  // Arrays of objects → render as name chips
  if (Array.isArray(v) && v.length > 0 && typeof v[0] === 'object' && v[0] !== null) {
    return <AffectedChips items={v as Record<string, unknown>[]} />
  }
  if (Array.isArray(v)) {
    if (v.length === 0) return <span style={{ color: 'var(--text-4)' }}>—</span>
    return (
      <span className="font-mono break-all" style={{ color: 'var(--text-2)' }}>
        {(v as unknown[]).join(', ')}
      </span>
    )
  }
  if (typeof v === 'boolean') {
    return v
      ? <span className="inline-flex items-center gap-1" style={{ color: '#10b981' }}><CheckCircle2 size={11} />Yes</span>
      : <span style={{ color: 'var(--text-4)' }}>No</span>
  }
  if (v === null || v === undefined) return <span style={{ color: 'var(--text-4)' }}>—</span>
  if (typeof v === 'object') {
    return (
      <span className="font-mono break-all text-[10px]" style={{ color: 'var(--text-3)' }}>
        {JSON.stringify(v)}
      </span>
    )
  }
  return <span className="font-mono break-all" style={{ color: 'var(--text-2)' }}>{String(v)}</span>
}

// ── Skeleton ──────────────────────────────────────────────────────────────────

function SkeletonCard() {
  return (
    <div
      className="rounded-xl overflow-hidden"
      style={{ border: '1px solid var(--border)', background: 'var(--surface-1)' }}
    >
      <div className="flex">
        <div className="w-1 flex-shrink-0" style={{ background: 'var(--border)' }} />
        <div className="flex-1 p-4 space-y-3">
          <div className="flex items-center gap-2">
            <div className="h-5 w-16 rounded-full animate-pulse" style={{ background: 'var(--surface-3)' }} />
            <div className="h-4 w-48 rounded animate-pulse" style={{ background: 'var(--surface-3)' }} />
          </div>
          <div className="h-3 w-full rounded animate-pulse" style={{ background: 'var(--surface-3)' }} />
          <div className="h-3 w-4/5 rounded animate-pulse" style={{ background: 'var(--surface-3)' }} />
          <div className="h-8 w-full rounded-lg animate-pulse" style={{ background: 'var(--surface-3)' }} />
        </div>
      </div>
    </div>
  )
}

// ── Toast ─────────────────────────────────────────────────────────────────────

interface ToastState {
  id: number
  message: string
  type: 'success' | 'error'
}

// ── InsightCard ───────────────────────────────────────────────────────────────

interface InsightCardProps {
  insight: AIInsight
  onDismiss: (id: string) => void
  onUndismiss: (id: string) => void
  dismissingId: string | null
  onNavigate: (href: string) => void
}

function InsightCard({ insight, onDismiss, onUndismiss, dismissingId, onNavigate }: InsightCardProps) {
  const [evidenceOpen, setEvidenceOpen] = useState(false)
  const cfg = SEV_CONFIG[insight.severity]
  const isDismissing = dismissingId === insight.id
  const hasEvidence = insight.evidence && Object.keys(insight.evidence).length > 0
  const action = RECOMMENDED_ACTIONS[insight.insight_type]
  const dest   = INSIGHT_DESTINATIONS[insight.insight_type]

  // Extract affected list from evidence (try multiple common keys)
  const evidence = insight.evidence ?? {}
  const affectedCount: number | undefined =
    typeof evidence.count === 'number' ? evidence.count : undefined
  const affectedList: Record<string, unknown>[] | undefined = (() => {
    for (const key of ['affected', 'users', 'endpoints']) {
      const v = evidence[key]
      if (Array.isArray(v) && v.length > 0) return v as Record<string, unknown>[]
    }
    return undefined
  })()

  return (
    <div
      className="rounded-xl overflow-hidden transition-[opacity] duration-200"
      style={{
        border: `1px solid ${cfg.border}`,
        background: 'var(--surface-1)',
        opacity: isDismissing ? 0.5 : 1,
      }}
    >
      <div className="flex">
        {/* Left severity bar */}
        <div className="w-1 flex-shrink-0" style={{ background: cfg.accent }} />

        {/* Body */}
        <div className="flex-1 min-w-0 p-4">
          {/* Header row */}
          <div className="flex items-start gap-2 flex-wrap">
            {/* Severity badge */}
            <span
              className="inline-flex items-center text-[11px] font-semibold px-2 py-0.5 rounded-full flex-shrink-0"
              style={{ color: cfg.accent, background: cfg.bg, border: `1px solid ${cfg.border}` }}
            >
              {cfg.label}
            </span>

            {/* Type badge */}
            <span
              className="inline-flex items-center text-[11px] font-medium px-2 py-0.5 rounded-full flex-shrink-0"
              style={{
                color: 'var(--text-3)',
                background: 'var(--surface-3)',
                border: '1px solid var(--border)',
              }}
            >
              {typeLabel(insight.insight_type)}
            </span>

            {/* NEW badge */}
            {insight.is_new && !insight.is_dismissed && (
              <span
                className="inline-flex items-center text-[10px] font-bold px-2 py-0.5 rounded-full flex-shrink-0 tracking-wide"
                style={{
                  color: '#10b981',
                  background: 'rgba(16,185,129,0.12)',
                  border: '1px solid rgba(16,185,129,0.25)',
                }}
              >
                NEW
              </span>
            )}

            {/* Dismissed badge */}
            {insight.is_dismissed && (
              <span
                className="inline-flex items-center text-[10px] font-medium px-2 py-0.5 rounded-full flex-shrink-0"
                style={{
                  color: 'var(--text-4)',
                  background: 'var(--surface-3)',
                  border: '1px solid var(--border)',
                }}
              >
                Dismissed
              </span>
            )}

            <div className="flex-1" />

            {/* Timestamp */}
            <span className="text-[11px] tabular-nums flex-shrink-0 flex items-center gap-1" style={{ color: 'var(--text-4)' }}>
              <Clock size={10} />
              {relativeTime(insight.created_at)}
            </span>

            {/* Dismiss / Undismiss */}
            {insight.is_dismissed ? (
              <button
                onClick={() => onUndismiss(insight.id)}
                disabled={isDismissing}
                title="Restore insight"
                className="flex-shrink-0 flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-lg transition-[background-color,color] duration-150 disabled:opacity-40"
                style={{ color: 'var(--text-4)', border: '1px solid var(--border)' }}
                onMouseEnter={e => {
                  e.currentTarget.style.color = 'var(--text-2)'
                  e.currentTarget.style.background = 'var(--hover-1)'
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.color = 'var(--text-4)'
                  e.currentTarget.style.background = 'transparent'
                }}
              >
                <RotateCcw size={11} />
                Restore
              </button>
            ) : (
              <button
                onClick={() => onDismiss(insight.id)}
                disabled={isDismissing}
                title="Dismiss insight"
                className="flex-shrink-0 flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-lg transition-[background-color,color,border-color] duration-150 disabled:opacity-40"
                style={{ color: 'var(--text-4)', border: '1px solid var(--border)' }}
                onMouseEnter={e => {
                  e.currentTarget.style.color = '#f87171'
                  e.currentTarget.style.background = 'rgba(239,68,68,0.08)'
                  e.currentTarget.style.borderColor = 'rgba(239,68,68,0.20)'
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.color = 'var(--text-4)'
                  e.currentTarget.style.background = 'transparent'
                  e.currentTarget.style.borderColor = 'var(--border)'
                }}
              >
                <X size={11} />
                Dismiss
              </button>
            )}
          </div>

          {/* Title */}
          <h3 className="mt-2.5 text-[15px] font-semibold leading-snug" style={{ color: 'var(--text-1)' }}>
            {insight.title}
          </h3>

          {/* Description */}
          {insight.description && (
            <p className="mt-1.5 text-[13px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
              {insight.description}
            </p>
          )}

          {/* Recommended action box + View Data button (same row) */}
          {(action || dest) && (
            <div className="mt-3 flex items-start gap-2">
              {action && (
                <div
                  className="flex-1 flex items-start gap-2 rounded-lg px-3 py-2.5"
                  style={{
                    background: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                  }}
                >
                  <Wrench size={13} className="flex-shrink-0 mt-0.5" style={{ color: 'var(--text-3)' }} />
                  <p className="text-[12px] leading-relaxed" style={{ color: 'var(--text-2)' }}>
                    {action}
                  </p>
                </div>
              )}
              {dest && (
                <button
                  onClick={() => onNavigate(dest.href)}
                  className="flex-shrink-0 flex items-center gap-1.5 text-[12px] font-medium px-3 py-2.5 rounded-lg transition-[background-color,border-color,color] duration-150 whitespace-nowrap"
                  style={{
                    background: `${cfg.bg}`,
                    border: `1px solid ${cfg.border}`,
                    color: cfg.accent,
                  }}
                  onMouseEnter={e => {
                    e.currentTarget.style.background = cfg.accent
                    e.currentTarget.style.color = '#fff'
                    e.currentTarget.style.borderColor = cfg.accent
                  }}
                  onMouseLeave={e => {
                    e.currentTarget.style.background = cfg.bg
                    e.currentTarget.style.color = cfg.accent
                    e.currentTarget.style.borderColor = cfg.border
                  }}
                  title={dest.label}
                >
                  {dest.label}
                  <ArrowRight size={12} />
                </button>
              )}
            </div>
          )}

          {/* Affected section */}
          {(affectedCount !== undefined || affectedList) && (
            <div className="mt-3">
              {affectedCount !== undefined && affectedCount > 0 && (
                <span
                  className="inline-flex items-center gap-1 text-[12px] font-medium px-2.5 py-1 rounded-full"
                  style={{
                    background: cfg.bg,
                    border: `1px solid ${cfg.border}`,
                    color: cfg.accent,
                  }}
                >
                  <AlertTriangle size={11} />
                  {affectedCount.toLocaleString()} affected
                </span>
              )}
              {affectedList && affectedList.length > 0 && (
                <AffectedChips items={affectedList} />
              )}
            </div>
          )}

          {/* Evidence expand */}
          {hasEvidence && (
            <div className="mt-3">
              <button
                onClick={() => setEvidenceOpen(x => !x)}
                className="flex items-center gap-1.5 text-[12px] transition-[color] duration-150"
                style={{ color: evidenceOpen ? 'var(--text-2)' : 'var(--text-4)' }}
                onMouseEnter={e => { e.currentTarget.style.color = 'var(--text-2)' }}
                onMouseLeave={e => { e.currentTarget.style.color = evidenceOpen ? 'var(--text-2)' : 'var(--text-4)' }}
              >
                {evidenceOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                {evidenceOpen ? 'Hide evidence' : 'Show evidence'}
                <span
                  className="text-[10px] px-1.5 py-0.5 rounded-full"
                  style={{ background: 'var(--surface-3)', color: 'var(--text-4)' }}
                >
                  {Object.keys(evidence).length} fields
                </span>
              </button>

              {evidenceOpen && (
                <div
                  className="mt-2 rounded-lg p-3 text-[11px] space-y-2"
                  style={{ background: 'var(--surface-3)', border: '1px solid var(--border)' }}
                >
                  {Object.entries(evidence).map(([k, v]) => (
                    <div key={k} className="flex gap-3 items-start">
                      <span
                        className="font-mono flex-shrink-0 capitalize"
                        style={{ color: 'var(--text-4)', minWidth: 140 }}
                      >
                        {k.replace(/_/g, ' ')}
                      </span>
                      <span className="flex-1 min-w-0">{renderEvidenceValue(k, v)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Category section ──────────────────────────────────────────────────────────

interface CategorySectionProps {
  category: typeof CATEGORIES[number]
  insights: AIInsight[]
  onDismiss: (id: string) => void
  onUndismiss: (id: string) => void
  dismissingId: string | null
  onNavigate: (href: string) => void
}

function CategorySection({ category, insights, onDismiss, onUndismiss, dismissingId, onNavigate }: CategorySectionProps) {
  const [collapsed, setCollapsed] = useState(false)
  const Icon = category.icon
  const count = insights.length

  return (
    <section>
      {/* Section header */}
      <button
        className="w-full flex items-center gap-2.5 mb-3 group"
        onClick={() => setCollapsed(x => !x)}
      >
        <div
          className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
        >
          <Icon size={14} style={{ color: 'var(--text-3)' }} />
        </div>
        <span className="text-[13px] font-semibold" style={{ color: 'var(--text-1)' }}>
          {category.label}
        </span>
        <span
          className="inline-flex items-center text-[11px] font-semibold px-2 py-0.5 rounded-full"
          style={{
            background: 'var(--surface-3)',
            border: '1px solid var(--border)',
            color: 'var(--text-3)',
          }}
        >
          {count}
        </span>
        <div className="flex-1" />
        {collapsed ? (
          <ChevronRight size={13} style={{ color: 'var(--text-4)' }} />
        ) : (
          <ChevronDown size={13} style={{ color: 'var(--text-4)' }} />
        )}
      </button>

      {!collapsed && (
        <div className="space-y-2 mb-6">
          {insights.map(insight => (
            <InsightCard
              key={insight.id}
              insight={insight}
              onDismiss={onDismiss}
              onUndismiss={onUndismiss}
              dismissingId={dismissingId}
              onNavigate={onNavigate}
            />
          ))}
        </div>
      )}
    </section>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AIInsights() {
  const queryClient = useQueryClient()
  const navigate    = useNavigate()

  const [severity, setSeverity] = useState('')
  const [showDismissed, setShowDismissed] = useState(false)
  const [page, setPage] = useState(1)
  const [toasts, setToasts] = useState<ToastState[]>([])
  const [dismissingId, setDismissingId] = useState<string | null>(null)

  const addToast = (message: string, type: 'success' | 'error') => {
    const id = Date.now()
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000)
  }

  const invalidateAll = () => {
    queryClient.invalidateQueries({ queryKey: ['ai-insights'] })
    queryClient.invalidateQueries({ queryKey: ['ai-insight-stats'] })
  }

  // ── Queries ───────────────────────────────────────────────────────────────

  const { data: statsData } = useQuery({
    queryKey: ['ai-insight-stats'],
    queryFn: fetchInsightStats,
    refetchInterval: 30000,
  })

  const { data, isLoading } = useQuery({
    queryKey: ['ai-insights', { severity, showDismissed, page }],
    queryFn: () =>
      fetchInsights({
        severity: severity || undefined,
        show_dismissed: showDismissed || undefined,
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
      }),
  })

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 1
  const insights: AIInsight[] = data?.data ?? []

  // ── Mutations ─────────────────────────────────────────────────────────────

  const dismissMutation = useMutation({
    mutationFn: dismissInsight,
    onMutate: (id) => setDismissingId(id),
    onSettled: () => setDismissingId(null),
    onSuccess: () => invalidateAll(),
    onError: () => addToast('Failed to dismiss insight', 'error'),
  })

  const undismissMutation = useMutation({
    mutationFn: undismissInsight,
    onMutate: (id) => setDismissingId(id),
    onSettled: () => setDismissingId(null),
    onSuccess: () => invalidateAll(),
    onError: () => addToast('Failed to restore insight', 'error'),
  })

  const runAnalysisMutation = useMutation({
    mutationFn: runAnalysis,
    onSuccess: (result) => {
      invalidateAll()
      addToast(
        `Analysis complete — ${result.insights_created} new insight${result.insights_created !== 1 ? 's' : ''} detected`,
        'success',
      )
    },
    onError: () => addToast('Analysis failed — check integrations', 'error'),
  })

  // ── Stats bar config ──────────────────────────────────────────────────────

  const statsChips = [
    {
      key: 'critical',
      label: 'Critical',
      count: statsData?.critical ?? 0,
      accent: '#ef4444',
      bg: 'rgba(239,68,68,0.10)',
      border: 'rgba(239,68,68,0.20)',
    },
    {
      key: 'high',
      label: 'High',
      count: statsData?.high ?? 0,
      accent: '#f97316',
      bg: 'rgba(249,115,22,0.10)',
      border: 'rgba(249,115,22,0.20)',
    },
    {
      key: 'warning',
      label: 'Warning',
      count: statsData?.warning ?? 0,
      accent: '#f59e0b',
      bg: 'rgba(245,158,11,0.10)',
      border: 'rgba(245,158,11,0.20)',
    },
    {
      key: 'total',
      label: 'Total',
      count: data?.total ?? 0,
      accent: 'var(--text-3)',
      bg: 'var(--surface-3)',
      border: 'var(--border)',
    },
  ]

  // ── Group insights by category for rendering ──────────────────────────────

  const insightsByCategory = CATEGORIES.map(cat => ({
    category: cat,
    insights: insights.filter(i => cat.types.includes(i.insight_type)),
  })).filter(({ insights: ins }) => ins.length > 0)

  // Uncategorised insights
  const categorisedIds = new Set(insightsByCategory.flatMap(({ insights: ins }) => ins.map(i => i.id)))
  const uncategorised = insights.filter(i => !categorisedIds.has(i.id))

  // ── Shared select style ───────────────────────────────────────────────────

  const selectStyle: React.CSSProperties = {
    background: 'var(--surface-2)',
    border: '1px solid var(--border-mid)',
    color: 'var(--text-2)',
    fontSize: 13,
    borderRadius: 8,
    padding: '6px 12px',
    appearance: 'none' as const,
    cursor: 'pointer',
    outline: 'none',
  }

  return (
    <div className="absolute inset-0 overflow-y-auto">

      {/* ── Toast stack ─────────────────────────────────────────────────── */}
      <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2 pointer-events-none">
        {toasts.map(toast => (
          <div
            key={toast.id}
            className="px-4 py-2.5 rounded-xl text-[13px] font-medium shadow-lg pointer-events-auto"
            style={{
              background: toast.type === 'success' ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
              border: toast.type === 'success' ? '1px solid rgba(16,185,129,0.30)' : '1px solid rgba(239,68,68,0.30)',
              color: toast.type === 'success' ? '#34d399' : '#f87171',
              backdropFilter: 'blur(12px)',
            }}
          >
            {toast.message}
          </div>
        ))}
      </div>

      {/* ── Sticky header ───────────────────────────────────────────────── */}
      <div
        className="sticky top-0 z-20 px-6 py-3 flex flex-wrap gap-3 items-center"
        style={{
          background: 'color-mix(in srgb, var(--surface-0) 92%, transparent)',
          backdropFilter: 'blur(12px)',
          borderBottom: '1px solid var(--border)',
        }}
      >
        {/* Title */}
        <div className="flex items-center gap-2">
          <Brain size={15} style={{ color: 'var(--accent)' }} />
          <span className="text-[13px] font-semibold" style={{ color: 'var(--text-1)' }}>
            Compliance Intelligence
          </span>
        </div>

        {/* Last run time */}
        {statsData && statsData.total > 0 && (
          <span className="text-[11px] flex items-center gap-1" style={{ color: 'var(--text-4)' }}>
            <RefreshCw size={10} />
            {statsData.total.toLocaleString()} active insights
          </span>
        )}

        {/* Stats bar */}
        <div className="flex items-center gap-2 ml-1">
          {statsChips.map(chip => (
            <button
              key={chip.key}
              onClick={() => {
                if (chip.key !== 'total') {
                  setSeverity(prev => prev === chip.key ? '' : chip.key)
                  setPage(1)
                }
              }}
              className="inline-flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-1 rounded-full transition-[opacity] duration-150 hover:opacity-80"
              style={{ color: chip.accent, background: chip.bg, border: `1px solid ${chip.border}` }}
            >
              {chip.count.toLocaleString()} {chip.label}
            </button>
          ))}
        </div>

        <div className="flex-1" />

        {/* Filter bar */}
        <div className="flex items-center gap-2">
          <select
            value={severity}
            onChange={e => { setSeverity(e.target.value); setPage(1) }}
            style={selectStyle}
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </select>

          <button
            onClick={() => { setShowDismissed(x => !x); setPage(1) }}
            className="flex items-center gap-1.5 text-[12px] px-3 py-1.5 rounded-lg transition-[background-color,border-color,color] duration-150"
            style={{
              background: showDismissed ? 'rgba(99,102,241,0.10)' : 'var(--surface-2)',
              border: showDismissed ? '1px solid rgba(99,102,241,0.30)' : '1px solid var(--border-mid)',
              color: showDismissed ? '#818cf8' : 'var(--text-3)',
            }}
          >
            <RotateCcw size={11} />
            {showDismissed ? 'Showing dismissed' : 'Dismissed'}
          </button>
        </div>

        {/* Run Analysis */}
        <button
          onClick={() => runAnalysisMutation.mutate()}
          disabled={runAnalysisMutation.isPending}
          className="flex items-center gap-2 text-[12px] font-medium px-3.5 py-2 rounded-lg transition-[background-color,opacity] duration-150 disabled:opacity-60"
          style={{ background: 'var(--accent)', color: '#fff' }}
          onMouseEnter={e => { if (!runAnalysisMutation.isPending) e.currentTarget.style.opacity = '0.85' }}
          onMouseLeave={e => { e.currentTarget.style.opacity = '1' }}
        >
          {runAnalysisMutation.isPending ? (
            <>
              <Loader2 size={12} className="animate-spin" />
              Analyzing…
            </>
          ) : (
            <>
              <Play size={12} />
              Run Analysis
            </>
          )}
        </button>
      </div>

      {/* ── Content ─────────────────────────────────────────────────────── */}
      <div
        className="px-6 py-5"
        style={{ background: 'var(--surface-0)', minHeight: 'calc(100% - 57px)' }}
      >
        {isLoading ? (
          <div className="space-y-3">
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
          </div>
        ) : insights.length === 0 ? (
          /* ── Empty state ────────────────────────────────────────────── */
          <div className="flex flex-col items-center justify-center py-24 gap-4">
            <div
              className="w-14 h-14 rounded-2xl flex items-center justify-center"
              style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
            >
              <Brain size={24} style={{ color: 'var(--text-4)' }} />
            </div>
            <div className="flex flex-col items-center gap-1">
              <span className="text-[15px] font-semibold" style={{ color: 'var(--text-2)' }}>
                No compliance insights
              </span>
              <span className="text-[13px]" style={{ color: 'var(--text-4)' }}>
                Run Analysis to scan your environment for compliance gaps and anomalies
              </span>
            </div>
            <button
              onClick={() => runAnalysisMutation.mutate()}
              disabled={runAnalysisMutation.isPending}
              className="flex items-center gap-2 text-[13px] font-medium px-4 py-2.5 rounded-lg mt-2 transition-[opacity] duration-150 disabled:opacity-60"
              style={{ background: 'var(--accent)', color: '#fff' }}
            >
              {runAnalysisMutation.isPending ? (
                <>
                  <Loader2 size={13} className="animate-spin" />
                  Analyzing…
                </>
              ) : (
                <>
                  <Sparkles size={13} />
                  Run Analysis
                </>
              )}
            </button>
          </div>
        ) : (
          /* ── Category sections ──────────────────────────────────────── */
          <div>
            {insightsByCategory.map(({ category, insights: catInsights }) => (
              <CategorySection
                key={category.id}
                category={category}
                insights={catInsights}
                onDismiss={id => dismissMutation.mutate(id)}
                onUndismiss={id => undismissMutation.mutate(id)}
                dismissingId={dismissingId}
                onNavigate={navigate}
              />
            ))}

            {/* Uncategorised fallback */}
            {uncategorised.length > 0 && (
              <section className="mb-6">
                <div className="flex items-center gap-2.5 mb-3">
                  <div
                    className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
                    style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
                  >
                    <AlertTriangle size={14} style={{ color: 'var(--text-3)' }} />
                  </div>
                  <span className="text-[13px] font-semibold" style={{ color: 'var(--text-1)' }}>
                    Other
                  </span>
                  <span
                    className="inline-flex items-center text-[11px] font-semibold px-2 py-0.5 rounded-full"
                    style={{ background: 'var(--surface-3)', border: '1px solid var(--border)', color: 'var(--text-3)' }}
                  >
                    {uncategorised.length}
                  </span>
                </div>
                <div className="space-y-2">
                  {uncategorised.map(insight => (
                    <InsightCard
                      key={insight.id}
                      insight={insight}
                      onDismiss={id => dismissMutation.mutate(id)}
                      onUndismiss={id => undismissMutation.mutate(id)}
                      dismissingId={dismissingId}
                      onNavigate={navigate}
                    />
                  ))}
                </div>
              </section>
            )}

            {/* Pagination */}
            {totalPages > 1 && (
              <div
                className="flex items-center justify-center gap-3 pt-4 pb-2"
                style={{ borderTop: '1px solid var(--border)' }}
              >
                <button
                  disabled={page <= 1}
                  onClick={() => setPage(p => p - 1)}
                  className="inline-flex items-center gap-1.5 text-[12px] px-3 py-1.5 rounded-lg disabled:opacity-40 transition-[background-color] duration-150"
                  style={{ background: 'var(--surface-2)', border: '1px solid var(--border-mid)', color: 'var(--text-2)' }}
                  onMouseEnter={e => { if (page > 1) e.currentTarget.style.background = 'var(--hover-1)' }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'var(--surface-2)' }}
                >
                  &larr; Prev
                </button>
                <span className="text-[12px] tabular-nums" style={{ color: 'var(--text-4)' }}>
                  {page} / {totalPages}
                </span>
                <button
                  disabled={page >= totalPages}
                  onClick={() => setPage(p => p + 1)}
                  className="inline-flex items-center gap-1.5 text-[12px] px-3 py-1.5 rounded-lg disabled:opacity-40 transition-[background-color] duration-150"
                  style={{ background: 'var(--surface-2)', border: '1px solid var(--border-mid)', color: 'var(--text-2)' }}
                  onMouseEnter={e => { if (page < totalPages) e.currentTarget.style.background = 'var(--hover-1)' }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'var(--surface-2)' }}
                >
                  Next &rarr;
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
