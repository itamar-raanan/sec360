import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { format } from 'date-fns'
import {
  Activity as ActivityIcon,
  LogIn,
  Globe,
  Wifi,
  MonitorSmartphone,
  AlertTriangle,
  FileText,
  LogOut,
  ChevronDown,
  Shield,
  Key,
  User,
  ShieldCheck,
  Fingerprint,
  Cloud,
  Sparkles,
  Monitor,
} from 'lucide-react'
import { fetchActivity } from '../api/activity'
import { usePanelStore } from '../store/panels'
import { explainEvent } from '../api/ai'
import { SkeletonEventRows } from '../components/shared/Skeleton'
import type { ActivityEvent, EventType } from '../types'

// Fetch more per page — events collapse heavily, so 200 raw → ~20 visible rows
const PAGE_SIZE = 200

const EVENT_CONFIG: Record<EventType, { icon: React.ElementType; label: string; accent: string; bg: string }> = {
  login:        { icon: LogIn,        label: 'Login',        accent: '#10b981', bg: 'rgba(16,185,129,0.10)' },
  logout:       { icon: LogOut,       label: 'Logout',       accent: '#71717a', bg: 'rgba(113,113,122,0.10)' },
  app_usage:    { icon: MonitorSmartphone, label: 'App Usage', accent: '#06b6d4', bg: 'rgba(6,182,212,0.10)' },
  network:      { icon: Globe,        label: 'Network',      accent: '#8b5cf6', bg: 'rgba(139,92,246,0.10)' },
  vpn:          { icon: Wifi,         label: 'VPN',          accent: '#10b981', bg: 'rgba(16,185,129,0.10)' },
  file_access:  { icon: FileText,     label: 'File Access',  accent: '#f59e0b', bg: 'rgba(245,158,11,0.10)' },
  oauth_grant:  { icon: Key,          label: 'OAuth',        accent: '#f97316', bg: 'rgba(249,115,22,0.10)' },
  saml:         { icon: Fingerprint,  label: 'SAML',         accent: '#6366f1', bg: 'rgba(99,102,241,0.10)' },
  user_account: { icon: User,         label: 'Account',      accent: '#ec4899', bg: 'rgba(236,72,153,0.10)' },
  access_eval:  { icon: ShieldCheck,  label: 'Access Eval',  accent: '#14b8a6', bg: 'rgba(20,184,166,0.10)' },
  cloud_access: { icon: Cloud,        label: 'Cloud Access', accent: '#0ea5e9', bg: 'rgba(14,165,233,0.10)' },
}

// ── Grouping ─────────────────────────────────────────────────────────────────

interface EventGroup {
  key: string
  representative: ActivityEvent
  count: number
  firstTime: Date
  lastTime: Date
  allEvents: ActivityEvent[]
}

function groupKey(e: ActivityEvent): string {
  const d = e.details as any
  return [
    e.user?.id ?? (d?.actor ?? ''),
    e.event_type,
    d?.event_name ?? '',
    d?.app_name ?? d?.application_name ?? '',
    String(d?.success ?? true),
    // Keep suspicious events in their own merge bucket so they're visually
    // distinct from normal events, but still collapse among themselves
    String(e.is_suspicious),
  ].join('\x00')
}

// ── EventRow (single event) ───────────────────────────────────────────────────

function EventRow({ event, indent = false }: { event: ActivityEvent; indent?: boolean }) {
  const [expanded, setExpanded] = useState(false)
  const [explain, setExplain] = useState<{ loading: boolean; text: string | null }>({ loading: false, text: null })
  const { openPanel } = usePanelStore()
  const cfg = EVENT_CONFIG[event.event_type] ?? { icon: ActivityIcon, label: event.event_type, accent: '#71717a', bg: 'rgba(113,113,122,0.10)' }
  const Icon = cfg.icon
  const description = (event.details as any)?.description as string | undefined
  const hasExpandable = event.details && Object.keys(event.details).filter(k => !['app','source','description','event_name'].includes(k)).length > 0

  const handleExplain = async (e: React.MouseEvent) => {
    e.stopPropagation()
    if (explain.loading || explain.text) return
    setExplain({ loading: true, text: null })
    try {
      const result = await explainEvent(event.id)
      setExplain({ loading: false, text: result.explanation })
    } catch {
      setExplain({ loading: false, text: 'Unable to generate explanation for this event.' })
    }
  }

  return (
    <div style={{ borderBottom: '1px solid var(--border)' }}>
      <div
        className="flex items-start gap-3 py-3 transition-[background-color] duration-100"
        style={{
          paddingLeft: indent ? 56 : 20,
          paddingRight: 20,
          background: event.is_suspicious ? 'rgba(239,68,68,0.04)' : 'transparent',
          cursor: hasExpandable ? 'pointer' : 'default',
        }}
        onMouseEnter={e => !event.is_suspicious && (e.currentTarget.style.background = 'var(--hover-1)')}
        onMouseLeave={e => !event.is_suspicious && (e.currentTarget.style.background = 'transparent')}
        onClick={() => hasExpandable && setExpanded(x => !x)}
      >
        <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
          style={{ background: event.is_suspicious ? 'rgba(239,68,68,0.12)' : cfg.bg }}>
          <Icon size={14} style={{ color: event.is_suspicious ? '#f87171' : cfg.accent }} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-semibold px-1.5 py-0.5 rounded-md"
              style={{ color: cfg.accent, background: cfg.bg }}>
              {cfg.label}
            </span>
            {(event.details as any)?.success === false && (
              <span className="text-[11px] font-semibold px-1.5 py-0.5 rounded-md"
                style={{ color: '#f87171', background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.2)' }}>
                Failed
              </span>
            )}
            <span className="text-[13px] font-medium truncate" style={{ color: 'var(--text-1)' }}>
              {event.user?.full_name || (event.details as any)?.user_email || (event.details as any)?.actor || 'Unknown user'}
            </span>
            {event.is_suspicious && (
              <span className="inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded-md"
                style={{ color: '#f87171', background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.2)' }}>
                <AlertTriangle size={10} />
                Suspicious
              </span>
            )}
          </div>
          {description && (
            <div className="text-[13px] mt-0.5" style={{ color: 'var(--text-2)' }}>{description}</div>
          )}
          <div className="flex items-center gap-3 mt-1 flex-wrap">
            {event.user?.email && (
              <span className="text-[11px] font-mono" style={{ color: 'var(--text-4)' }}>{event.user.email}</span>
            )}
            {event.ip_address && (
              <span className="inline-flex items-center gap-1 text-[11px] font-mono" style={{ color: 'var(--text-4)' }}>
                <Globe size={10} style={{ flexShrink: 0 }} />
                {event.ip_address}
              </span>
            )}
            {event.device_id && (
              <button
                onClick={e => { e.stopPropagation(); openPanel('endpoint', event.device_id!, 'Endpoint') }}
                className="inline-flex items-center gap-1 text-[11px] font-mono transition-colors"
                style={{ color: 'var(--text-4)' }}
                onMouseEnter={ev => (ev.currentTarget.style.color = '#34d399')}
                onMouseLeave={ev => (ev.currentTarget.style.color = 'var(--text-4)')}
                title="Open endpoint"
              >
                <Monitor size={10} style={{ flexShrink: 0 }} />
                device
              </button>
            )}
            {((event.details as any)?.city || event.country) && (
              <span className="text-[11px]" style={{ color: 'var(--text-4)' }}>
                {[(event.details as any)?.city, event.country].filter(Boolean).join(', ')}
              </span>
            )}
            {((event.details as any)?.app_name || (event.details as any)?.application_name) && (
              <span className="text-[11px]" style={{ color: 'var(--text-3)' }}>
                {(event.details as any).app_name || (event.details as any).application_name}
              </span>
            )}
          </div>
        </div>
        <div className="flex-shrink-0 flex flex-col items-end gap-1.5 pt-0.5">
          <span className="text-[11px] tabular-nums whitespace-nowrap" style={{ color: 'var(--text-4)' }}>
            {format(new Date(event.timestamp), 'HH:mm')}
          </span>
          <button onClick={handleExplain} disabled={explain.loading} title="AI explain"
            className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-md transition-[background-color,color,border-color] duration-150 disabled:opacity-50"
            style={{ color: explain.text ? '#a78bfa' : 'var(--text-4)', background: explain.text ? 'rgba(167,139,250,0.08)' : 'transparent', border: explain.text ? '1px solid rgba(167,139,250,0.20)' : '1px solid transparent' }}
            onMouseEnter={e => { if (!explain.text) { e.currentTarget.style.color = '#a78bfa'; e.currentTarget.style.background = 'rgba(167,139,250,0.08)'; e.currentTarget.style.borderColor = 'rgba(167,139,250,0.20)' } }}
            onMouseLeave={e => { if (!explain.text) { e.currentTarget.style.color = 'var(--text-4)'; e.currentTarget.style.background = 'transparent'; e.currentTarget.style.borderColor = 'transparent' } }}>
            {explain.loading ? (
              <svg className="animate-spin" width={10} height={10} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5}><path d="M21 12a9 9 0 1 1-6.219-8.56" /></svg>
            ) : <Sparkles size={10} />}
            Explain
          </button>
          {hasExpandable && <ChevronDown size={12} style={{ color: 'var(--text-4)', transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 150ms' }} />}
        </div>
      </div>

      {explain.text && (
        <div className="pb-3 pt-0 ml-11" style={{ paddingLeft: indent ? 56 : undefined }}>
          <div className="rounded-lg p-3 text-[12px] mx-5" style={{ background: 'rgba(167,139,250,0.06)', border: '1px solid rgba(167,139,250,0.18)' }}>
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-1.5">
                <Sparkles size={11} style={{ color: '#a78bfa' }} />
                <span className="text-[11px] font-semibold" style={{ color: '#a78bfa' }}>AI Analysis</span>
              </div>
              <button onClick={e => { e.stopPropagation(); setExplain({ loading: false, text: null }) }}
                className="text-[10px]" style={{ color: 'var(--text-4)' }}>✕</button>
            </div>
            <p className="leading-relaxed" style={{ color: 'var(--text-2)' }}>{explain.text}</p>
          </div>
        </div>
      )}

      {expanded && hasExpandable && (
        <div className="pb-3 pt-0 ml-11">
          <div className="rounded-lg p-3 text-[11px] space-y-1.5 mx-5"
            style={{ background: 'var(--surface-3)', border: '1px solid var(--border)' }}>
            {Object.entries(event.details ?? {})
              .filter(([k]) => !['app', 'source', 'description', 'event_name', 'message'].includes(k))
              .map(([k, v]) => {
                const isArray = Array.isArray(v)
                const isRisky = k === 'risky_scopes'
                return (
                  <div key={k} className={isArray ? 'flex flex-col gap-0.5' : 'flex gap-3 items-start'}>
                    <span className="font-mono shrink-0 capitalize" style={{ color: 'var(--text-4)', minWidth: 120 }}>
                      {k.replace(/_/g, ' ')}
                    </span>
                    {isArray ? (
                      <div className="flex flex-wrap gap-1 mt-0.5 ml-[120px]">
                        {(v as string[]).map((item, i) => (
                          <span key={i} className="px-1.5 py-0.5 rounded text-[10px] font-mono"
                            style={{ background: isRisky ? 'rgba(239,68,68,0.12)' : 'var(--surface-2)', color: isRisky ? '#f87171' : 'var(--text-2)', border: `1px solid ${isRisky ? 'rgba(239,68,68,0.2)' : 'var(--border)'}` }}>
                            {item}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="font-mono break-all" style={{ color: 'var(--text-2)' }}>{String(v)}</span>
                    )}
                  </div>
                )
              })}
          </div>
        </div>
      )}
    </div>
  )
}

// ── GroupedEventRow ───────────────────────────────────────────────────────────

function GroupedEventRow({ group }: { group: EventGroup }) {
  const [expanded, setExpanded] = useState(false)

  if (group.count === 1) return <EventRow event={group.representative} />

  const e = group.representative
  const cfg = EVENT_CONFIG[e.event_type] ?? { icon: ActivityIcon, label: e.event_type, accent: '#71717a', bg: 'rgba(113,113,122,0.10)' }
  const Icon = cfg.icon
  const d = e.details as any
  const displayName = e.user?.full_name || d?.user_email || d?.actor || 'Unknown user'
  const sameTime = group.firstTime.getTime() === group.lastTime.getTime()
  const timeRange = sameTime
    ? format(group.lastTime, 'HH:mm')
    : `${format(group.firstTime, 'HH:mm')} – ${format(group.lastTime, 'HH:mm')}`

  return (
    <div style={{ borderBottom: '1px solid var(--border)' }}>
      {/* Merged row */}
      <div
        className="flex items-center gap-3 px-5 py-3 cursor-pointer transition-[background-color] duration-100"
        onClick={() => setExpanded(x => !x)}
        style={{ background: e.is_suspicious ? 'rgba(239,68,68,0.04)' : 'transparent' }}
        onMouseEnter={ev => (ev.currentTarget.style.background = e.is_suspicious ? 'rgba(239,68,68,0.08)' : 'var(--hover-1)')}
        onMouseLeave={ev => (ev.currentTarget.style.background = e.is_suspicious ? 'rgba(239,68,68,0.04)' : 'transparent')}
      >
        {/* Icon */}
        <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: cfg.bg }}>
          <Icon size={14} style={{ color: cfg.accent }} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0 flex items-center gap-2 flex-wrap">
          <span className="text-[11px] font-semibold px-1.5 py-0.5 rounded-md"
            style={{ color: cfg.accent, background: cfg.bg }}>
            {cfg.label}
          </span>
          {d?.success === false && (
            <span className="text-[11px] font-semibold px-1.5 py-0.5 rounded-md"
              style={{ color: '#f87171', background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.2)' }}>
              Failed
            </span>
          )}
          <span className="text-[13px] font-medium truncate" style={{ color: 'var(--text-1)' }}>
            {displayName}
          </span>
          {(d?.app_name || d?.application_name) && (
            <span className="text-[12px]" style={{ color: 'var(--text-3)' }}>→ {d.app_name || d.application_name}</span>
          )}
          {e.is_suspicious && (
            <span className="inline-flex items-center gap-1 text-[11px] font-medium px-1.5 py-0.5 rounded-md"
              style={{ color: '#f87171', background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.2)' }}>
              <AlertTriangle size={10} />
              Suspicious
            </span>
          )}
          {/* Count badge */}
          <span className="inline-flex items-center text-[11px] font-semibold px-2 py-0.5 rounded-full tabular-nums"
            style={{ background: 'var(--surface-3)', color: 'var(--text-3)', border: '1px solid var(--border-mid)' }}>
            ×{group.count}
          </span>
        </div>

        {/* Right: time range + expand */}
        <div className="flex-shrink-0 flex items-center gap-2">
          <span className="text-[11px] tabular-nums whitespace-nowrap" style={{ color: 'var(--text-4)' }}>
            {timeRange}
          </span>
          <ChevronDown size={12} style={{
            color: 'var(--text-4)',
            transform: expanded ? 'rotate(180deg)' : 'none',
            transition: 'transform 150ms',
          }} />
        </div>
      </div>

      {/* Expanded individual events */}
      {expanded && (
        <div style={{ background: 'var(--surface-0)', borderTop: '1px solid var(--border)' }}>
          {group.allEvents.map(ev => (
            <EventRow key={ev.id} event={ev} indent />
          ))}
        </div>
      )}
    </div>
  )
}

// ── DateDivider ───────────────────────────────────────────────────────────────

function DateDivider({ date, count }: { date: string; count: number }) {
  return (
    <div className="flex items-center gap-3 px-5 py-2 sticky top-0 z-10"
      style={{ background: 'color-mix(in srgb, var(--surface-1) 92%, transparent)', backdropFilter: 'blur(8px)', borderBottom: '1px solid var(--border)' }}>
      <Shield size={11} style={{ color: 'var(--text-4)' }} />
      <span className="text-[10px] font-semibold uppercase tracking-widest" style={{ color: 'var(--text-4)' }}>
        {date}
      </span>
      <span className="text-[10px] tabular-nums ml-auto" style={{ color: 'var(--text-4)' }}>
        {count} {count === 1 ? 'event' : 'events'}
      </span>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function Activity() {
  const [searchParams] = useSearchParams()
  const [eventType, setEventType] = useState(() => searchParams.get('event_type') ?? 'login,saml,oauth_grant')
  const [source, setSource] = useState(() => searchParams.get('source') ?? '')
  const [isSuspicious, setIsSuspicious] = useState(() => searchParams.get('is_suspicious') ?? '')
  const [page, setPage] = useState(1)

  const { data, isLoading } = useQuery({
    queryKey: ['activity', { eventType, source, isSuspicious, page }],
    queryFn: () => fetchActivity({
      event_type: eventType || undefined,
      source: source || undefined,
      is_suspicious: isSuspicious === 'true' ? true : isSuspicious === 'false' ? false : undefined,
      limit: PAGE_SIZE,
      offset: (page - 1) * PAGE_SIZE,
    }),
  })

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 1

  // Group by date, then merge events with the same signature within each date
  const grouped = (data?.data ?? []).reduce<{ date: string; groups: EventGroup[] }[]>((acc, event) => {
    const date = format(new Date(event.timestamp), 'EEEE, MMMM d')
    const k = groupKey(event)
    const ts = new Date(event.timestamp)
    const last = acc[acc.length - 1]
    if (last?.date === date) {
      const existing = last.groups.find(g => g.key === k)
      if (existing) {
        existing.count++
        existing.allEvents.push(event)
        if (ts < existing.firstTime) existing.firstTime = ts
        if (ts > existing.lastTime) existing.lastTime = ts
      } else {
        last.groups.push({ key: k, representative: event, count: 1, firstTime: ts, lastTime: ts, allEvents: [event] })
      }
      return acc
    }
    return [...acc, { date, groups: [{ key: k, representative: event, count: 1, firstTime: ts, lastTime: ts, allEvents: [event] }] }]
  }, [])

  const selectClass = "text-[13px] rounded-lg px-3 py-2 focus:outline-none transition-[border-color] duration-150 appearance-none cursor-pointer"
  const selectStyle = { background: 'var(--surface-2)', border: '1px solid var(--border-mid)', color: 'var(--text-2)' }

  const totalVisible = grouped.reduce((s, d) => s + d.groups.length, 0)

  return (
    <div className="absolute inset-0 overflow-y-auto">
      {/* Filter bar */}
      <div className="sticky top-0 z-20 px-6 py-3 flex flex-wrap gap-3 items-center"
        style={{ background: 'color-mix(in srgb, var(--surface-0) 92%, transparent)', backdropFilter: 'blur(12px)', borderBottom: '1px solid var(--border)' }}>
        <div className="flex items-center gap-2">
          <LogIn size={14} style={{ color: 'var(--accent)' }} />
          <span className="text-[13px] font-semibold" style={{ color: 'var(--text-1)' }}>
            {eventType === 'cloud_access' ? 'Cloud Access' : 'Login Activity'}
          </span>
        </div>
        <div className="flex items-center gap-2 ml-4 flex-wrap">
          <select value={eventType} onChange={e => { setEventType(e.target.value); setPage(1) }}
            className={selectClass} style={selectStyle}>
            <optgroup label="Logins">
              <option value="login,saml,oauth_grant">All logins</option>
              <option value="login">Direct login</option>
              <option value="saml">SSO / SAML</option>
              <option value="oauth_grant">Sign in with Google</option>
            </optgroup>
            <optgroup label="Cloud Access">
              <option value="cloud_access">All cloud access</option>
            </optgroup>
          </select>
          <select value={source} onChange={e => { setSource(e.target.value); setPage(1) }}
            className={selectClass} style={selectStyle}>
            <option value="">All sources</option>
            <option value="google_workspace">Google</option>
            <option value="jumpcloud">JumpCloud</option>
            <option value="cloudsoc">CloudSOC</option>
          </select>
          <select value={isSuspicious} onChange={e => { setIsSuspicious(e.target.value); setPage(1) }}
            className={selectClass} style={selectStyle}>
            <option value="">All activity</option>
            <option value="true">Suspicious only</option>
            <option value="false">Normal only</option>
          </select>
        </div>
        {data && (
          <span className="ml-auto text-[11px] tabular-nums" style={{ color: 'var(--text-4)' }}>
            {totalVisible} entries
            {totalVisible < data.total && (
              <span style={{ color: 'var(--text-4)' }}> ({data.total.toLocaleString()} raw)</span>
            )}
          </span>
        )}
      </div>

      {/* Feed */}
      <div style={{ background: 'var(--surface-1)' }}>
        {isLoading ? (
          <div className="p-6"><SkeletonEventRows count={10} /></div>
        ) : grouped.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 gap-3">
            <ActivityIcon size={32} style={{ color: 'var(--text-4)' }} />
            <span className="text-sm" style={{ color: 'var(--text-4)' }}>No activity events found</span>
          </div>
        ) : (
          grouped.map(({ date, groups }) => (
            <div key={date}>
              <DateDivider date={date} count={groups.length} />
              {groups.map(g => <GroupedEventRow key={g.key} group={g} />)}
            </div>
          ))
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 py-4"
          style={{ borderTop: '1px solid var(--border)' }}>
          <button disabled={page <= 1} onClick={() => setPage(p => p - 1)}
            className="text-[12px] px-3 py-1.5 rounded-lg disabled:opacity-40"
            style={{ background: 'var(--surface-2)', border: '1px solid var(--border-mid)', color: 'var(--text-2)' }}>
            ← Prev
          </button>
          <span className="text-[12px]" style={{ color: 'var(--text-4)' }}>
            {page} / {totalPages}
          </span>
          <button disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}
            className="text-[12px] px-3 py-1.5 rounded-lg disabled:opacity-40"
            style={{ background: 'var(--surface-2)', border: '1px solid var(--border-mid)', color: 'var(--text-2)' }}>
            Next →
          </button>
        </div>
      )}
    </div>
  )
}
