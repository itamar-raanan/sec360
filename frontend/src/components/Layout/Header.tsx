import React, { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Activity, AlertTriangle, ArrowRight, Bell, CheckCircle2, Clock3, Plug, Search } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { fetchIntegrations } from '../../api/integrations'
import { fetchInsightStats } from '../../api/ai'
import { useAuthStore } from '../../store/auth'

const PAGE_TITLES: Record<string, { title: string; desc: string }> = {
  '/dashboard':    { title: 'Overview',      desc: 'Live security posture' },
  '/endpoints':    { title: 'Endpoints',     desc: 'Managed devices and compliance' },
  '/users':        { title: 'Users',         desc: 'Identity risk and activity' },
  '/compliance':   { title: 'Compliance',    desc: 'Control coverage and exceptions' },
  '/activity':     { title: 'Activity',      desc: 'Security event timeline' },
  '/investigation': { title: 'Investigation', desc: 'Cross-source entity analysis' },
  '/ai-chat':      { title: 'AI Assistant',  desc: 'Query your security posture' },
  '/ai-insights':  { title: 'AI Insights',   desc: 'Prioritized anomalous conditions' },
  '/dlp-user-policy-search': { title: 'DLP User Policy Search', desc: 'User exclusions across Symantec DLP policies' },
  '/reports':      { title: 'Reports',       desc: 'Generated reports and exports' },
  '/integrations': { title: 'Integrations',  desc: 'Connected platforms and APIs' },
  '/settings':     { title: 'Settings',      desc: 'Platform configuration' },
}

interface HeaderProps {
  onOpenCmd?: () => void
}

export default function Header({ onOpenCmd }: HeaderProps) {
  const location = useLocation()
  const navigate = useNavigate()
  const { user } = useAuthStore()
  const [statusOpen, setStatusOpen] = useState(false)
  const statusRef = useRef<HTMLDivElement>(null)
  const path = '/' + location.pathname.split('/')[1]
  const meta = PAGE_TITLES[path] || { title: 'SEC360', desc: '' }
  const canReadInsights = user?.role === 'admin' || user?.role === 'analyst'

  const { data: integrations = [] } = useQuery({
    queryKey: ['integrations'],
    queryFn: fetchIntegrations,
    refetchInterval: 60_000,
  })
  const { data: insightStats } = useQuery({
    queryKey: ['ai-insight-stats'],
    queryFn: fetchInsightStats,
    enabled: canReadInsights,
    refetchInterval: 30_000,
  })

  useEffect(() => {
    const close = (event: PointerEvent) => {
      if (statusRef.current && !statusRef.current.contains(event.target as Node)) setStatusOpen(false)
    }
    document.addEventListener('pointerdown', close)
    return () => document.removeEventListener('pointerdown', close)
  }, [])

  const activeSources = integrations.filter(item => item.is_enabled)
  const errorSources = activeSources.filter(item => item.status === 'error')
  const healthySources = activeSources.filter(item => item.status === 'connected')
  const urgentInsights = (insightStats?.critical ?? 0) + (insightStats?.high ?? 0)
  const latestSync = activeSources
    .map(item => item.last_sync ? new Date(item.last_sync) : null)
    .filter((date): date is Date => Boolean(date))
    .sort((a, b) => b.getTime() - a.getTime())[0]
  const healthState = !activeSources.length
    ? 'warning'
    : errorSources.length
      ? 'error'
      : healthySources.length < activeSources.length
        ? 'warning'
        : 'healthy'
  const healthLabel = !activeSources.length
    ? 'No active sources'
    : errorSources.length
      ? `${errorSources.length} source issue${errorSources.length === 1 ? '' : 's'}`
      : healthySources.length < activeSources.length
        ? 'Sources need review'
        : 'Systems healthy'

  return (
    <header
      className="h-14 px-4 sm:px-6 flex items-center justify-between sticky top-0 z-10"
      style={{
        background: 'color-mix(in srgb, var(--surface-1) 88%, transparent)',
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        borderBottom: '1px solid var(--border)',
      }}
    >
      <div className="flex min-w-0 items-center gap-3">
        <h1 className="truncate text-[14px] font-semibold tracking-[-0.02em]" style={{ color: 'var(--text-1)' }}>{meta.title}</h1>
        {meta.desc && (
          <>
            <span className="hidden sm:inline" style={{ color: 'var(--border-mid)', fontSize: 13 }}>/</span>
            <span className="hidden truncate text-[11px] sm:inline" style={{ color: 'var(--text-4)' }}>{meta.desc}</span>
          </>
        )}
      </div>

      <div className="flex items-center gap-1.5">
        <button
          onClick={onOpenCmd}
          className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-[8px] text-[11px] pressable hover:bg-white/[0.025]"
          style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)', color: 'var(--text-4)' }}
          title="Open command palette"
        >
          <Search size={12} />
          <span>Search or run a command</span>
          <kbd className="ml-2 rounded px-1 py-0.5 font-mono text-[9px]" style={{ background: 'var(--surface-3)', border: '1px solid var(--border)' }}>⌘K</kbd>
        </button>

        <div className="relative" ref={statusRef}>
          <button
            onClick={() => setStatusOpen(open => !open)}
            className="relative flex items-center gap-2 rounded-[8px] px-2.5 py-1.5 text-[11px] hover:bg-white/[0.04]"
            style={{ color: 'var(--text-3)', background: statusOpen ? 'var(--hover-1)' : 'transparent' }}
            title="Open operational status"
            aria-expanded={statusOpen}
          >
            <span className="status-pulse" data-status={healthState} />
            <span className="hidden lg:inline">{healthLabel}</span>
            <Bell size={14} strokeWidth={1.8} />
            {urgentInsights > 0 && <span className="absolute -right-0.5 -top-0.5 min-w-[15px] rounded-full bg-red-500 px-1 text-center font-mono text-[8px] leading-[15px] text-white">{urgentInsights > 99 ? '99+' : urgentInsights}</span>}
          </button>

          {statusOpen && (
            <div className="ui-float-surface absolute right-0 top-[calc(100%+10px)] w-[min(360px,calc(100vw-24px))] overflow-hidden fade-in">
              <div className="flex items-start justify-between border-b px-4 py-3.5" style={{ borderColor: 'var(--border)' }}>
                <div>
                  <p className="ui-eyebrow">Operational status</p>
                  <p className="mt-1.5 text-[13px] font-semibold" style={{ color: 'var(--text-1)' }}>{healthState === 'healthy' ? 'Collection plane healthy' : 'Attention required'}</p>
                </div>
                {healthState === 'healthy' ? <CheckCircle2 size={15} className="text-emerald-400" /> : <AlertTriangle size={15} className="text-amber-400" />}
              </div>

              <button onClick={() => { setStatusOpen(false); navigate('/integrations') }} className="ui-data-row flex w-full items-center gap-3 px-4 py-3 text-left">
                <span className="flex h-8 w-8 items-center justify-center rounded-[8px]" style={{ background: 'var(--surface-3)', color: 'var(--text-3)' }}><Plug size={14} /></span>
                <span className="min-w-0 flex-1">
                  <span className="block text-[12px] font-medium" style={{ color: 'var(--text-2)' }}>Data sources</span>
                  <span className="block text-[10px]" style={{ color: 'var(--text-4)' }}>{healthySources.length} healthy · {errorSources.length} degraded · {activeSources.length} enabled</span>
                </span>
                <ArrowRight size={13} style={{ color: 'var(--text-4)' }} />
              </button>

              <div className="flex items-center gap-3 border-y px-4 py-3" style={{ borderColor: 'var(--border)' }}>
                <span className="flex h-8 w-8 items-center justify-center rounded-[8px]" style={{ background: 'var(--surface-3)', color: 'var(--text-3)' }}><Clock3 size={14} /></span>
                <span>
                  <span className="block text-[12px] font-medium" style={{ color: 'var(--text-2)' }}>Latest source observation</span>
                  <span className="block text-[10px]" style={{ color: 'var(--text-4)' }}>{latestSync ? formatDistanceToNow(latestSync, { addSuffix: true }) : 'No completed synchronization'}</span>
                </span>
              </div>

              {canReadInsights && (
                <button onClick={() => { setStatusOpen(false); navigate('/ai-insights') }} className="ui-data-row flex w-full items-center gap-3 px-4 py-3 text-left">
                  <span className="flex h-8 w-8 items-center justify-center rounded-[8px]" style={{ background: urgentInsights ? 'rgba(227,84,84,0.09)' : 'var(--surface-3)', color: urgentInsights ? '#e35454' : 'var(--text-3)' }}><Activity size={14} /></span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-[12px] font-medium" style={{ color: 'var(--text-2)' }}>Priority insights</span>
                    <span className="block text-[10px]" style={{ color: 'var(--text-4)' }}>{urgentInsights} high or critical · {insightStats?.new_count ?? 0} unread</span>
                  </span>
                  <ArrowRight size={13} style={{ color: 'var(--text-4)' }} />
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
