import React, { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Search, LayoutDashboard, Monitor, Users, CheckCircle,
  Activity, FileText, Plug, Settings, X, ArrowRight,
  Lock, User,
} from 'lucide-react'
import apiClient from '../api/client'
import { usePanelStore } from '../store/panels'
import type { Endpoint, User as HrUser } from '../types'

interface NavCommand {
  kind: 'nav'
  id: string
  label: string
  description: string
  icon: React.ElementType
  action: () => void
  keywords?: string[]
}

interface EndpointResult {
  kind: 'endpoint'
  id: string
  label: string
  description: string
  score: number
  compliance: string | null
}

interface UserResult {
  kind: 'user'
  id: string
  label: string
  description: string
  score: number
}

type Result = NavCommand | EndpointResult | UserResult

function useDebounce(value: string, ms: number) {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return debounced
}

interface CommandPaletteProps {
  open: boolean
  onClose: () => void
}

export default function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const navigate = useNavigate()
  const { openPanel } = usePanelStore()
  const inputRef = useRef<HTMLInputElement>(null)
  const debouncedQuery = useDebounce(query, 200)

  const navCommands: NavCommand[] = [
    { kind: 'nav', id: 'dashboard',    label: 'Overview',      description: 'Security dashboard & metrics',   icon: LayoutDashboard, action: () => navigate('/dashboard'),    keywords: ['home', 'overview'] },
    { kind: 'nav', id: 'endpoints',    label: 'Endpoints',     description: 'Managed devices and compliance', icon: Monitor,         action: () => navigate('/endpoints'),    keywords: ['devices', 'machines', 'hosts'] },
    { kind: 'nav', id: 'users',        label: 'Users',         description: 'User risk and activity',         icon: Users,           action: () => navigate('/users'),         keywords: ['people', 'accounts', 'identities'] },
    { kind: 'nav', id: 'compliance',   label: 'Compliance',    description: 'Device compliance status',       icon: CheckCircle,     action: () => navigate('/compliance'),    keywords: ['status', 'policy'] },
    { kind: 'nav', id: 'activity',     label: 'Activity',      description: 'Security event feed',            icon: Activity,        action: () => navigate('/activity'),      keywords: ['events', 'logs', 'timeline'] },
    { kind: 'nav', id: 'reports',      label: 'Reports',       description: 'Generate and export reports',    icon: FileText,        action: () => navigate('/reports'),       keywords: ['export', 'pdf', 'csv'] },
    { kind: 'nav', id: 'security',     label: 'Security',      description: 'Users, roles & audit log',       icon: Lock,            action: () => navigate('/security'),      keywords: ['audit', 'users', 'access'] },
    { kind: 'nav', id: 'integrations', label: 'Integrations',  description: 'Connected platforms and APIs',   icon: Plug,            action: () => navigate('/integrations'),  keywords: ['sentinelone', 'jumpcloud', 'google'] },
    { kind: 'nav', id: 'settings',     label: 'Settings',      description: 'Platform configuration',        icon: Settings,        action: () => navigate('/settings'),      keywords: ['config', 'platform', 'sso', 'mfa'] },
  ]

  // Live entity search — only fires when query has ≥2 chars
  const searchEnabled = debouncedQuery.trim().length >= 2
  const { data: searchData, isFetching } = useQuery({
    queryKey: ['cmd-search', debouncedQuery],
    queryFn: () => apiClient.get(`/search?q=${encodeURIComponent(debouncedQuery)}`).then(r => r.data as {
      endpoints: Endpoint[]
      users: HrUser[]
    }),
    enabled: searchEnabled,
    staleTime: 10_000,
  })

  // Build flattened result list
  const results: Result[] = React.useMemo(() => {
    const q = query.trim().toLowerCase()

    if (!q) return navCommands

    // Navigation matches
    const navMatches = navCommands.filter(c =>
      c.label.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q) ||
      c.keywords?.some(k => k.includes(q))
    )

    // Entity results from API
    const epResults: EndpointResult[] = (searchData?.endpoints ?? []).slice(0, 5).map(ep => ({
      kind: 'endpoint',
      id: ep.id,
      label: ep.hostname,
      description: [ep.ip_address, ep.owner?.email].filter(Boolean).join(' · ') || 'No IP / owner',
      score: ep.risk_score_override ?? ep.risk_score,
      compliance: ep.compliance_status?.status ?? null,
    }))

    const userResults: UserResult[] = (searchData?.users ?? []).slice(0, 4).map(u => ({
      kind: 'user',
      id: u.id,
      label: u.full_name,
      description: u.email + (u.department ? ` · ${u.department}` : ''),
      score: u.risk_score,
    }))

    return [...navMatches, ...epResults, ...userResults]
  }, [query, searchData, navCommands])

  useEffect(() => {
    if (open) {
      setQuery('')
      setSelected(0)
      setTimeout(() => inputRef.current?.focus(), 10)
    }
  }, [open])

  useEffect(() => { setSelected(0) }, [query])

  const execute = useCallback((result: Result) => {
    if (result.kind === 'nav') {
      result.action()
    } else if (result.kind === 'endpoint') {
      openPanel('endpoint', result.id, result.label)
    } else {
      navigate(`/users?highlight=${result.id}`)
    }
    onClose()
  }, [onClose, openPanel, navigate])

  useEffect(() => {
    if (!open) return
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { onClose(); return }
      if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, results.length - 1)) }
      if (e.key === 'ArrowUp')   { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)) }
      if (e.key === 'Enter' && results[selected]) execute(results[selected])
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [open, results, selected, execute, onClose])

  if (!open) return null

  // Group results for rendering
  const navResults   = results.filter(r => r.kind === 'nav') as NavCommand[]
  const epResults    = results.filter(r => r.kind === 'endpoint') as EndpointResult[]
  const userResults  = results.filter(r => r.kind === 'user') as UserResult[]

  function riskColor(score: number) {
    if (score >= 76) return '#f87171'
    if (score >= 51) return '#fb923c'
    if (score >= 26) return '#fbbf24'
    return '#4ade80'
  }

  function ResultRow({ result, index }: { result: Result; index: number }) {
    const isActive = index === selected

    if (result.kind === 'nav') {
      const Icon = result.icon
      return (
        <button
          className="w-full flex items-center gap-3 px-4 py-2.5 text-left transition-[background-color] duration-75"
          style={{ background: isActive ? 'rgba(16,185,129,0.08)' : 'transparent' }}
          onMouseEnter={() => setSelected(index)}
          onClick={() => execute(result)}
        >
          <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: isActive ? 'rgba(16,185,129,0.12)' : 'var(--surface-3)' }}>
            <Icon size={14} style={{ color: isActive ? 'var(--accent)' : '#71717a' }} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[13px] font-medium" style={{ color: isActive ? '#f1f5f9' : '#a1a1aa' }}>{result.label}</div>
            <div className="text-[11px] text-zinc-600">{result.description}</div>
          </div>
          {isActive && <ArrowRight size={13} style={{ color: 'var(--accent)', flexShrink: 0 }} />}
        </button>
      )
    }

    if (result.kind === 'endpoint') {
      return (
        <button
          className="w-full flex items-center gap-3 px-4 py-2.5 text-left transition-[background-color] duration-75"
          style={{ background: isActive ? 'rgba(16,185,129,0.08)' : 'transparent' }}
          onMouseEnter={() => setSelected(index)}
          onClick={() => execute(result)}
        >
          <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: isActive ? 'rgba(96,165,250,0.12)' : 'rgba(96,165,250,0.06)' }}>
            <Monitor size={13} style={{ color: isActive ? '#93c5fd' : '#4a7eb5' }} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[13px] font-medium font-mono" style={{ color: isActive ? '#f1f5f9' : '#a1a1aa' }}>{result.label}</div>
            <div className="text-[11px] text-zinc-600 truncate">{result.description}</div>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className="text-xs font-bold font-mono" style={{ color: riskColor(result.score) }}>{Math.round(result.score)}</span>
            {isActive && <ArrowRight size={13} style={{ color: 'var(--accent)' }} />}
          </div>
        </button>
      )
    }

    // user
    return (
      <button
        className="w-full flex items-center gap-3 px-4 py-2.5 text-left transition-[background-color] duration-75"
        style={{ background: isActive ? 'rgba(16,185,129,0.08)' : 'transparent' }}
        onMouseEnter={() => setSelected(index)}
        onClick={() => execute(result)}
      >
        <div className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 text-[11px] font-bold"
          style={{ background: 'rgba(16,185,129,0.12)', color: '#34d399' }}>
          {result.label[0]?.toUpperCase()}
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-[13px] font-medium" style={{ color: isActive ? '#f1f5f9' : '#a1a1aa' }}>{result.label}</div>
          <div className="text-[11px] text-zinc-600 truncate">{result.description}</div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="text-xs font-bold font-mono" style={{ color: riskColor(result.score) }}>{Math.round(result.score)}</span>
          {isActive && <ArrowRight size={13} style={{ color: 'var(--accent)' }} />}
        </div>
      </button>
    )
  }

  const hasEntityResults = epResults.length > 0 || userResults.length > 0
  const isSearching = searchEnabled && isFetching

  // Compute cumulative indices for correct `selected` mapping
  let idx = 0
  const navStart    = idx; idx += navResults.length
  const epStart     = idx; idx += epResults.length
  const userStart   = idx

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]"
      style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-[540px] mx-4 rounded-2xl overflow-hidden fade-in"
        style={{
          background: 'var(--surface-2)',
          border: '1px solid var(--border-lit)',
          boxShadow: '0 24px 64px rgba(0,0,0,0.6)',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3.5" style={{ borderBottom: '1px solid var(--border)' }}>
          <Search size={16} style={{ color: 'var(--text-4)', flexShrink: 0 }} />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search pages, endpoints, users…"
            className="flex-1 bg-transparent text-white text-[14px] placeholder-zinc-600 focus:outline-none"
          />
          {isSearching && (
            <div className="w-3.5 h-3.5 rounded-full border-2 border-zinc-600 border-t-emerald-400 animate-spin flex-shrink-0" />
          )}
          <button onClick={onClose} style={{ color: 'var(--text-4)', transition: 'color 150ms ease' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-2)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-4)')}>
            <X size={15} />
          </button>
        </div>

        {/* Results */}
        <div className="py-1.5 max-h-[420px] overflow-y-auto">
          {results.length === 0 && !isSearching ? (
            <div className="px-4 py-8 text-center text-[13px] text-zinc-600">
              No results for "{query}"
            </div>
          ) : (
            <>
              {/* Navigation section */}
              {navResults.length > 0 && (
                <>
                  <p className="text-[10px] font-semibold uppercase tracking-widest px-4 pt-2 pb-1.5 text-zinc-600">
                    {query ? 'Navigation' : 'Jump to'}
                  </p>
                  {navResults.map((r, i) => (
                    <ResultRow key={r.id} result={r} index={navStart + i} />
                  ))}
                </>
              )}

              {/* Endpoints section */}
              {epResults.length > 0 && (
                <>
                  <p className="text-[10px] font-semibold uppercase tracking-widest px-4 pt-3 pb-1.5 text-zinc-600">
                    Endpoints
                  </p>
                  {epResults.map((r, i) => (
                    <ResultRow key={r.id} result={r} index={epStart + i} />
                  ))}
                </>
              )}

              {/* Users section */}
              {userResults.length > 0 && (
                <>
                  <p className="text-[10px] font-semibold uppercase tracking-widest px-4 pt-3 pb-1.5 text-zinc-600">
                    Users
                  </p>
                  {userResults.map((r, i) => (
                    <ResultRow key={r.id} result={r} index={userStart + i} />
                  ))}
                </>
              )}

              {/* Searching indicator */}
              {isSearching && !hasEntityResults && query.length >= 2 && (
                <div className="px-4 py-4 text-center text-[12px] text-zinc-600">Searching…</div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center gap-4 px-4 py-2.5" style={{ borderTop: '1px solid var(--border)' }}>
          <div className="flex items-center gap-1.5 text-[11px] text-zinc-700">
            <kbd className="px-1.5 py-0.5 rounded text-[10px] font-mono" style={{ background: 'var(--surface-3)', border: '1px solid var(--border)' }}>↑↓</kbd>
            Navigate
          </div>
          <div className="flex items-center gap-1.5 text-[11px] text-zinc-700">
            <kbd className="px-1.5 py-0.5 rounded text-[10px] font-mono" style={{ background: 'var(--surface-3)', border: '1px solid var(--border)' }}>↵</kbd>
            Open
          </div>
          <div className="flex items-center gap-1.5 text-[11px] text-zinc-700">
            <kbd className="px-1.5 py-0.5 rounded text-[10px] font-mono" style={{ background: 'var(--surface-3)', border: '1px solid var(--border)' }}>Esc</kbd>
            Close
          </div>
          {query.length >= 2 && (
            <span className="ml-auto text-[11px] text-zinc-700">
              {epResults.length + userResults.length} entity result{epResults.length + userResults.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
