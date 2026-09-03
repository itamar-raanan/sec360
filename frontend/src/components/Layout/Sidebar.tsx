import React from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  ShieldCheck,
  LayoutDashboard,
  Monitor,
  Users,
  CheckCircle,
  Activity,
  LogOut,
  Plug,
  Settings,
  FileText,
  Search,
  PanelLeftClose,
  PanelLeftOpen,
  Sun,
  Moon,
  Brain,
  MessageSquare,
  Database,
  Fingerprint,
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { useAuthStore } from '../../store/auth'
import { useThemeStore } from '../../store/theme'
import { fetchInsightStats } from '../../api/ai'

const NAV_ITEMS = [
  { to: '/dashboard',    icon: LayoutDashboard, label: 'Overview',     minRole: 'viewer' },
  { to: '/endpoints',    icon: Monitor,         label: 'Endpoints',    minRole: 'viewer' },
  { to: '/users',        icon: Users,           label: 'Users',        minRole: 'viewer' },
  { to: '/compliance',   icon: CheckCircle,     label: 'Compliance',   minRole: 'viewer' },
  { to: '/activity',     icon: Activity,        label: 'Activity',     minRole: 'viewer' },
  { to: '/investigation', icon: Search,          label: 'Investigation', minRole: 'viewer' },
  { to: '/data-quality',  icon: Fingerprint,     label: 'Data Quality',  minRole: 'viewer' },
  { to: '/dlp-user-policy-search', icon: Database, label: 'DLP Policy Search', minRole: 'analyst' },
  { to: '/ai-chat',      icon: MessageSquare,   label: 'AI Assistant', minRole: 'viewer' },
  { to: '/ai-insights',  icon: Brain,           label: 'AI Insights',  minRole: 'analyst' },
  { to: '/reports',      icon: FileText,        label: 'Reports',      minRole: 'analyst' },
  { to: '/integrations', icon: Plug,            label: 'Integrations', minRole: 'admin' },
  { to: '/settings',     icon: Settings,        label: 'Settings',     minRole: 'admin' },
]

const ROLE_RANK: Record<string, number> = { viewer: 1, analyst: 2, admin: 3 }

interface SidebarProps {
  collapsed?: boolean
  onToggle?: () => void
  onOpenCmd?: () => void
}

export default function Sidebar({ collapsed = false, onToggle, onOpenCmd }: SidebarProps) {
  const { user, logout } = useAuthStore()
  const { theme, toggle: toggleTheme } = useThemeStore()
  const navigate = useNavigate()
  const userRank = ROLE_RANK[user?.role ?? 'viewer'] ?? 1

  // Fetch insight stats to show alert dot on AI Insights nav item
  const { data: insightStats } = useQuery({
    queryKey: ['ai-insight-stats'],
    queryFn: fetchInsightStats,
    refetchInterval: 30000,
    // Only fetch for analyst+ roles
    enabled: userRank >= 2,
  })
  const hasUrgentInsights = (insightStats?.critical ?? 0) + (insightStats?.high ?? 0) > 0

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const visibleItems = NAV_ITEMS.filter(item => userRank >= (ROLE_RANK[item.minRole] ?? 1))

  return (
    <aside
      className="flex-shrink-0 flex flex-col h-[100dvh] sticky top-0 overflow-hidden"
      style={{
        width: collapsed ? 60 : 220,
        transition: 'width 220ms cubic-bezier(0.23,1,0.32,1)',
        background: 'var(--surface-1)',
        borderRight: '1px solid var(--border)',
      }}
    >
      {/* Brand */}
      <div
        className="h-14 flex items-center flex-shrink-0"
        style={{
          borderBottom: '1px solid var(--border)',
          padding: collapsed ? '0 16px' : '0 20px',
          transition: 'padding 220ms cubic-bezier(0.23,1,0.32,1)',
        }}
      >
        <div
          className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: 'var(--accent)', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.18)' }}
        >
          <ShieldCheck size={15} className="text-white" strokeWidth={2.5} />
        </div>
        <div
          className="overflow-hidden flex items-center gap-2 flex-1"
          style={{
            maxWidth: collapsed ? 0 : 160,
            opacity: collapsed ? 0 : 1,
            transition: 'max-width 200ms ease, opacity 150ms ease',
            whiteSpace: 'nowrap',
            marginLeft: collapsed ? 0 : 10,
          }}
        >
          <span className="font-bold text-[15px] tracking-tight" style={{ color: 'var(--text-1)' }}>SEC360</span>
          <div className="ml-auto flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 flex-shrink-0" style={{ animation: 'pulse-dot 2.5s ease-in-out infinite' }} />
          </div>
        </div>
      </div>

      {/* Search trigger */}
      <div
        className="pt-3 pb-1 flex-shrink-0"
        style={{ padding: collapsed ? '12px 10px 4px' : '12px 10px 4px' }}
      >
        {collapsed ? (
          <button
            onClick={onOpenCmd}
            title="Search (⌘K)"
            className="w-full flex items-center justify-center h-8 rounded-lg transition-[background-color] duration-150"
            style={{ background: 'var(--surface-3)', border: '1px solid var(--border)', color: 'var(--text-4)' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--border-mid)'; e.currentTarget.style.color = 'var(--text-3)' }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-4)' }}
          >
            <Search size={13} />
          </button>
        ) : (
          <button
            onClick={onOpenCmd}
            className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-[12px] transition-[background-color] duration-150"
            style={{ background: 'var(--surface-3)', border: '1px solid var(--border)', color: 'var(--text-4)' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--border-mid)'; e.currentTarget.style.color = 'var(--text-3)' }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-4)' }}
          >
            <Search size={12} className="flex-shrink-0" />
            <span className="flex-1 text-left overflow-hidden" style={{ whiteSpace: 'nowrap' }}>Search…</span>
            <kbd className="px-1 py-0.5 rounded text-[9px] font-mono flex-shrink-0"
              style={{ background: 'var(--surface-1)', border: '1px solid var(--border)', color: 'var(--text-4)' }}>⌘K</kbd>
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2.5 py-2 overflow-y-auto space-y-0.5 overflow-x-hidden">
        {!collapsed && (
          <p className="text-[10px] uppercase tracking-[0.12em] font-semibold px-3 pb-2 pt-1 whitespace-nowrap" style={{ color: 'var(--text-4)' }}>
            Navigation
          </p>
        )}
        {visibleItems.map(({ to, icon: Icon, label }) => {
          const showDot = to === '/ai-insights' && hasUrgentInsights
          return (
            <NavLink
              key={to}
              to={to}
              title={collapsed ? label : undefined}
              className={({ isActive }) =>
                `group nav-item relative flex items-center rounded-lg text-[13px] font-medium transition-[background-color,color] duration-150 ${
                  collapsed ? 'justify-center px-0 py-2.5' : 'gap-2.5 px-3 py-2.5'
                } ${
                  isActive
                    ? 'nav-item--active text-emerald-500'
                    : 'text-zinc-500 hover:text-zinc-200 hover:bg-white/[0.04]'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  {isActive && !collapsed && (
                    <span
                      className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 rounded-r-full"
                      style={{ background: 'var(--accent)' }}
                    />
                  )}
                  <span
                    className={`relative rounded-md p-1 transition-[background-color] duration-150 flex-shrink-0 ${
                      isActive ? 'text-emerald-400' : 'text-zinc-600 group-hover:text-zinc-300'
                    }`}
                    style={isActive ? { background: 'var(--accent-dim)' } : {}}
                  >
                    <Icon size={14} strokeWidth={isActive ? 2.5 : 2} />
                    {showDot && (
                      <span
                        className="absolute top-0 right-0 w-2 h-2 rounded-full"
                        style={{
                          background: '#ef4444',
                          border: '1.5px solid var(--surface-1)',
                          transform: 'translate(30%, -30%)',
                        }}
                      />
                    )}
                  </span>
                  <span
                    className="overflow-hidden whitespace-nowrap flex-1 flex items-center gap-1.5"
                    style={{
                      maxWidth: collapsed ? 0 : 160,
                      opacity: collapsed ? 0 : 1,
                      transition: 'max-width 200ms ease, opacity 150ms ease',
                    }}
                  >
                    {label}
                    {showDot && !collapsed && (
                      <span
                        className="inline-flex items-center text-[9px] font-bold px-1 py-0.5 rounded-full flex-shrink-0"
                        style={{
                          color: '#ef4444',
                          background: 'rgba(239,68,68,0.12)',
                          border: '1px solid rgba(239,68,68,0.20)',
                          lineHeight: 1,
                        }}
                      >
                        {(insightStats?.critical ?? 0) + (insightStats?.high ?? 0)}
                      </span>
                    )}
                  </span>
                </>
              )}
            </NavLink>
          )
        })}
      </nav>

      {/* Theme toggle */}
      <div className="px-2.5 py-2 flex-shrink-0" style={{ borderTop: '1px solid var(--border)' }}>
        <button
          onClick={toggleTheme}
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          className={`w-full flex items-center rounded-lg py-2 transition-[background-color,color] duration-150 ${
            collapsed ? 'justify-center px-0' : 'gap-2 px-3'
          }`}
          style={{ color: 'var(--text-4)' }}
          onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-2)'; (e.currentTarget as HTMLButtonElement).style.background = 'var(--hover-1)' }}
          onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-4)'; (e.currentTarget as HTMLButtonElement).style.background = 'transparent' }}
        >
          {theme === 'dark'
            ? <Sun size={14} className="flex-shrink-0" />
            : <Moon size={14} className="flex-shrink-0" />
          }
          <span
            className="text-[12px] overflow-hidden whitespace-nowrap"
            style={{ maxWidth: collapsed ? 0 : 120, opacity: collapsed ? 0 : 1, transition: 'max-width 200ms ease, opacity 150ms ease' }}
          >
            {theme === 'dark' ? 'Light mode' : 'Dark mode'}
          </span>
        </button>
      </div>

      {/* Collapse toggle */}
      <div className="px-2.5 py-2 flex-shrink-0" style={{ borderTop: '1px solid var(--border)' }}>
        <button
          onClick={onToggle}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className={`w-full flex items-center rounded-lg py-2 transition-[background-color,color] duration-150 text-zinc-600 hover:text-zinc-300 hover:bg-white/[0.04] ${
            collapsed ? 'justify-center px-0' : 'gap-2 px-3'
          }`}
        >
          {collapsed
            ? <PanelLeftOpen size={14} />
            : <>
                <PanelLeftClose size={14} className="flex-shrink-0" />
                <span
                  className="text-[12px] overflow-hidden whitespace-nowrap"
                  style={{ maxWidth: collapsed ? 0 : 120, opacity: collapsed ? 0 : 1, transition: 'max-width 200ms ease, opacity 150ms ease' }}
                >
                  Collapse
                </span>
              </>
          }
        </button>
      </div>

      {/* User profile */}
      <div className="px-2.5 py-3 flex-shrink-0" style={{ borderTop: '1px solid var(--border)' }}>
        <div
          className={`flex items-center rounded-lg hover:bg-white/[0.04] transition-[background-color] duration-150 group ${
            collapsed ? 'justify-center px-0 py-2' : 'gap-2.5 px-3 py-2.5'
          }`}
          title={collapsed ? `${user?.email?.split('@')[0]} · ${user?.role}` : undefined}
        >
          <div
            className="w-7 h-7 rounded-full flex items-center justify-center text-white text-[11px] font-bold flex-shrink-0"
            style={{ background: 'linear-gradient(135deg, #059669, #0d9488)' }}
          >
            {user?.email?.[0]?.toUpperCase() ?? 'A'}
          </div>
          <div
            className="flex-1 min-w-0 overflow-hidden"
            style={{ maxWidth: collapsed ? 0 : 120, opacity: collapsed ? 0 : 1, transition: 'max-width 200ms ease, opacity 150ms ease' }}
          >
            <div className="text-[12px] font-medium truncate leading-none whitespace-nowrap" style={{ color: 'var(--text-1)' }}>
              {user?.email?.split('@')[0]}
            </div>
            <div className="text-[10px] capitalize mt-0.5 whitespace-nowrap" style={{ color: 'var(--text-4)' }}>{user?.role}</div>
          </div>
          <button
            onClick={handleLogout}
            className="text-zinc-600 hover:text-red-400 transition-[color] duration-150 p-1 rounded opacity-0 group-hover:opacity-100 flex-shrink-0"
            style={{ maxWidth: collapsed ? 0 : 24, overflow: 'hidden', transition: 'max-width 200ms ease, opacity 150ms ease' }}
            title="Logout"
          >
            <LogOut size={13} />
          </button>
        </div>
      </div>
    </aside>
  )
}
