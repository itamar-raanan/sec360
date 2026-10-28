import React, { useEffect, useMemo, useState } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import {
  ChevronDown,
  ShieldCheck,
  LogOut,
  Search,
  PanelLeftClose,
  PanelLeftOpen,
  Sun,
  Moon,
} from 'lucide-react'
import { useAuthStore } from '../../store/auth'
import { useThemeStore } from '../../store/theme'
import { NAV_GROUPS, type NavigationGroupId, type NavigationItem, visibleNavigation } from './navigation'
import { useConnectedIntegrations } from '../../hooks/useConnectedIntegrations'

interface SidebarProps {
  collapsed?: boolean
  onToggle?: () => void
  onOpenCmd?: () => void
}

export default function Sidebar({ collapsed = false, onToggle, onOpenCmd }: SidebarProps) {
  const { user, logout } = useAuthStore()
  const { theme, toggle: toggleTheme } = useThemeStore()
  const navigate = useNavigate()
  const location = useLocation()
  const { connected, features } = useConnectedIntegrations()

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  const visibleItems = visibleNavigation(user?.role, connected, features)
  const mainItems = visibleItems.filter(item => item.placement !== 'footer')
  const footerItems = visibleItems.filter(item => item.placement === 'footer')
  const storageKey = `sidebar-groups:${user?.email || 'default'}`
  const [expandedGroups, setExpandedGroups] = useState<Record<NavigationGroupId, boolean>>(() => {
    const defaults = Object.fromEntries(NAV_GROUPS.map(group => [group.id, group.defaultExpanded])) as Record<NavigationGroupId, boolean>
    try {
      const saved = window.localStorage.getItem(storageKey)
      return saved ? { ...defaults, ...JSON.parse(saved) } : defaults
    } catch {
      return defaults
    }
  })

  const activeGroup = useMemo(
    () => mainItems.find(item => location.pathname === item.to || location.pathname.startsWith(`${item.to}/`))?.group,
    [location.pathname, mainItems],
  )

  useEffect(() => {
    if (!activeGroup) return
    setExpandedGroups(current => current[activeGroup] ? current : { ...current, [activeGroup]: true })
  }, [activeGroup])

  useEffect(() => {
    window.localStorage.setItem(storageKey, JSON.stringify(expandedGroups))
  }, [expandedGroups, storageKey])

  const toggleGroup = (group: NavigationGroupId) => {
    setExpandedGroups(current => ({ ...current, [group]: !current[group] }))
  }

  const renderLink = ({ to, icon: Icon, label }: NavigationItem) => (
    <NavLink
      key={to}
      to={to}
      end={to === '/dashboard'}
      title={collapsed ? label : undefined}
      className={({ isActive }) =>
        `group nav-item relative flex items-center rounded-xl text-[13px] font-medium transition-[background-color,color,box-shadow] duration-150 ${
          collapsed ? 'justify-center px-0 py-2.5' : 'gap-2.5 px-3 py-2'
        } ${
          isActive
            ? 'nav-item--active'
            : 'text-zinc-500 hover:text-zinc-200 hover:bg-white/[0.04]'
        }`
      }
    >
      {({ isActive }) => (
        <>
          {isActive && !collapsed && <span className="absolute inset-y-2 left-0 w-0.5 rounded-full" style={{ background: 'var(--accent)', boxShadow: '0 0 12px var(--accent)' }} />}
          <span
            className={`rounded-md p-1 transition-[background-color] duration-150 flex-shrink-0 ${
              isActive ? '' : 'text-zinc-600 group-hover:text-zinc-300'
            }`}
            style={isActive ? { color: 'var(--text-1)' } : {}}
          >
            <Icon size={14} strokeWidth={isActive ? 2.5 : 2} />
          </span>
          <span
            className="overflow-hidden whitespace-nowrap flex-1"
            style={{ maxWidth: collapsed ? 0 : 160, opacity: collapsed ? 0 : 1, transition: 'max-width 200ms ease, opacity 150ms ease' }}
          >
            {label}
          </span>
        </>
      )}
    </NavLink>
  )

  return (
    <aside
      className="glass-sidebar hidden md:flex flex-shrink-0 flex-col h-[100dvh] sticky top-0 overflow-hidden"
      style={{
        width: collapsed ? 68 : 236,
        transition: 'width 220ms cubic-bezier(0.23,1,0.32,1)',
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
          className="brand-mark"
        >
          <ShieldCheck size={15} strokeWidth={2.5} />
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
            className="ui-control w-full flex items-center justify-center h-9 transition-[background-color] duration-150"
            style={{ color: 'var(--text-4)' }}
          >
            <Search size={13} />
          </button>
        ) : (
          <button
            onClick={onOpenCmd}
            className="ui-control w-full flex items-center gap-2.5 px-3 py-2 text-[12px] transition-[background-color] duration-150"
            style={{ color: 'var(--text-4)' }}
          >
            <Search size={12} className="flex-shrink-0" />
            <span className="flex-1 text-left overflow-hidden" style={{ whiteSpace: 'nowrap' }}>Search…</span>
            <kbd className="px-1.5 py-0.5 rounded-md text-[10px] flex-shrink-0"
              style={{ background: 'var(--surface-1)', border: '1px solid var(--border)', color: 'var(--text-4)' }}>⌘K</kbd>
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2.5 py-2 overflow-y-auto overflow-x-hidden" aria-label="Product navigation">
        {collapsed ? (
          <div className="space-y-0.5">
            {NAV_GROUPS.map(group => {
              const groupItems = mainItems.filter(item => item.group === group.id)
              if (!groupItems.length) return null
              return (
                <div key={group.id} className="space-y-0.5 first:pt-0 pt-1.5 mt-1.5 first:mt-0 border-t first:border-t-0" style={{ borderColor: 'var(--border)' }}>
                  {groupItems.map(renderLink)}
                </div>
              )
            })}
          </div>
        ) : (
          <div className="space-y-1">
            {NAV_GROUPS.map(group => {
              const groupItems = mainItems.filter(item => item.group === group.id)
              if (!groupItems.length) return null
              if (!group.collapsible) return <div key={group.id}>{groupItems.map(renderLink)}</div>
              const isExpanded = expandedGroups[group.id]
              const hasActiveItem = group.id === activeGroup
              return (
                <section key={group.id}>
                  <button
                    type="button"
                    onClick={() => toggleGroup(group.id)}
                    className="group flex w-full items-center gap-2 rounded-md px-3 py-2 text-left transition-colors hover:bg-white/[0.025]"
                    aria-expanded={isExpanded}
                  >
                    <span
                      className="text-[12px] font-medium flex-1 whitespace-nowrap"
                      style={{ color: hasActiveItem ? 'var(--text-2)' : 'var(--text-4)' }}
                    >
                      {group.label}
                    </span>
                    {hasActiveItem && <span className="h-1 w-1 rounded-full" style={{ background: 'var(--accent)' }} aria-hidden />}
                    <ChevronDown
                      size={12}
                      style={{ color: 'var(--text-4)', transform: isExpanded ? 'rotate(0deg)' : 'rotate(-90deg)', transition: 'transform 160ms ease' }}
                    />
                  </button>
                  <div className={isExpanded ? 'space-y-0.5 pb-1' : 'hidden'}>{groupItems.map(renderLink)}</div>
                </section>
              )
            })}
          </div>
        )}
      </nav>

      {footerItems.length > 0 && (
        <div className="px-2.5 py-2 flex-shrink-0" style={{ borderTop: '1px solid var(--border)' }}>
          {footerItems.map(renderLink)}
        </div>
      )}

      {/* Theme toggle */}
      <div className="px-2.5 py-2 flex-shrink-0" style={{ borderTop: '1px solid var(--border)' }}>
        <button
          onClick={toggleTheme}
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            className={`w-full flex items-center rounded-xl py-2 transition-[background-color,color] duration-150 ${
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
          className={`w-full flex items-center rounded-xl py-2 transition-[background-color,color] duration-150 text-zinc-600 hover:text-zinc-300 hover:bg-white/[0.04] ${
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
          className={`flex items-center rounded-xl border border-transparent hover:border-white/[0.06] hover:bg-white/[0.04] transition-[background-color,border-color] duration-150 group ${
            collapsed ? 'justify-center px-0 py-2' : 'gap-2.5 px-3 py-2.5'
          }`}
          title={collapsed ? `${user?.email?.split('@')[0]} · ${user?.role}` : undefined}
        >
          <div
            className="w-8 h-8 rounded-full flex items-center justify-center text-[11px] font-bold flex-shrink-0"
            style={{ background: 'var(--accent-dim)', color: 'var(--accent)', border: '1px solid var(--accent-ring)' }}
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
            <div className="text-[11px] capitalize mt-0.5 whitespace-nowrap" style={{ color: 'var(--text-3)' }}>{user?.role}</div>
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
