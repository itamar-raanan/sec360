import React, { useEffect, useRef, useState } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import { LogOut, Menu, Moon, Search, ShieldCheck, Sun, X } from 'lucide-react'
import { useAuthStore } from '../../store/auth'
import { useThemeStore } from '../../store/theme'
import { visibleNavigation } from './navigation'
import { useConnectedIntegrations } from '../../hooks/useConnectedIntegrations'

const PRIMARY_PATHS = ['/dashboard', '/endpoints', '/compliance', '/activity']

interface MobileNavigationProps {
  onOpenCmd: () => void
}

export default function MobileNavigation({ onOpenCmd }: MobileNavigationProps) {
  const [open, setOpen] = useState(false)
  const location = useLocation()
  const navigate = useNavigate()
  const panelRef = useRef<HTMLDivElement>(null)
  const { user, logout } = useAuthStore()
  const { theme, toggle: toggleTheme } = useThemeStore()
  const { connected } = useConnectedIntegrations()
  const items = visibleNavigation(user?.role, connected)
  const primary = items.filter(item => PRIMARY_PATHS.includes(item.to))

  useEffect(() => setOpen(false), [location.pathname])
  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => event.key === 'Escape' && setOpen(false)
    document.body.style.overflow = 'hidden'
    window.addEventListener('keydown', onKey)
    panelRef.current?.focus()
    return () => {
      document.body.style.overflow = ''
      window.removeEventListener('keydown', onKey)
    }
  }, [open])

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <>
      <nav className="mobile-tab-bar md:hidden" aria-label="Primary navigation">
        {primary.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} className={({ isActive }) => `mobile-tab ${isActive ? 'is-active' : ''}`}>
            <Icon size={18} strokeWidth={1.9} />
            <span>{label}</span>
          </NavLink>
        ))}
        <button className={`mobile-tab ${open ? 'is-active' : ''}`} onClick={() => setOpen(true)} aria-expanded={open}>
          <Menu size={19} strokeWidth={1.9} />
          <span>More</span>
        </button>
      </nav>

      {open && (
        <div className="mobile-sheet-backdrop md:hidden" role="presentation" onMouseDown={() => setOpen(false)}>
          <div
            ref={panelRef}
            className="mobile-sheet"
            role="dialog"
            aria-modal="true"
            aria-label="Product navigation"
            tabIndex={-1}
            onMouseDown={event => event.stopPropagation()}
          >
            <div className="mobile-sheet-handle" aria-hidden />
            <div className="mobile-sheet-header">
              <div className="flex items-center gap-2.5">
                <span className="brand-mark"><ShieldCheck size={15} strokeWidth={2.4} /></span>
                <div><p className="text-[13px] font-semibold" style={{ color: 'var(--text-1)' }}>SEC360</p><p className="text-[10px]" style={{ color: 'var(--text-4)' }}>Security operations workspace</p></div>
              </div>
              <button className="ui-icon-button" onClick={() => setOpen(false)} aria-label="Close navigation"><X size={16} /></button>
            </div>

            <button className="mobile-command" onClick={() => { setOpen(false); onOpenCmd() }}>
              <Search size={15} /><span>Search or run a command</span><kbd>⌘K</kbd>
            </button>

            <div className="mobile-sheet-content">
              {(['Monitor', 'Analyze', 'Manage'] as const).map(group => {
                const groupItems = items.filter(item => item.group === group)
                if (!groupItems.length) return null
                return <section key={group} aria-labelledby={`mobile-group-${group}`}>
                  <p className="ui-eyebrow px-1" id={`mobile-group-${group}`}>{group}</p>
                  <div className="mt-2 grid grid-cols-2 gap-1.5">
                    {groupItems.map(({ to, icon: Icon, label, shortLabel }) => (
                      <NavLink key={to} to={to} className={({ isActive }) => `mobile-sheet-link ${isActive ? 'is-active' : ''}`}>
                        <Icon size={16} /><span>{shortLabel || label}</span>
                      </NavLink>
                    ))}
                  </div>
                </section>
              })}
            </div>

            <div className="mobile-sheet-footer">
              <button onClick={toggleTheme}>{theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}<span>{theme === 'dark' ? 'Light mode' : 'Dark mode'}</span></button>
              <span className="min-w-0 flex-1 truncate text-center text-[10px]" style={{ color: 'var(--text-4)' }}>{user?.email}</span>
              <button onClick={handleLogout} className="danger"><LogOut size={15} /><span>Sign out</span></button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
