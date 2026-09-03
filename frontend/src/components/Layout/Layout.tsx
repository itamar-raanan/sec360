import React, { useState, useEffect } from 'react'
import { Outlet, Navigate, useLocation } from 'react-router-dom'
import Sidebar from './Sidebar'
import Header from './Header'
import CommandPalette from '../CommandPalette'
import FloatingPanels from '../FloatingPanels'
import { useAuthStore } from '../../store/auth'
import { useThemeStore } from '../../store/theme'

export default function Layout() {
  const { isAuthenticated } = useAuthStore()
  const { theme } = useThemeStore()
  const location = useLocation()
  const [cmdOpen, setCmdOpen] = useState(false)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
  }, [theme])
  const [sidebarCollapsed, setSidebarCollapsed] = useState(
    () => localStorage.getItem('sidebar-collapsed') === 'true'
  )

  const toggleSidebar = () => {
    setSidebarCollapsed(v => {
      const next = !v
      localStorage.setItem('sidebar-collapsed', String(next))
      return next
    })
  }

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setCmdOpen(v => !v)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  const { sessionLoading } = useAuthStore()

  if (sessionLoading) {
    // Session check still in-flight — render nothing to avoid premature redirect.
    // This resolves within one /auth/me round-trip (~50–200 ms).
    return null
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return (
    <>
      <div className="grain-overlay" aria-hidden />
      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
      <FloatingPanels />
      <div className="flex h-[100dvh] overflow-hidden" style={{ background: 'var(--surface-0)' }}>
        <Sidebar collapsed={sidebarCollapsed} onToggle={toggleSidebar} onOpenCmd={() => setCmdOpen(true)} />
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <Header onOpenCmd={() => setCmdOpen(true)} />
          <main className="flex-1 overflow-hidden relative">
            <div key={location.pathname} className="fade-up h-full" style={{ animationDuration: '200ms' }}>
              <Outlet />
            </div>
          </main>
        </div>
      </div>
    </>
  )
}
