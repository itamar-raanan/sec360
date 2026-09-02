import React from 'react'
import { useLocation } from 'react-router-dom'
import { Bell, Search } from 'lucide-react'

const PAGE_TITLES: Record<string, { title: string; desc: string }> = {
  '/dashboard':    { title: 'Overview',      desc: 'Platform-wide security visibility' },
  '/endpoints':    { title: 'Endpoints',     desc: 'Managed devices and compliance' },
  '/users':        { title: 'Users',         desc: 'User risk and activity' },
  '/compliance':   { title: 'Compliance',    desc: 'Device compliance status' },
  '/activity':     { title: 'Activity',      desc: 'Security event feed' },
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
  const path = '/' + location.pathname.split('/')[1]
  const meta = PAGE_TITLES[path] || { title: 'SEC360', desc: '' }

  return (
    <header
      className="h-14 px-6 flex items-center justify-between sticky top-0 z-10"
      style={{
        background: 'color-mix(in srgb, var(--surface-1) 85%, transparent)',
        backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
        borderBottom: '1px solid var(--border)',
      }}
    >
      <div className="flex items-center gap-3">
        <h1 className="text-[15px] font-semibold tracking-tight" style={{ color: 'var(--text-1)' }}>{meta.title}</h1>
        {meta.desc && (
          <>
            <span style={{ color: 'var(--border-mid)', fontSize: 13 }}>/</span>
            <span className="text-[12px]" style={{ color: 'var(--text-4)' }}>{meta.desc}</span>
          </>
        )}
      </div>

      <div className="flex items-center gap-1.5">
        {/* Command palette trigger */}
        <button
          onClick={onOpenCmd}
          className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg text-[12px] pressable transition-[background-color,border-color] duration-150"
          style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-4)' }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--border-mid)'; e.currentTarget.style.color = 'var(--text-3)' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-4)' }}
          title="Open command palette (⌘K)"
        >
          <Search size={12} />
          <span>Search…</span>
          <kbd className="ml-1 px-1 py-0.5 rounded text-[10px] font-mono"
            style={{ background: 'var(--surface-3)', border: '1px solid var(--border)', color: 'var(--text-4)' }}>
            ⌘K
          </kbd>
        </button>

        <button
          className="relative p-2 rounded-lg pressable transition-[color,background-color] duration-150"
          style={{ color: 'var(--text-4)' }}
          onMouseEnter={e => { e.currentTarget.style.background = 'var(--hover-1)'; e.currentTarget.style.color = 'var(--text-2)' }}
          onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-4)' }}
          title="Notifications"
        >
          <Bell size={15} strokeWidth={1.75} />
          <span
            className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-red-500"
            style={{ boxShadow: '0 0 0 2px var(--surface-1)' }}
          />
        </button>
      </div>
    </header>
  )
}
