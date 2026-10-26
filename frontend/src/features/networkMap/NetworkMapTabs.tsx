import { Box, Settings2, Table2 } from 'lucide-react'
import { NavLink } from 'react-router-dom'

import { useAuthStore } from '../../store/auth'

export default function NetworkMapTabs({ floating = false }: { floating?: boolean }) {
  const { user } = useAuthStore()
  const tabs = [
    { to: '/network-map', label: 'Visual', icon: Box, end: true },
    { to: '/network-map/table', label: 'Table', icon: Table2, end: false },
    ...(user?.role === 'admin' ? [{ to: '/network-map/config', label: 'Config', icon: Settings2, end: false }] : []),
  ]

  return <nav aria-label="Network Map views" className={`ui-command-surface flex items-center gap-1 rounded-[var(--radius-panel)] px-1 ${floating ? 'pointer-events-auto' : ''}`}>
    {tabs.map(({ to, label, icon: Icon, end }) => <NavLink key={to} to={to} end={end} className="ui-tab"><Icon size={13} /> {label}</NavLink>)}
  </nav>
}
