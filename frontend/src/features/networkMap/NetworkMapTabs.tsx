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

  return <nav aria-label="Network Map views" className={`flex items-center gap-1 rounded-xl border border-white/[0.09] bg-[#07111c]/90 p-1 shadow-lg backdrop-blur-xl ${floating ? 'pointer-events-auto' : ''}`}>
    {tabs.map(({ to, label, icon: Icon, end }) => <NavLink key={to} to={to} end={end} className={({ isActive }) => `inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-[11px] font-semibold transition-colors ${isActive ? 'bg-cyan-300 text-[#041017]' : 'text-slate-400 hover:bg-white/[0.05] hover:text-white'}`}><Icon size={13} /> {label}</NavLink>)}
  </nav>
}
