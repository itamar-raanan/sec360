import {
  Activity,
  Bug,
  CheckCircle,
  Database,
  FileText,
  LayoutDashboard,
  Monitor,
  Plug,
  Settings,
  Users,
  type LucideIcon,
} from 'lucide-react'

export type ProductRole = 'viewer' | 'analyst' | 'admin'

export interface NavigationItem {
  to: string
  icon: LucideIcon
  label: string
  shortLabel?: string
  minRole: ProductRole
  group: 'Monitor' | 'Analyze' | 'Manage'
}

export const ROLE_RANK: Record<ProductRole, number> = { viewer: 1, analyst: 2, admin: 3 }

export const NAV_ITEMS: NavigationItem[] = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Overview', minRole: 'viewer', group: 'Monitor' },
  { to: '/endpoints', icon: Monitor, label: 'Endpoints', minRole: 'viewer', group: 'Monitor' },
  { to: '/users', icon: Users, label: 'Users', minRole: 'viewer', group: 'Monitor' },
  { to: '/compliance', icon: CheckCircle, label: 'Compliance', minRole: 'viewer', group: 'Monitor' },
  { to: '/activity', icon: Activity, label: 'Activity', minRole: 'viewer', group: 'Monitor' },
  { to: '/application-vulnerabilities', icon: Bug, label: 'App Vulnerabilities', shortLabel: 'Vulnerabilities', minRole: 'viewer', group: 'Analyze' },
  { to: '/dlp-user-policy-search', icon: Database, label: 'DLP Policy Search', minRole: 'analyst', group: 'Analyze' },
  { to: '/reports', icon: FileText, label: 'Reports', minRole: 'analyst', group: 'Manage' },
  { to: '/integrations', icon: Plug, label: 'Integrations', minRole: 'admin', group: 'Manage' },
  { to: '/settings', icon: Settings, label: 'Settings', minRole: 'admin', group: 'Manage' },
]

export function visibleNavigation(role?: string) {
  const safeRole = (role === 'admin' || role === 'analyst' ? role : 'viewer') as ProductRole
  return NAV_ITEMS.filter(item => ROLE_RANK[safeRole] >= ROLE_RANK[item.minRole])
}
