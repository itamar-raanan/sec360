import {
  Activity,
  Bug,
  Braces,
  CheckCircle,
  Database,
  FileText,
  LayoutDashboard,
  Monitor,
  Network,
  FileCheck2,
  History,
  Plug,
  ShieldCheck,
  Settings,
  Users,
  type LucideIcon,
} from 'lucide-react'

export type ProductRole = 'viewer' | 'analyst' | 'admin'
export type NavigationGroupId = 'overview' | 'monitor' | 'security-posture' | 'audit-policy' | 'infrastructure' | 'manage'

export interface NavigationGroup {
  id: NavigationGroupId
  label: string
  collapsible: boolean
  defaultExpanded: boolean
}

export const NAV_GROUPS: NavigationGroup[] = [
  { id: 'overview', label: 'Overview', collapsible: false, defaultExpanded: true },
  { id: 'monitor', label: 'Monitor', collapsible: true, defaultExpanded: true },
  { id: 'security-posture', label: 'Security Posture', collapsible: true, defaultExpanded: true },
  { id: 'audit-policy', label: 'Audit & Policy', collapsible: true, defaultExpanded: true },
  { id: 'infrastructure', label: 'Infrastructure', collapsible: true, defaultExpanded: false },
  { id: 'manage', label: 'Manage', collapsible: true, defaultExpanded: false },
]

export interface NavigationItem {
  to: string
  icon: LucideIcon
  label: string
  shortLabel?: string
  minRole: ProductRole
  group: NavigationGroupId
  placement?: 'main' | 'footer'
  requiredIntegration?: string
  requiredAnyIntegration?: string[]
  requiredFeature?: string
}

export const ROLE_RANK: Record<ProductRole, number> = { viewer: 1, analyst: 2, admin: 3 }

export const NAV_ITEMS: NavigationItem[] = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Overview', minRole: 'viewer', group: 'overview' },
  { to: '/endpoints', icon: Monitor, label: 'Endpoints', minRole: 'viewer', group: 'monitor' },
  { to: '/users', icon: Users, label: 'Users', minRole: 'viewer', group: 'monitor' },
  { to: '/activity', icon: Activity, label: 'Activity', minRole: 'viewer', group: 'monitor', requiredAnyIntegration: ['adfs', 'active_directory', 'google_workspace'] },
  { to: '/compliance', icon: CheckCircle, label: 'Compliance', minRole: 'viewer', group: 'security-posture' },
  { to: '/application-vulnerabilities', icon: Bug, label: 'Vulnerabilities', minRole: 'viewer', group: 'security-posture', requiredFeature: 'application_vulnerabilities' },
  { to: '/linux-audit', icon: FileCheck2, label: 'Linux Audit', minRole: 'viewer', group: 'audit-policy', requiredFeature: 'linux_audit' },
  { to: '/proxy-audit', icon: History, label: 'Proxy Audit', minRole: 'viewer', group: 'audit-policy', requiredFeature: 'proxy_audit' },
  { to: '/dlp-user-policy-search', icon: Database, label: 'DLP Search', minRole: 'analyst', group: 'audit-policy', requiredIntegration: 'symantec_dlp' },
  { to: '/puppet-facts', icon: Braces, label: 'Puppet Facts', minRole: 'analyst', group: 'audit-policy', requiredFeature: 'puppet_facts' },
  { to: '/network-map', icon: Network, label: 'Network Map', minRole: 'viewer', group: 'infrastructure', requiredFeature: 'network_map' },
  { to: '/reports', icon: FileText, label: 'Reports', minRole: 'analyst', group: 'manage' },
  { to: '/integrations', icon: Plug, label: 'Integrations', minRole: 'admin', group: 'manage' },
  { to: '/security', icon: ShieldCheck, label: 'Security', minRole: 'admin', group: 'manage' },
  { to: '/settings', icon: Settings, label: 'Settings', minRole: 'admin', group: 'manage', placement: 'footer' },
]

export function visibleNavigation(
  role?: string,
  connected = new Set<string>(),
  features = new Set<string>(),
) {
  const safeRole = (role === 'admin' || role === 'analyst' ? role : 'viewer') as ProductRole
  return NAV_ITEMS.filter(item =>
    ROLE_RANK[safeRole] >= ROLE_RANK[item.minRole]
    && (!item.requiredIntegration || connected.has(item.requiredIntegration))
    && (!item.requiredAnyIntegration || item.requiredAnyIntegration.some(type => connected.has(type)))
    && (!item.requiredFeature || features.has(item.requiredFeature))
  )
}
