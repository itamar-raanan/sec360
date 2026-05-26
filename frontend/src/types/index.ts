export type EmploymentStatus = 'active' | 'inactive' | 'on_leave'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type ComplianceStatusValue = 'compliant' | 'partial' | 'non_compliant'
export type AgentProduct = 'sentinelone' | 'symantec' | 'prisma' | 'globalprotect' | 'symantec_wss' | 'other'
export type AgentStatus = 'active' | 'inactive' | 'unknown'
export type EventType = 'login' | 'app_usage' | 'network' | 'vpn' | 'logout' | 'file_access' | 'oauth_grant' | 'saml' | 'user_account' | 'access_eval' | 'cloud_access'
export type AuthRole = 'admin' | 'analyst' | 'viewer'

export interface AuthUser {
  id: string
  email: string
  role: AuthRole
  is_active: boolean
}

export interface UserSources {
  jumpcloud?: {
    active: boolean
    suspended: boolean
    mfa: boolean
    last_seen?: string | null
    external_id?: string | null
  }
  google?: {
    active: boolean
    suspended: boolean
    mfa: boolean
    last_login?: string | null
    org_unit?: string | null
  }
}

export interface User {
  id: string
  full_name: string
  email: string
  department: string | null
  manager: string | null
  employment_status: EmploymentStatus
  mfa_enabled: boolean
  suspended: boolean
  last_login: string | null
  risk_score: number
  job_title?: string | null
  phone?: string | null
  sources?: UserSources | null
  endpoint_count: number
  created_at: string
  updated_at: string
}

export interface UserDetail extends User {
  endpoints: Endpoint[]
  recent_events: ActivityEvent[]
}

export interface Endpoint {
  id: string
  hostname: string
  serial_number: string | null
  os_version: string | null
  username: string | null
  ip_address: string | null
  all_ips: string | null
  external_ip: string | null
  last_reboot: string | null
  location: string | null
  source: string | null
  last_seen: string | null
  risk_score: number
  risk_score_override: number | null
  risk_score_note: string | null
  owner_user_id: string | null
  owner: {
    id: string
    full_name: string
    email: string
    department: string | null
  } | null
  tags?: string | null
  agents?: SecurityAgent[]
  compliance_status?: ComplianceStatus | null
  created_at: string
  updated_at: string
}

export interface ComplianceStatus {
  id: string
  endpoint_id: string
  edr_installed: boolean
  edr_version_ok: boolean
  dlp_installed: boolean
  dlp_version_ok: boolean
  gp_installed: boolean
  gp_version_ok: boolean
  wss_installed: boolean
  wss_version_ok: boolean
  disk_encrypted: boolean | null
  device_control_enabled: boolean | null
  status: ComplianceStatusValue
  last_evaluated: string
}

export interface SecurityAgent {
  id: string
  endpoint_id: string
  product_name: AgentProduct
  status: AgentStatus
  version: string | null
  last_seen: string | null
  agent_group: string | null
  agent_state: string | null
}

export interface ComplianceSummaryStats {
  total: number
  compliant: number
  partial: number
  non_compliant: number
  compliant_pct: number
  no_edr: number
  outdated_agent: number
  offline: number
  no_encryption: number
}

export interface ActivityEvent {
  id: string
  user_id: string | null
  event_type: EventType
  timestamp: string
  location: string | null
  device_id: string | null
  ip_address: string | null
  country: string | null
  details: Record<string, unknown> | null
  is_suspicious: boolean
  user?: {
    id: string
    full_name: string
    email: string
  } | null
  created_at: string
}

export interface RiskSummaryBucket {
  low: number
  medium: number
  high: number
  critical: number
  total: number
}

export interface RiskSummary {
  users: RiskSummaryBucket
  endpoints: RiskSummaryBucket
}

export interface TokenResponse {
  access_token: string
  token_type: string
  user: AuthUser
}

export interface AgentSummary {
  id: string
  product_name: string
  status: AgentStatus
  version: string | null
  last_seen: string | null
  agent_group: string | null
}

export interface ComplianceSummaryShort {
  status: ComplianceStatusValue
  edr_installed: boolean
  edr_version_ok: boolean
  dlp_installed: boolean
  dlp_version_ok: boolean
  gp_installed: boolean
  gp_version_ok: boolean
  wss_installed: boolean
  wss_version_ok: boolean
  disk_encrypted: boolean | null
  device_control_enabled: boolean | null
  last_evaluated: string
}

export interface EndpointIdentity {
  id: string
  hostname: string
  os_version: string | null
  ip_address: string | null
  location: string | null
  username: string | null
  last_seen: string | null
  risk_score: number
  agents: AgentSummary[]
  compliance: ComplianceSummaryShort | null
  agent_products: string[]
}

export interface UserIdentity extends User {
  endpoints: EndpointIdentity[]
  data_sources: string[]
  total_endpoints: number
  endpoints_with_sentinelone: number
  endpoints_with_symantec: number
  endpoints_compliant: number
  endpoints_non_compliant: number
  all_agents_ok: boolean
}

export interface SearchResults {
  users: User[]
  endpoints: Endpoint[]
}

export interface IntegrationConfig {
  id: string
  integration_type: string
  display_name: string
  is_enabled: boolean
  status: 'unconfigured' | 'connected' | 'error'
  last_sync: string | null
  last_error: string | null
  records_synced: string | null
  credentials_configured: boolean
}

export interface IntegrationCredentials {
  // JumpCloud
  api_key?: string
  // SentinelOne
  console_url?: string
  // Symantec DLP
  db_host?: string
  db_port?: number
  db_name?: string
  db_user?: string
  db_password?: string
  db_type?: string
  // Google Workspace
  service_account_json?: string
  admin_email?: string
  // HiBob
  service_user_id?: string
  service_user_token?: string
}
