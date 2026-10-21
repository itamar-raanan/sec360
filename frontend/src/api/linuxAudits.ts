import apiClient from './client'

export interface LinuxAuditResult {
  id?: string
  title?: string
  section?: string
  assessment?: string
  profiles?: string[]
  status?: string
  expected?: string
  expected_evidence?: string
  check_type?: string
  check_commands?: string[]
  how_to_check?: string
  review_guidance?: string
  remediation?: string
  actual?: unknown
  evidence_text?: unknown
  evidence?: unknown
  [key: string]: unknown
}

export interface LinuxAuditReport {
  id: string
  schema_version: string | null
  hostname: string
  fqdn: string | null
  ip_address: string | null
  ip_addresses: string[]
  endpoint_id: string | null
  os_name: string | null
  kernel: string | null
  architecture: string | null
  virtualization_type: string | null
  machine_id_hash: string | null
  profile: string | null
  benchmark_name: string
  benchmark_version: string | null
  audit_tool_version: string | null
  audit_tool_git_commit: string | null
  generated_at: string
  total_count: number
  pass_count: number
  fail_count: number
  review_count: number
  excluded_count: number
  error_count: number
  pass_rate: number
  filename: string
  uploaded_by_email: string
  uploaded_at: string
  results?: LinuxAuditResult[]
  benchmark?: Record<string, unknown>
}

export interface LinuxAuditSummary {
  reports: number
  servers: number
  last_audit: string | null
  failed_controls: number
  error_controls: number
}

export interface LinuxAuditParams {
  search?: string
  profile?: string
  result?: 'pass' | 'attention'
  limit?: number
  offset?: number
}

export interface LinuxAuditIngestToken {
  id: string
  name: string
  token_prefix: string
  created_by_email: string
  created_at: string
  last_used_at: string | null
  last_used_ip: string | null
  revoked_at: string | null
  token?: string
}

export async function fetchLinuxAudits(params: LinuxAuditParams = {}) {
  const response = await apiClient.get<LinuxAuditReport[]>('/linux-audits', { params })
  return {
    items: response.data,
    total: Number(response.headers['x-total-count'] || response.data.length),
  }
}

export async function fetchLinuxAuditSummary() {
  return apiClient.get<LinuxAuditSummary>('/linux-audits/summary').then(response => response.data)
}

export async function fetchLinuxAudit(reportId: string) {
  return apiClient.get<LinuxAuditReport>(`/linux-audits/${reportId}`).then(response => response.data)
}

export async function uploadLinuxAudit(file: File, ipAddress?: string) {
  const form = new FormData()
  form.append('file', file)
  if (ipAddress?.trim()) form.append('ip_address', ipAddress.trim())
  return apiClient.post<LinuxAuditReport>('/linux-audits/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }).then(response => response.data)
}

export async function fetchLinuxAuditIngestTokens() {
  return apiClient.get<LinuxAuditIngestToken[]>('/linux-audits/ingest-tokens')
    .then(response => response.data)
}

export async function createLinuxAuditIngestToken(name: string) {
  return apiClient.post<LinuxAuditIngestToken>('/linux-audits/ingest-tokens', { name })
    .then(response => response.data)
}

export async function revokeLinuxAuditIngestToken(tokenId: string) {
  return apiClient.delete(`/linux-audits/ingest-tokens/${tokenId}`)
    .then(response => response.data as { ok: boolean })
}
