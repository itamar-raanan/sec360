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
  hostname: string
  ip_address: string | null
  endpoint_id: string | null
  os_name: string | null
  profile: string | null
  benchmark_name: string
  benchmark_version: string | null
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
