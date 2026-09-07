import apiClient from './client'

export type VulnerabilitySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'

export interface ApplicationVulnerability {
  id: string
  sentinelone_id: string
  sentinelone_endpoint_id: string | null
  application: string
  application_name: string
  application_vendor: string | null
  application_version: string | null
  cve_id: string
  cvss_version: string | null
  nvd_cvss_version: string | null
  nvd_base_score: number | null
  risk_score: number | null
  severity: VulnerabilitySeverity | null
  endpoint_name: string
  endpoint_type: string | null
  os_type: string | null
  days_detected: number | null
  detection_date: string | null
  published_date: string | null
  last_scan_date: string | null
  last_scan_result: string | null
  exploit_code_maturity: string | null
  remediation_level: string | null
  report_confidence: string | null
  mitigation_status: string | null
  mitigation_status_change_time: string | null
  mitigation_status_changed_by: string | null
  mitigation_status_reason: string | null
  status: string | null
  mark_type: string | null
  marked_by: string | null
  marked_date: string | null
  reason: string | null
  synced_at: string
  endpoint: { id: string; hostname: string; owner_name: string | null; owner_email: string | null } | null
  raw_json?: Record<string, unknown>
}

export interface VulnerabilitySummary {
  total: number
  unique_cves: number
  applications: number
  endpoints: number
  severity: { critical: number; high: number; medium: number; low: number }
  exploit_available: number
  not_mitigated: number
  last_sync: string | null
  top_applications: Array<{ name: string; findings: number; cves: number; max_cvss: number | null }>
}

export interface VulnerabilityFacets {
  severities: string[]
  statuses: string[]
  mitigations: string[]
  os_types: string[]
}

export interface VulnerabilityParams {
  search?: string
  severity?: string
  status?: string
  mitigation?: string
  exploit?: boolean
  os_type?: string
  sort?: string
  order?: 'asc' | 'desc'
  limit?: number
  offset?: number
}

export async function fetchVulnerabilitySummary() {
  return (await apiClient.get<VulnerabilitySummary>('/application-vulnerabilities/summary')).data
}

export async function fetchVulnerabilityFacets() {
  return (await apiClient.get<VulnerabilityFacets>('/application-vulnerabilities/facets')).data
}

export async function fetchApplicationVulnerabilities(params: VulnerabilityParams) {
  const response = await apiClient.get<ApplicationVulnerability[]>('/application-vulnerabilities', { params })
  return { items: response.data, total: Number(response.headers['x-total-count'] || response.data.length) }
}

export async function fetchApplicationVulnerability(id: string) {
  return (await apiClient.get<ApplicationVulnerability>(`/application-vulnerabilities/${id}`)).data
}

export async function exportApplicationVulnerabilities(params: VulnerabilityParams) {
  const response = await apiClient.get<Blob>('/application-vulnerabilities/export.csv', { params, responseType: 'blob' })
  const url = URL.createObjectURL(response.data)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = 'sentinelone_application_vulnerabilities.csv'
  anchor.click()
  URL.revokeObjectURL(url)
}
