import apiClient from './client'

export type ProviderStatus = 'queued' | 'running' | 'completed' | 'no_data' | 'not_configured' | 'unsupported' | 'awaiting_consent' | 'rate_limited' | 'timeout' | 'authentication_error' | 'failed'

export interface ProviderPreview {
  provider: string
  label: string
  enabled: boolean
  status: string
  sent_indicators: string[]
  scope: string
  capabilities: { lookup: boolean; scan: boolean; screenshot: boolean }
}

export interface InvestigationPreview {
  indicator: {
    original: string
    normalized: string
    indicator_type: 'url' | 'domain'
    exact_url: string | null
    hostname: string
    registrable_domain: string
    scan_target: string
    preview: string
    is_sensitive: boolean
    sensitive_reasons: string[]
    resolved_ips: string[]
    resolution_ms: number
  }
  providers: ProviderPreview[]
  disclosure_notice: string
  sensitive_notice: string
}

export interface ProviderResult {
  id: string
  provider: string
  label: string
  operation: string
  queried_scope: string
  queried_indicator: string
  status: ProviderStatus
  native_verdict: string | null
  native_metrics: Record<string, unknown>
  assessment: Record<string, unknown>
  findings: Array<Record<string, unknown>>
  evidence: Record<string, unknown>
  report_url: string | null
  observed_at: string | null
  fetched_at: string | null
  cache_status: string
  error_code: string | null
  error_message: string | null
  raw_response: unknown
  artifacts: Array<{ id: string; type: string; content_type: string; size_bytes: number; captured_at: string; url: string }>
  operations?: ProviderResult[]
}

export interface Investigation {
  id: string
  indicator?: InvestigationPreview['indicator'] | null
  indicator_preview: string
  indicator_type: string
  hostname: string
  registrable_domain: string
  status: string
  is_sensitive: boolean
  sensitive_reasons: string[]
  requested_by: string
  risk_score: number | null
  risk_level: string
  evidence_confidence: string
  coverage: { usable?: number; applicable?: number; label?: string }
  reasons: string[]
  provider_contributions: Array<Record<string, unknown>>
  scoring_version: string
  created_at: string
  updated_at: string
  completed_at: string | null
  providers?: ProviderResult[]
}

export const previewIndicator = async (indicator: string): Promise<InvestigationPreview> =>
  (await apiClient.post('/url-investigations/preview', { indicator })).data

export const createInvestigation = async (indicator: string, force_refresh: boolean): Promise<{ id: string; deduplicated: boolean }> =>
  (await apiClient.post('/url-investigations', { indicator, force_refresh, acknowledge_disclosure: true })).data

export const fetchInvestigation = async (id: string): Promise<Investigation> =>
  (await apiClient.get(`/url-investigations/detail/${id}`)).data

export const fetchInvestigationHistory = async (): Promise<Investigation[]> =>
  (await apiClient.get('/url-investigations', { params: { limit: 100 } })).data

export const runActiveOperation = async (id: string, provider: string, operation: 'scan' | 'screenshot') =>
  (await apiClient.post(`/url-investigations/${id}/actions/${provider}`, { operation, acknowledge_active_submission: true })).data

export const deleteInvestigation = async (id: string) => apiClient.delete(`/url-investigations/${id}`)
