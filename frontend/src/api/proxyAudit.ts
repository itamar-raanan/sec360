import apiClient from './client'

export interface ProxyAuditConnection {
  configured: boolean
  base_url: string
  username: string
  verify_ssl: boolean
  timeout_seconds: number
  status: 'unconfigured' | 'configured' | 'connected' | 'error'
  last_tested_at: string | null
  last_sync: string | null
  last_error: string | null
  records_synced: number
  sync_in_progress: boolean
}

export interface ProxyAuditConnectionInput {
  base_url: string
  username: string
  password: string
  verify_ssl: boolean
  timeout_seconds: number
}

export interface ProxyAuditEvent {
  id: string
  policy_uuid: string
  policy_name: string
  object_type: 'policy' | 'shared_object'
  author: string | null
  revision_date: string
  revision_number: string
  comment: string | null
  change_summary: string
  additions: number
  deletions: number
  synced_at: string
  diff_text?: string
}

export interface ProxyAuditSummary {
  revisions: number
  objects: number
  shared_revisions: number
  authors: number
  last_change: string | null
}

export interface ProxyAuditParams {
  search?: string
  object_type?: 'policy' | 'shared_object'
  author?: string
  limit?: number
  offset?: number
}

export function fetchProxyAuditConnection() {
  return apiClient.get<ProxyAuditConnection>('/proxy-audit/connection').then(response => response.data)
}

export function saveProxyAuditConnection(data: ProxyAuditConnectionInput) {
  return apiClient.put<ProxyAuditConnection>('/proxy-audit/connection', data).then(response => response.data)
}

export function testProxyAuditConnection(data: ProxyAuditConnectionInput) {
  return apiClient.post<{ success: boolean; message: string }>('/proxy-audit/connection/test', data)
    .then(response => response.data)
}

export function syncProxyAudit() {
  return apiClient.post<{ started: boolean; message: string }>('/proxy-audit/sync')
    .then(response => response.data)
}

export function fetchProxyAuditSummary() {
  return apiClient.get<ProxyAuditSummary>('/proxy-audit/summary').then(response => response.data)
}

export function fetchProxyAuditEvents(params: ProxyAuditParams = {}) {
  return apiClient.get<ProxyAuditEvent[]>('/proxy-audit', { params }).then(response => ({
    items: response.data,
    total: Number(response.headers['x-total-count'] || response.data.length),
  }))
}

export function fetchProxyAuditEvent(eventId: string) {
  return apiClient.get<ProxyAuditEvent>(`/proxy-audit/${eventId}`).then(response => response.data)
}
