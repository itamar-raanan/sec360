import apiClient from './client'

export type LifecycleState = 'active' | 'stale' | 'ignored' | 'decommissioned'
export type ConfidenceTier = 'high' | 'medium' | 'low'

export interface IdentityConfidence {
  score: number
  tier: ConfidenceTier
  method: 'hardware_serial' | 'directory_identity' | 'normalized_hostname' | 'source_native'
  explanation: string
  signals: string[]
  issues: string[]
  sources: string[]
  freshest_observation: string | null
}

export interface QualityEndpoint {
  id: string
  hostname: string
  serial_number: string | null
  username: string | null
  source: string | null
  last_seen: string | null
  owner: { id: string; full_name: string; email: string } | null
  lifecycle_state: LifecycleState
  lifecycle_reason: string | null
  lifecycle_changed_at: string | null
  lifecycle_changed_by: string | null
  included_in_compliance: boolean
  compliance_exclusion_reason: string | null
  confidence: IdentityConfidence
}

export interface SourceFreshness {
  integration_type: string
  display_name: string
  is_enabled: boolean
  status: string
  last_sync: string | null
  age_hours: number | null
  records_synced: string | null
}

export interface QualitySummary {
  total: number
  current_inventory: number
  lifecycle: Record<LifecycleState, number>
  confidence: Record<ConfidenceTier, number>
  unassigned: number
  duplicate_candidates: number
  source_freshness: SourceFreshness[]
  generated_at: string
}

export interface DuplicateCandidate {
  candidate_id: string
  score: number
  reasons: string[]
  left: QualityEndpoint
  right: QualityEndpoint
}

export async function fetchQualitySummary() {
  return (await apiClient.get<QualitySummary>('/data-quality/summary')).data
}

export async function fetchQualityEndpoints(params: {
  search?: string
  lifecycle?: string
  confidence?: string
  issue?: string
}) {
  const response = await apiClient.get<QualityEndpoint[]>('/data-quality/endpoints', { params })
  return { items: response.data, total: Number(response.headers['x-total-count'] || response.data.length) }
}

export async function fetchDuplicateCandidates() {
  return (await apiClient.get<{ items: DuplicateCandidate[]; total: number }>('/data-quality/duplicates')).data
}

export async function updateEndpointLifecycle(
  endpointId: string,
  state: LifecycleState,
  reason: string | null,
) {
  return (await apiClient.patch<QualityEndpoint>(`/data-quality/endpoints/${endpointId}/lifecycle`, { state, reason })).data
}
