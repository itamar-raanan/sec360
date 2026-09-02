import apiClient from './client'

export interface DlpPolicyExclusion {
  object_id: string | number | null
  object_name: string | null
  object_description: string | null
  object_status: string | null
  rule_type: string | number | null
  used_as: 'SENDER' | 'RECIPIENT' | 'UNUSED' | string
  policy_id: string | number | null
  policy_name: string | null
  policy_active_status: string | number | null
  policy_record_status: string | null
  user_patterns: string | null
  ip_addresses: string | null
  url_domains: string | null
  personal_email_breadth: string | number | null
  personal_email_excluded_domains: string | null
  personal_email_max_recipients: string | number | null
  modified_date: string | null
  modified_by_id: string | number | null
  object_uuid: string | null
}

export interface DlpPolicySearchResponse {
  items: DlpPolicyExclusion[]
  row_count: number
  max_rows: number
  truncated: boolean
  query_duration_ms: number
  source_refreshed_at: string
  integration_status: string
}

export async function fetchDlpPolicyExclusions(): Promise<DlpPolicySearchResponse> {
  const response = await apiClient.get<DlpPolicySearchResponse>('/dlp-policy-search')
  return response.data
}
