import { apiClient } from './client'

export interface AIInsight {
  id: string
  insight_type: string
  severity: 'info' | 'warning' | 'high' | 'critical'
  title: string
  description: string
  user_id: string | null
  user?: { id: string; full_name: string; email: string } | null
  evidence: Record<string, unknown> | null
  event_ids: string[] | null
  is_dismissed: boolean
  is_new: boolean
  created_at: string
  expires_at: string | null
}

export interface InsightStats {
  total: number
  critical: number
  high: number
  warning: number
  info: number
  new_count: number
}

export interface FetchInsightsParams {
  severity?: string
  insight_type?: string
  user_id?: string
  show_dismissed?: boolean
  limit?: number
  offset?: number
}

export async function fetchInsights(
  params: FetchInsightsParams = {}
): Promise<{ data: AIInsight[]; total: number }> {
  const res = await apiClient.get<{ data: AIInsight[]; total: number }>('/ai/insights', { params })
  return res.data
}

export async function fetchInsightStats(): Promise<InsightStats> {
  const res = await apiClient.get<InsightStats>('/ai/insights/stats')
  return res.data
}

export async function dismissInsight(id: string): Promise<AIInsight> {
  const res = await apiClient.post<AIInsight>(`/ai/insights/${id}/dismiss`)
  return res.data
}

export async function undismissInsight(id: string): Promise<AIInsight> {
  const res = await apiClient.post<AIInsight>(`/ai/insights/${id}/undismiss`)
  return res.data
}

export async function runAnalysis(): Promise<{ insights_created: number; insights_total: number }> {
  const res = await apiClient.post<{ insights_created: number; insights_total: number }>('/ai/analyze')
  return res.data
}

export async function explainEvent(eventId: string): Promise<{ explanation: string }> {
  const res = await apiClient.post<{ explanation: string }>('/ai/explain', { event_id: eventId })
  return res.data
}
