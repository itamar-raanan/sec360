import apiClient from './client'
import type { ActivityEvent } from '../types'

interface ActivityListParams {
  event_type?: string
  source?: string
  user_id?: string
  country?: string
  is_suspicious?: boolean
  date_from?: string
  date_to?: string
  limit?: number
  offset?: number
}

export async function fetchActivity(params: ActivityListParams = {}): Promise<{ data: ActivityEvent[]; total: number }> {
  const res = await apiClient.get<ActivityEvent[]>('/activity', { params })
  return {
    data: res.data,
    total: parseInt(res.headers['x-total-count'] || '0', 10),
  }
}

export async function fetchSuspiciousActivity(limit = 50): Promise<ActivityEvent[]> {
  const res = await apiClient.get<ActivityEvent[]>('/activity/suspicious', { params: { limit } })
  return res.data
}
