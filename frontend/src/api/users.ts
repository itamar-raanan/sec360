import apiClient from './client'
import type { User, UserDetail, Endpoint, ActivityEvent } from '../types'

interface UserListParams {
  department?: string
  employment_status?: string
  risk_level?: string
  search?: string
  limit?: number
  offset?: number
}

export async function fetchUsers(params: UserListParams = {}): Promise<{ data: User[]; total: number }> {
  const res = await apiClient.get<User[]>('/users', { params })
  return {
    data: res.data,
    total: parseInt(res.headers['x-total-count'] || '0', 10),
  }
}

export async function fetchUser(id: string): Promise<UserDetail> {
  const res = await apiClient.get<UserDetail>(`/users/${id}`)
  return res.data
}

export async function fetchUserTimeline(id: string, days = 7): Promise<ActivityEvent[]> {
  const res = await apiClient.get<ActivityEvent[]>(`/users/${id}/timeline`, { params: { days } })
  return res.data
}

export async function fetchUserDevices(id: string): Promise<Endpoint[]> {
  const res = await apiClient.get<Endpoint[]>(`/users/${id}/devices`)
  return res.data
}
