import apiClient from './client'
import type { User, Endpoint, RiskSummary } from '../types'

export async function fetchRiskyUsers(params: { min_score?: number; limit?: number; offset?: number } = {}): Promise<{ data: User[]; total: number }> {
  const res = await apiClient.get<User[]>('/risk/users', { params })
  return {
    data: res.data,
    total: parseInt(res.headers['x-total-count'] || '0', 10),
  }
}

export async function fetchRiskyEndpoints(params: { min_score?: number; limit?: number; offset?: number } = {}): Promise<{ data: Endpoint[]; total: number }> {
  const res = await apiClient.get<Endpoint[]>('/risk/endpoints', { params })
  return {
    data: res.data,
    total: parseInt(res.headers['x-total-count'] || '0', 10),
  }
}

export async function fetchRiskSummary(): Promise<RiskSummary> {
  const res = await apiClient.get<RiskSummary>('/risk/summary')
  return res.data
}
