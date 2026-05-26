import apiClient from './client'
import type { Endpoint, SecurityAgent } from '../types'

interface EndpointListParams {
  compliance_status?: string
  agent_status?: string
  os_filter?: string
  search?: string
  has_s1?: boolean
  has_dlp?: boolean
  unassigned?: boolean
  active_only?: boolean
  limit?: number
  offset?: number
}

export async function fetchEndpoints(params: EndpointListParams = {}): Promise<{ data: Endpoint[]; total: number }> {
  const res = await apiClient.get<Endpoint[]>('/endpoints', { params })
  return {
    data: res.data,
    total: parseInt(res.headers['x-total-count'] || '0', 10),
  }
}

export async function fetchEndpoint(id: string): Promise<Endpoint> {
  const res = await apiClient.get<Endpoint>(`/endpoints/${id}`)
  return res.data
}

export async function fetchEndpointAgents(id: string): Promise<SecurityAgent[]> {
  const res = await apiClient.get<SecurityAgent[]>(`/endpoints/${id}/agents`)
  return res.data
}
