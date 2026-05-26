import apiClient from './client'
import type { IntegrationConfig } from '../types'

export const fetchIntegrations = async (): Promise<IntegrationConfig[]> => {
  const { data } = await apiClient.get('/integrations')
  return data
}

export const saveIntegrationCredentials = async (
  type: string,
  credentials: Record<string, unknown>,
  is_enabled: boolean = true
): Promise<IntegrationConfig> => {
  const { data } = await apiClient.put(`/integrations/${type}`, { credentials, is_enabled })
  return data
}

export const testIntegration = async (type: string): Promise<{ success: boolean; message: string }> => {
  const { data } = await apiClient.post(`/integrations/${type}/test`)
  return data
}

export const syncIntegration = async (type: string): Promise<{ success: boolean; message: string; records_synced?: number }> => {
  const { data } = await apiClient.post(`/integrations/${type}/sync`)
  return data
}

export const deleteIntegrationCredentials = async (type: string): Promise<void> => {
  await apiClient.delete(`/integrations/${type}/credentials`)
}

export const createCustomIntegration = async (body: {
  integration_type: string
  display_name: string
  credentials: Record<string, unknown>
  is_enabled?: boolean
}): Promise<IntegrationConfig> => {
  const { data } = await apiClient.post('/integrations', body)
  return data
}

export const deleteIntegration = async (type: string): Promise<void> => {
  await apiClient.delete(`/integrations/${type}`)
}
