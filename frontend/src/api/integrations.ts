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

export const importActiveDirectoryCsv = async (
  file: File,
  onProgress?: (percent: number) => void,
): Promise<{
  success: boolean
  message: string
  users: number
  linked_endpoints: number
  rejected_rows: number
}> => {
  // The shared client defaults to application/json. postForm explicitly sets
  // multipart/form-data and lets Axios/browser attach the required boundary,
  // otherwise FastAPI reports the file field as missing (HTTP 422).
  const { data } = await apiClient.postForm('/integrations/active_directory/import', { file }, {
    onUploadProgress: event => {
      if (event.total && onProgress) {
        onProgress(Math.min(100, Math.round((event.loaded / event.total) * 100)))
      }
    },
  })
  return data
}
