import apiClient from './client'

export interface PuppetFact {
  id: string
  certname: string
  name: string
  value: unknown
  value_type: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'null'
  environment: string | null
  synced_at: string
}

export interface PuppetFactSummary {
  facts: number
  fact_names: number
  nodes: number
  last_sync: string | null
  report_statuses: Record<string, number>
}

export interface PuppetFactFacets {
  names: string[]
  environments: string[]
}

export interface PuppetFactParams {
  search?: string
  certname?: string
  name?: string
  environment?: string
  limit?: number
  offset?: number
}

export async function fetchPuppetFactSummary() {
  return (await apiClient.get<PuppetFactSummary>('/puppet-facts/summary')).data
}

export async function fetchPuppetFactFacets() {
  return (await apiClient.get<PuppetFactFacets>('/puppet-facts/facets')).data
}

export async function fetchPuppetFacts(params: PuppetFactParams) {
  const response = await apiClient.get<PuppetFact[]>('/puppet-facts', { params })
  return {
    items: response.data,
    total: Number(response.headers['x-total-count'] ?? response.data.length),
  }
}

export async function exportPuppetFacts(params: PuppetFactParams) {
  const response = await apiClient.get<Blob>('/puppet-facts/export.csv', {
    params,
    responseType: 'blob',
  })
  const url = URL.createObjectURL(response.data)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = 'puppet_facts.csv'
  anchor.click()
  URL.revokeObjectURL(url)
}
