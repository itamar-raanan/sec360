import apiClient from './client'

export type PuppetFactValueType = 'string' | 'number' | 'boolean' | 'array' | 'object' | 'null'
export type PuppetFactSort = 'certname' | 'name' | 'value_type' | 'environment' | 'synced_at'
export type SortOrder = 'asc' | 'desc'

export interface PuppetFact {
  id: string
  certname: string
  name: string
  value: unknown
  value_type: PuppetFactValueType
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
  value_types: PuppetFactValueType[]
}

export interface PuppetFactParams {
  search?: string
  certname?: string
  names?: string
  environment?: string
  value_types?: string
  favorites_only?: boolean
  sort?: PuppetFactSort
  order?: SortOrder
  limit?: number
  offset?: number
}

export interface PuppetFactViewDefinition {
  search: string
  certname: string
  names: string[]
  environment: string
  value_types: PuppetFactValueType[]
  favorites_only: boolean
  page_size: 25 | 50 | 100
  sort: PuppetFactSort
  order: SortOrder
}

export interface PuppetFactFavorite {
  id: string
  fact_name: string
  created_at: string
}

export interface PuppetFactSavedView {
  id: string
  name: string
  definition: PuppetFactViewDefinition
  is_default: boolean
  created_at: string
  updated_at: string
}

export type SavedViewPayload = Pick<PuppetFactSavedView, 'name' | 'definition' | 'is_default'>

export async function fetchPuppetFactSummary(params: PuppetFactParams = {}) {
  return (await apiClient.get<PuppetFactSummary>('/puppet-facts/summary', { params })).data
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

export async function fetchPuppetFactFavorites() {
  return (await apiClient.get<PuppetFactFavorite[]>('/puppet-facts/favorites')).data
}

export async function createPuppetFactFavorite(factName: string) {
  return (await apiClient.post<PuppetFactFavorite>('/puppet-facts/favorites', { fact_name: factName })).data
}

export async function deletePuppetFactFavorite(id: string) {
  await apiClient.delete(`/puppet-facts/favorites/${encodeURIComponent(id)}`)
}

export async function fetchPuppetFactSavedViews() {
  return (await apiClient.get<PuppetFactSavedView[]>('/puppet-facts/saved-views')).data
}

export async function createPuppetFactSavedView(payload: SavedViewPayload) {
  return (await apiClient.post<PuppetFactSavedView>('/puppet-facts/saved-views', payload)).data
}

export async function updatePuppetFactSavedView(id: string, payload: SavedViewPayload) {
  return (await apiClient.put<PuppetFactSavedView>(`/puppet-facts/saved-views/${encodeURIComponent(id)}`, payload)).data
}

export async function deletePuppetFactSavedView(id: string) {
  await apiClient.delete(`/puppet-facts/saved-views/${encodeURIComponent(id)}`)
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
