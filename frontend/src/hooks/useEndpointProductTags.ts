import { useQuery } from '@tanstack/react-query'
import apiClient from '../api/client'


export type EndpointProductTag = 'S1' | 'DLP' | 'WSS'
export const DEFAULT_ENDPOINT_PRODUCT_TAGS: EndpointProductTag[] = ['S1', 'DLP', 'WSS']

export function useEndpointProductTags() {
  const query = useQuery<{ tags: EndpointProductTag[] }>({
    queryKey: ['endpoint-product-tags'],
    queryFn: async () => (await apiClient.get('/settings/endpoint-product-tags')).data,
    staleTime: 5 * 60 * 1000,
  })
  const tags = query.data?.tags ?? DEFAULT_ENDPOINT_PRODUCT_TAGS
  return {
    ...query,
    tags,
    enabled: (tag: EndpointProductTag) => tags.includes(tag),
  }
}
