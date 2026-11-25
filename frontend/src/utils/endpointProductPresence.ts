import type { Endpoint } from '../types'

const SECURITY_PRODUCTS: Record<string, string> = {
  sentinelone: 'sentinelone',
  symantec_dlp: 'symantec',
  symantec_wss: 'symantec_wss',
}

// Inventory presence is independent of connectivity and Compliance scope.
// Excluded devices still have the products that their collectors reported.
export function endpointHasProduct(
  endpoint: Pick<Endpoint, 'agents' | 'puppet_managed'>,
  key: string,
): boolean {
  if (key === 'puppet') return Boolean(endpoint.puppet_managed)
  const product = SECURITY_PRODUCTS[key]
  return Boolean(product && endpoint.agents?.some(agent => agent.product_name === product))
}
