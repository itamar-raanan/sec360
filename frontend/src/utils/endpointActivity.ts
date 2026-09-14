import type { Endpoint } from '../types'
import type { EndpointProductTag } from '../hooks/useEndpointProductTags'

interface EndpointSourceDefinition {
  integrationType: string
  label: string
  shortLabel: string
  productTag?: EndpointProductTag
}

export interface EndpointActivitySource extends EndpointSourceDefinition {
  lastSeen: string
}

const ENDPOINT_SOURCES: Record<string, EndpointSourceDefinition> = {
  jumpcloud: { integrationType: 'jumpcloud', label: 'JumpCloud', shortLabel: 'JC' },
  sentinelone: { integrationType: 'sentinelone', label: 'SentinelOne', shortLabel: 'S1', productTag: 'S1' },
  symantec: { integrationType: 'symantec_dlp', label: 'DLP', shortLabel: 'DLP', productTag: 'DLP' },
  active_directory: { integrationType: 'active_directory', label: 'Active Directory', shortLabel: 'AD' },
  puppet: { integrationType: 'puppet', label: 'Puppet', shortLabel: 'Puppet' },
}

export function primaryEndpointActivity(
  ep: Endpoint,
  connected: ReadonlySet<string>,
  enabledProductTags: readonly EndpointProductTag[],
): EndpointActivitySource | null {
  if (!ep.source || !ep.last_seen) return null
  const definition = ENDPOINT_SOURCES[ep.source]
  if (!definition || !connected.has(definition.integrationType)) return null
  if (definition.productTag && !enabledProductTags.includes(definition.productTag)) return null
  return { ...definition, lastSeen: ep.last_seen }
}

export function connectedLastActivity(
  ep: Endpoint,
  connected: ReadonlySet<string>,
  enabledProductTags: readonly EndpointProductTag[],
): string | null {
  const primary = primaryEndpointActivity(ep, connected, enabledProductTags)
  const observations = primary ? [primary.lastSeen] : []

  for (const agent of ep.agents ?? []) {
    const sourceConnected = (
      (agent.product_name === 'sentinelone' && connected.has('sentinelone') && enabledProductTags.includes('S1'))
      || (agent.product_name === 'symantec' && connected.has('symantec_dlp') && enabledProductTags.includes('DLP'))
      // WSS presence is discovered through the SentinelOne integration.
      || (agent.product_name === 'symantec_wss' && connected.has('sentinelone') && enabledProductTags.includes('WSS'))
    )
    if (sourceConnected && agent.last_seen) observations.push(agent.last_seen)
  }

  return observations.reduce<string | null>((latest, current) => (
    !latest || new Date(current).getTime() > new Date(latest).getTime() ? current : latest
  ), null)
}
