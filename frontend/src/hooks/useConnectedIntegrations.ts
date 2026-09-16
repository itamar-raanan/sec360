import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'

import { fetchIntegrations } from '../api/integrations'

export function useConnectedIntegrations() {
  const query = useQuery({
    queryKey: ['integrations'],
    queryFn: fetchIntegrations,
    staleTime: 15_000,
    refetchInterval: 30_000,
  })

  const connected = useMemo(
    () => new Set(
      (query.data ?? [])
        .filter(item => item.is_enabled && item.status === 'connected')
        .map(item => item.integration_type),
    ),
    [query.data],
  )

  // Product visibility should survive a temporary health-check or sync error.
  // `connected` remains the source of truth for live features and freshness;
  // `configured` describes products the administrator intentionally enabled.
  const configured = useMemo(
    () => new Set(
      (query.data ?? [])
        .filter(item => item.is_enabled && item.credentials_configured)
        .map(item => item.integration_type),
    ),
    [query.data],
  )

  const features = useMemo(
    () => new Set(
      (query.data ?? [])
        .filter(item => item.is_enabled && item.status === 'connected')
        .flatMap(item => item.available_features ?? []),
    ),
    [query.data],
  )

  return { ...query, connected, configured, features }
}
