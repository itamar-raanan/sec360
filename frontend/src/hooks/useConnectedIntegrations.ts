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

  return { ...query, connected }
}
