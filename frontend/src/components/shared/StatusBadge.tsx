import React from 'react'
import type { ComplianceStatusValue, AgentStatus } from '../../types'

interface StatusBadgeProps {
  status: ComplianceStatusValue | AgentStatus | string
}

const STATUS_CONFIG: Record<string, { label: string; tone: 'success' | 'warning' | 'danger' | 'neutral' }> = {
  compliant: { label: 'Compliant', tone: 'success' },
  partial: { label: 'Partial', tone: 'warning' },
  non_compliant: { label: 'Non-Compliant', tone: 'danger' },
  active: { label: 'Active', tone: 'success' },
  inactive: { label: 'Inactive', tone: 'danger' },
  unknown: { label: 'Unknown', tone: 'neutral' },
  on_leave: { label: 'On Leave', tone: 'neutral' },
}

export default function StatusBadge({ status }: StatusBadgeProps) {
  const config = STATUS_CONFIG[status] || { label: status, tone: 'neutral' as const }
  return (
    <span className="status-badge" data-tone={config.tone}>
      {config.label}
    </span>
  )
}
