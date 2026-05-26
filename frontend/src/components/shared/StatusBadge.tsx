import React from 'react'
import type { ComplianceStatusValue, AgentStatus } from '../../types'

interface StatusBadgeProps {
  status: ComplianceStatusValue | AgentStatus | string
}

const STATUS_CONFIG: Record<string, { label: string; className: string }> = {
  compliant: { label: 'Compliant', className: 'bg-green-500/15 text-green-400 border-green-500/30' },
  partial: { label: 'Partial', className: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' },
  non_compliant: { label: 'Non-Compliant', className: 'bg-red-500/15 text-red-400 border-red-500/30' },
  active: { label: 'Active', className: 'bg-green-500/15 text-green-400 border-green-500/30' },
  inactive: { label: 'Inactive', className: 'bg-red-500/15 text-red-400 border-red-500/30' },
  unknown: { label: 'Unknown', className: 'bg-gray-500/15 text-gray-400 border-gray-500/30' },
  on_leave: { label: 'On Leave', className: 'bg-fuchsia-500/10 text-fuchsia-400 border-fuchsia-500/30' },
}

export default function StatusBadge({ status }: StatusBadgeProps) {
  const config = STATUS_CONFIG[status] || { label: status, className: 'bg-gray-500/15 text-gray-400 border-gray-500/30' }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded border text-xs font-medium ${config.className}`}>
      {config.label}
    </span>
  )
}
