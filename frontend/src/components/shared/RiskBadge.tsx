import React from 'react'
import type { RiskLevel } from '../../types'

interface RiskBadgeProps {
  score?: number
  level?: RiskLevel | string
}

function scoreToLevel(score: number): RiskLevel {
  if (score <= 25) return 'low'
  if (score <= 50) return 'medium'
  if (score <= 75) return 'high'
  return 'critical'
}

const LEVEL_CONFIG: Record<RiskLevel, { label: string; dot: string; text: string; bg: string; border: string }> = {
  low:      { label: 'Low',      dot: '#10b981', text: '#4ade80', bg: 'rgba(34,197,94,0.08)',  border: 'rgba(34,197,94,0.2)' },
  medium:   { label: 'Medium',   dot: '#eab308', text: '#facc15', bg: 'rgba(234,179,8,0.08)',  border: 'rgba(234,179,8,0.2)' },
  high:     { label: 'High',     dot: '#f97316', text: '#fb923c', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.2)' },
  critical: { label: 'Critical', dot: '#ef4444', text: '#f87171', bg: 'rgba(239,68,68,0.08)',  border: 'rgba(239,68,68,0.2)' },
}

export default function RiskBadge({ score, level }: RiskBadgeProps) {
  const riskLevel: RiskLevel = level as RiskLevel ?? (score !== undefined ? scoreToLevel(score) : 'low')
  const cfg = LEVEL_CONFIG[riskLevel] || LEVEL_CONFIG.low

  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold"
      style={{ color: cfg.text, background: cfg.bg, border: `1px solid ${cfg.border}` }}
    >
      <span
        className="w-1.5 h-1.5 rounded-full flex-shrink-0"
        style={{
          backgroundColor: cfg.dot,
          animation: riskLevel === 'critical' ? 'pulse-dot 1.5s ease-in-out infinite' : undefined,
        }}
      />
      {cfg.label}
      {score !== undefined && (
        <span className="tabular-nums opacity-60 font-normal">{Math.round(score)}</span>
      )}
    </span>
  )
}
