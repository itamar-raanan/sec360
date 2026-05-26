import React from 'react'
import { Minus, X, Monitor, User } from 'lucide-react'
import { usePanelStore, type FloatingPanel } from '../store/panels'
import { EndpointDetailPanel } from './panels/EndpointDetailPanel'
import { UserDetailPanel } from './panels/UserDetailPanel'

const PANEL_WIDTH     = 460
const PANEL_WIDTH_MIN = 200   // narrow tab when minimized
const PANEL_HEIGHT    = 640
const HEADER_H_OPEN   = 40
const HEADER_H_MIN    = 28

function PanelWindow({ panel }: { panel: FloatingPanel }) {
  const { closePanel, toggleMinimize } = usePanelStore()
  const Icon = panel.type === 'endpoint' ? Monitor : User
  const w = panel.minimized ? PANEL_WIDTH_MIN : PANEL_WIDTH
  const h = panel.minimized ? HEADER_H_MIN    : PANEL_HEIGHT

  return (
    <div
      style={{
        width: w,
        height: h,
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        background: 'var(--surface-1)',
        border: '1px solid var(--border-lit)',
        borderBottom: 'none',
        borderRadius: panel.minimized ? '8px 8px 0 0' : '14px 14px 0 0',
        boxShadow: '0 -8px 40px rgba(0,0,0,0.55), 0 0 0 1px var(--hover-1)',
        overflow: 'hidden',
        transition: 'width 200ms cubic-bezier(0.4,0,0.2,1), height 200ms cubic-bezier(0.4,0,0.2,1), border-radius 200ms cubic-bezier(0.4,0,0.2,1)',
        pointerEvents: 'auto',
      }}
    >
      {/* Panel header — click to toggle minimize */}
      <div
        className="flex items-center gap-2 px-3 flex-shrink-0 cursor-pointer select-none"
        style={{
          height: panel.minimized ? HEADER_H_MIN : HEADER_H_OPEN,
          borderBottom: panel.minimized ? 'none' : '1px solid var(--border)',
          background: panel.minimized ? 'var(--surface-2)' : 'var(--surface-1)',
          transition: 'background-color 150ms ease',
        }}
        onClick={() => toggleMinimize(panel.id)}
        onMouseEnter={e => { if (!panel.minimized) return; (e.currentTarget as HTMLDivElement).style.background = 'var(--surface-3)' }}
        onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = panel.minimized ? 'var(--surface-2)' : 'var(--surface-1)' }}
      >
        <div className="w-4 h-4 rounded flex items-center justify-center flex-shrink-0"
          style={{ background: 'var(--accent-dim)' }}>
          <Icon size={10} style={{ color: 'var(--accent)' }} />
        </div>
        <span className="text-white flex-1 truncate" style={{ fontSize: panel.minimized ? 11 : 12, fontWeight: 500 }}>{panel.title}</span>

        {/* action buttons */}
        <button
          onClick={e => { e.stopPropagation(); toggleMinimize(panel.id) }}
          className="flex items-center justify-center rounded flex-shrink-0"
          style={{ width: 18, height: 18, color: 'var(--text-4)', transition: 'color 120ms ease, background-color 120ms ease' }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--text-2)'; e.currentTarget.style.background = 'var(--border)' }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-4)'; e.currentTarget.style.background = 'transparent' }}
          title={panel.minimized ? 'Restore' : 'Minimize'}
        >
          <Minus size={10} />
        </button>
        <button
          onClick={e => { e.stopPropagation(); closePanel(panel.id) }}
          className="flex items-center justify-center rounded flex-shrink-0"
          style={{ width: 18, height: 18, color: 'var(--text-4)', transition: 'color 120ms ease, background-color 120ms ease' }}
          onMouseEnter={e => { e.currentTarget.style.color = '#f87171'; e.currentTarget.style.background = 'rgba(239,68,68,0.08)' }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-4)'; e.currentTarget.style.background = 'transparent' }}
          title="Close"
        >
          <X size={10} />
        </button>
      </div>

      {/* Panel content */}
      {!panel.minimized && (
        <div className="flex-1 overflow-hidden">
          {panel.type === 'endpoint'
            ? <EndpointDetailPanel endpointId={panel.objectId} />
            : <UserDetailPanel     userId={panel.objectId} />
          }
        </div>
      )}
    </div>
  )
}

export default function FloatingPanels() {
  const { panels } = usePanelStore()
  if (panels.length === 0) return null

  return (
    <div
      className="fixed bottom-0 right-4 z-40 flex items-end gap-2"
      style={{ pointerEvents: 'none' }}
    >
      {panels.map(panel => (
        <PanelWindow key={panel.id} panel={panel} />
      ))}
    </div>
  )
}
