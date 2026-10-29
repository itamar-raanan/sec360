import React, { useEffect, useMemo, useRef, useState } from 'react'
import { ChevronLeft, ChevronRight, Copy, ExternalLink, Monitor, User, X } from 'lucide-react'
import { useLocation, useNavigate } from 'react-router-dom'
import { usePanelStore, type EntityPanel, type PanelType } from '../store/panels'
import { EndpointDetailPanel } from './panels/EndpointDetailPanel'
import { UserDetailPanel } from './panels/UserDetailPanel'

const ENTITY_TYPES = new Set<PanelType>(['endpoint', 'user'])

function isTypingTarget(target: EventTarget | null) {
  if (!(target instanceof HTMLElement)) return false
  return Boolean(target.closest('input, textarea, select, [contenteditable="true"]'))
}

function EntityDrawerContent({ panel, onDismiss }: { panel: EntityPanel; onDismiss: () => void }) {
  const navigate = useNavigate()
  const { movePanel, setPanelTitle } = usePanelStore()
  const [copied, setCopied] = useState(false)
  const closeButtonRef = useRef<HTMLButtonElement>(null)
  const sequenceIndex = panel.sequence?.findIndex(item => item.id === panel.objectId) ?? -1
  const canMoveBack = sequenceIndex > 0
  const canMoveForward = Boolean(panel.sequence && sequenceIndex >= 0 && sequenceIndex < panel.sequence.length - 1)
  const Icon = panel.type === 'endpoint' ? Monitor : User
  const typeLabel = panel.type === 'endpoint' ? 'Endpoint' : 'User'
  const handleTitleChange = React.useCallback((title: string) => {
    setPanelTitle(panel.id, title)
  }, [panel.id, setPanelTitle])

  useEffect(() => {
    closeButtonRef.current?.focus({ preventScroll: true })
  }, [panel.id])

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1400)
    } catch {
      setCopied(false)
    }
  }

  const openCollection = () => {
    navigate(panel.type === 'endpoint' ? '/endpoints' : '/users')
    onDismiss()
  }

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onDismiss()
        return
      }
      if (isTypingTarget(event.target)) return
      if (event.key.toLowerCase() === 'c' && !event.metaKey && !event.ctrlKey && !event.altKey) {
        event.preventDefault()
        void copyLink()
      }
      if ((event.key === 'j' || event.key === ']') && canMoveForward) {
        event.preventDefault()
        movePanel(1)
      }
      if ((event.key === 'k' || event.key === '[') && canMoveBack) {
        event.preventDefault()
        movePanel(-1)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [canMoveBack, canMoveForward, movePanel, onDismiss])

  return (
    <aside
      className="entity-drawer"
      role="dialog"
      aria-modal="false"
      aria-label={`${typeLabel} details: ${panel.title}`}
    >
      <header className="entity-drawer-header">
        <div className="entity-drawer-identity">
          <span className="entity-drawer-icon"><Icon size={16} /></span>
          <div className="min-w-0">
            <p className="ui-context">{typeLabel} workspace</p>
            <h2 className="truncate">{panel.title}</h2>
          </div>
        </div>

        <div className="entity-drawer-actions">
          {panel.sequence && panel.sequence.length > 1 && (
            <div className="entity-drawer-sequence" aria-label={`${typeLabel} navigation`}>
              <button type="button" onClick={() => movePanel(-1)} disabled={!canMoveBack} aria-label={`Previous ${typeLabel.toLowerCase()}`} title="Previous (K or [)">
                <ChevronLeft size={15} />
              </button>
              <span>{sequenceIndex + 1} / {panel.sequence.length}</span>
              <button type="button" onClick={() => movePanel(1)} disabled={!canMoveForward} aria-label={`Next ${typeLabel.toLowerCase()}`} title="Next (J or ])">
                <ChevronRight size={15} />
              </button>
            </div>
          )}
          <button type="button" className="ui-icon-button" onClick={() => void copyLink()} aria-label="Copy direct link" title="Copy direct link (C)">
            <Copy size={15} />
            <span className="entity-drawer-action-label">{copied ? 'Copied' : 'Copy link'}</span>
          </button>
          <button type="button" className="ui-icon-button" onClick={openCollection} aria-label={`Open ${typeLabel.toLowerCase()} list`} title={`Open ${typeLabel.toLowerCase()} list`}>
            <ExternalLink size={15} />
          </button>
          <button ref={closeButtonRef} type="button" className="ui-icon-button" onClick={onDismiss} aria-label="Close details" title="Close (Esc)">
            <X size={16} />
          </button>
        </div>
      </header>

      <div key={panel.id} className="entity-drawer-body">
        {panel.type === 'endpoint'
          ? <EndpointDetailPanel endpointId={panel.objectId} onTitleChange={handleTitleChange} />
          : <UserDetailPanel userId={panel.objectId} onTitleChange={handleTitleChange} />}
      </div>

      <footer className="entity-drawer-shortcuts" aria-hidden="true">
        <span><kbd>Esc</kbd> close</span>
        <span><kbd>C</kbd> copy link</span>
        {panel.sequence && panel.sequence.length > 1 && <span><kbd>J</kbd><kbd>K</kbd> navigate</span>}
      </footer>
    </aside>
  )
}

export default function EntityDrawer() {
  const location = useLocation()
  const { panels, closePanel, syncPanelFromUrl } = usePanelStore()
  const [closing, setClosing] = useState(false)
  const closeTimer = useRef<number | null>(null)
  const previousFocus = useRef<HTMLElement | null>(null)
  const panel = panels[0]
  const panelId = panel?.id

  const urlEntity = useMemo(() => {
    const params = new URLSearchParams(location.search)
    const type = params.get('entity')
    const objectId = params.get('entityId')
    return {
      type: type && ENTITY_TYPES.has(type as PanelType) ? type as PanelType : null,
      objectId: objectId || undefined,
    }
  }, [location.search])

  useEffect(() => {
    syncPanelFromUrl(urlEntity.type, urlEntity.objectId)
  }, [syncPanelFromUrl, urlEntity.objectId, urlEntity.type])

  useEffect(() => () => {
    if (closeTimer.current !== null) window.clearTimeout(closeTimer.current)
  }, [])

  useEffect(() => {
    if (panelId && !previousFocus.current) {
      previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    } else if (!panelId && previousFocus.current) {
      if (previousFocus.current.isConnected) previousFocus.current.focus({ preventScroll: true })
      previousFocus.current = null
    }
  }, [panelId])

  const dismiss = () => {
    if (!panel || closing) return
    setClosing(true)
    closeTimer.current = window.setTimeout(() => {
      closePanel(panel.id)
      setClosing(false)
    }, 180)
  }

  if (!panel) return null

  return (
    <div className="entity-drawer-layer" data-closing={closing || undefined}>
      <div className="entity-drawer-backdrop" aria-hidden="true" />
      <EntityDrawerContent panel={panel} onDismiss={dismiss} />
    </div>
  )
}
