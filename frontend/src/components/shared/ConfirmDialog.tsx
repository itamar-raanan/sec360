import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { AlertTriangle, X } from 'lucide-react'

interface ConfirmOptions {
  title?: string
  message: string
  confirmLabel?: string
  tone?: 'danger' | 'default'
}

type ConfirmFunction = (options: ConfirmOptions | string) => Promise<boolean>

const ConfirmContext = createContext<ConfirmFunction | null>(null)

export function ConfirmProvider({ children }: { children: React.ReactNode }) {
  const [request, setRequest] = useState<(ConfirmOptions & { resolve: (value: boolean) => void }) | null>(null)
  const cancelRef = useRef<HTMLButtonElement>(null)

  const confirm = useCallback<ConfirmFunction>((input) => new Promise(resolve => {
    const options = typeof input === 'string' ? { message: input } : input
    setRequest({ title: 'Confirm action', confirmLabel: 'Confirm', tone: 'danger', ...options, resolve })
  }), [])

  const finish = useCallback((value: boolean) => {
    request?.resolve(value)
    setRequest(null)
  }, [request])

  useEffect(() => {
    if (!request) return
    const onKey = (event: KeyboardEvent) => event.key === 'Escape' && finish(false)
    window.addEventListener('keydown', onKey)
    window.setTimeout(() => cancelRef.current?.focus(), 0)
    return () => window.removeEventListener('keydown', onKey)
  }, [finish, request])

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {request && (
        <div className="dialog-backdrop" role="presentation" onMouseDown={() => finish(false)}>
          <section className="dialog-panel" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-description" onMouseDown={event => event.stopPropagation()}>
            <div className="flex items-start gap-3">
              <span className={`dialog-icon ${request.tone === 'danger' ? 'danger' : ''}`}><AlertTriangle size={17} /></span>
              <div className="min-w-0 flex-1">
                <h2 id="confirm-title" className="text-[14px] font-semibold" style={{ color: 'var(--text-1)' }}>{request.title}</h2>
                <p id="confirm-description" className="mt-1.5 text-[12px] leading-relaxed" style={{ color: 'var(--text-3)' }}>{request.message}</p>
              </div>
              <button className="ui-icon-button !h-8 !w-8" onClick={() => finish(false)} aria-label="Close"><X size={14} /></button>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <button ref={cancelRef} className="ui-secondary-button" onClick={() => finish(false)}>Cancel</button>
              <button className={request.tone === 'danger' ? 'ui-danger-button' : 'ui-primary-button'} onClick={() => finish(true)}>{request.confirmLabel}</button>
            </div>
          </section>
        </div>
      )}
    </ConfirmContext.Provider>
  )
}

export function useConfirm() {
  const context = useContext(ConfirmContext)
  if (!context) throw new Error('useConfirm must be used inside ConfirmProvider')
  return context
}
