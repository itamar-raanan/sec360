import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldCheck, AlertCircle, Smartphone, ArrowRight } from 'lucide-react'
import { useAuthStore } from '../store/auth'
import apiClient from '../api/client'
import AuthLeftPanel from '../components/AuthLeftPanel'

export default function SsoMfa() {
  const navigate = useNavigate()
  const { setAuth } = useAuthStore()

  const [code, setCode] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await apiClient.post('/auth/saml/mfa-verify', { code })
      setAuth(res.data.user)
      navigate('/dashboard', { replace: true })
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Invalid 2FA code')
    } finally {
      setLoading(false)
    }
  }

  const inputStyle: React.CSSProperties = {
    transition: 'border-color 120ms ease, box-shadow 120ms ease',
  }
  const onFocus = (e: React.FocusEvent<HTMLInputElement>) => {
    e.target.style.borderColor = 'var(--accent)'
    e.target.style.boxShadow   = '0 0 0 3px var(--accent-dim)'
  }
  const onBlur = (e: React.FocusEvent<HTMLInputElement>) => {
    e.target.style.borderColor = 'var(--border-mid)'
    e.target.style.boxShadow   = 'none'
  }

  return (
    <div className="auth-shell min-h-[100dvh] flex">
      <AuthLeftPanel />

      {/* Right — form */}
      <div className="flex-1 flex flex-col items-center justify-center p-8 relative overflow-hidden">
        {/* Mobile logo */}
        <div className="lg:hidden flex items-center gap-2.5 mb-10 relative z-10">
          <div className="brand-mark">
            <ShieldCheck size={16} strokeWidth={2.5} />
          </div>
          <span className="font-bold text-lg tracking-tight" style={{ color: 'var(--text-1)' }}>SEC360</span>
        </div>

        {/* Form card */}
        <div
          className="auth-card ui-command-surface w-full max-w-[360px] relative z-10 p-8 fade-up"
          style={{ background: 'var(--glass-panel-strong)', animationDuration: '300ms' }}
        >
          {/* Header */}
          <div className="mb-7">
            <div className="auth-icon mb-4 !h-10 !w-10">
              <Smartphone size={17} style={{ color: 'var(--accent)' }} />
            </div>
            <h1 className="ui-page-title mb-1">Two-factor auth</h1>
            <p className="ui-page-description !mt-0">
              SSO identity verified — enter your authenticator code to continue
            </p>
          </div>

          {error && (
            <div
              className="flex items-center gap-2.5 rounded-lg p-3 mb-5"
              style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.18)', color: '#f87171', fontSize: 12.5 }}
            >
              <AlertCircle size={13} className="flex-shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label className="ui-form-label">
                Authenticator code
              </label>
              <input
                type="text"
                inputMode="numeric"
                pattern="\d{6}"
                maxLength={6}
                value={code}
                onChange={e => setCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000 000"
                required
                autoFocus
                className="ui-input min-h-11 text-center font-mono tracking-[0.5em] focus:outline-none"
                style={inputStyle}
                onFocus={onFocus}
                onBlur={onBlur}
              />
            </div>

            <button
              type="submit"
              disabled={loading || code.length !== 6}
              className="ui-primary-button ui-button-lg w-full pressable disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loading ? 'Verifying…' : <><span>Verify &amp; sign in</span><ArrowRight size={14} /></>}
            </button>

            <a
              href="/login"
              className="block text-center py-1"
              style={{ fontSize: 12.5, color: 'var(--text-4)', transition: 'color 120ms ease' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-2)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-4)')}
            >
              ← Back to sign in
            </a>
          </form>
        </div>

        {/* Footer */}
        <div className="mt-8 relative z-10 flex items-center gap-4" style={{ fontSize: 12, color: 'var(--text-4)' }}>
          <span>© 2026 SEC360</span>
          <span>·</span>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            <span>All systems operational</span>
          </div>
        </div>
      </div>
    </div>
  )
}
