import React, { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { ShieldCheck, AlertCircle, Smartphone, ArrowRight } from 'lucide-react'
import { useAuthStore } from '../store/auth'
import apiClient from '../api/client'
import AuthLeftPanel from '../components/AuthLeftPanel'

export default function SsoMfa() {
  const [params] = useSearchParams()
  const token = params.get('token') ?? ''
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
      const res = await apiClient.post('/auth/saml/mfa-verify', { token, code })
      setAuth(res.data.user)
      navigate('/dashboard', { replace: true })
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Invalid 2FA code')
    } finally {
      setLoading(false)
    }
  }

  if (!token) {
    navigate('/login', { replace: true })
    return null
  }

  const inputStyle: React.CSSProperties = {
    background: 'var(--hover-1)',
    border: '1px solid var(--border-mid)',
    transition: 'border-color 120ms ease, box-shadow 120ms ease',
  }
  const onFocus = (e: React.FocusEvent<HTMLInputElement>) => {
    e.target.style.borderColor = 'rgba(16,185,129,0.7)'
    e.target.style.boxShadow   = '0 0 0 3px rgba(16,185,129,0.12)'
  }
  const onBlur = (e: React.FocusEvent<HTMLInputElement>) => {
    e.target.style.borderColor = 'var(--border-mid)'
    e.target.style.boxShadow   = 'none'
  }

  return (
    <div className="min-h-[100dvh] flex" style={{ background: 'var(--surface-0)' }}>
      <AuthLeftPanel />

      {/* Right — form */}
      <div className="flex-1 flex flex-col items-center justify-center p-8 relative overflow-hidden">
        {/* Subtle bg grid */}
        <div className="absolute inset-0 pointer-events-none" style={{
          backgroundImage: 'linear-gradient(var(--hover-2) 1px, transparent 1px), linear-gradient(90deg, var(--hover-2) 1px, transparent 1px)',
          backgroundSize: '36px 36px',
        }} />
        {/* Corner glow */}
        <div className="absolute top-0 right-0 pointer-events-none" style={{
          width: 320, height: 320,
          background: 'radial-gradient(circle at top right, rgba(16,185,129,0.06), transparent 70%)',
        }} />

        {/* Mobile logo */}
        <div className="lg:hidden flex items-center gap-2.5 mb-10 relative z-10">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ background: 'var(--accent)', boxShadow: '0 0 16px rgba(16,185,129,0.4)' }}>
            <ShieldCheck size={16} className="text-white" strokeWidth={2.5} />
          </div>
          <span className="text-white font-bold text-lg tracking-tight">SEC360</span>
        </div>

        {/* Form card */}
        <div
          className="w-full max-w-[340px] relative z-10 rounded-2xl p-8 fade-up"
          style={{
            background: 'var(--surface-1)',
            border: '1px solid var(--border-mid)',
            boxShadow: '0 0 0 1px rgba(16,185,129,0.04), 0 24px 64px rgba(0,0,0,0.6)',
            animationDuration: '300ms',
          }}
        >
          {/* Header */}
          <div className="mb-7">
            <div className="w-9 h-9 rounded-xl flex items-center justify-center mb-4"
              style={{ background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.18)' }}>
              <Smartphone size={17} style={{ color: 'var(--accent)' }} />
            </div>
            <h1 className="text-white font-bold mb-1" style={{ fontSize: 20, letterSpacing: '-0.025em' }}>Two-factor auth</h1>
            <p style={{ fontSize: 12.5, color: 'var(--text-4)' }}>
              Google SSO verified — enter your authenticator code to continue
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
              <label className="block font-bold uppercase tracking-[0.1em]" style={{ fontSize: 10, color: 'var(--text-4)' }}>
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
                className="w-full text-[13px] text-white placeholder-zinc-700 rounded-lg px-3.5 py-2.5 text-center font-mono tracking-[0.5em] focus:outline-none"
                style={inputStyle}
                onFocus={onFocus}
                onBlur={onBlur}
              />
            </div>

            <button
              type="submit"
              disabled={loading || code.length !== 6}
              className="w-full flex items-center justify-center gap-2 text-white font-bold rounded-lg py-2.5 pressable disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ fontSize: 13, background: 'var(--accent)', boxShadow: '0 0 24px rgba(16,185,129,0.22)', letterSpacing: '-0.01em' }}
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
        <div className="mt-8 relative z-10 flex items-center gap-4" style={{ fontSize: 11, color: 'var(--text-4)' }}>
          <span>© 2025 SEC360</span>
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
