import React, { useState, useEffect } from 'react'
import { Navigate, useSearchParams, useLocation } from 'react-router-dom'
import { Eye, EyeOff, AlertCircle, Smartphone, ShieldCheck, ArrowRight } from 'lucide-react'
import { useAuth } from '../hooks/useAuth'
import AuthLeftPanel from '../components/AuthLeftPanel'

type Step = 'credentials' | 'totp'

const SSO_ERRORS: Record<string, string> = {
  not_invited: 'Your account is not registered. Contact your administrator to request access.',
  account_disabled: 'Your account has been disabled. Contact your administrator.',
}

export default function Login() {
  const { isAuthenticated, login } = useAuth()
  const [searchParams] = useSearchParams()
  const location = useLocation()
  const from = (location.state as { from?: Location })?.from?.pathname || '/dashboard'
  const [step, setStep]       = useState<Step>('credentials')
  const [email, setEmail]     = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [showPw, setShowPw]   = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(() => SSO_ERRORS[searchParams.get('sso_error') ?? ''] ?? '')
  const [ssoEnabled, setSsoEnabled] = useState<boolean | null>(null)

  useEffect(() => {
    fetch('/api/auth/saml/status')
      .then(r => r.json())
      .then(d => setSsoEnabled(d.enabled === true))
      .catch(() => setSsoEnabled(false))
  }, [])

  if (isAuthenticated) return <Navigate to={from} replace />

  const inputBase = "w-full text-[15px] rounded-lg px-4 py-3 focus:outline-none"
  const inputStyle: React.CSSProperties = {
    background: 'var(--surface-3)',
    border: '1px solid var(--border-mid)',
    color: 'var(--text-1)',
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

  const handleCredentials = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const result = await login(email, password)
      if (result.mfa_required) setStep('totp')
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Invalid email or password')
    } finally {
      setLoading(false)
    }
  }

  const handleTotp = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(email, password, totpCode)
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Invalid 2FA code')
    } finally {
      setLoading(false)
    }
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
          <span className="font-bold text-lg tracking-tight" style={{ color: 'var(--text-1)' }}>SEC360</span>
        </div>

        {/* Form card */}
        <div
          className="w-full max-w-[480px] relative z-10 rounded-2xl p-10"
          style={{
            background: 'var(--surface-1)',
            border: '1px solid var(--border-mid)',
            boxShadow: '0 0 0 1px rgba(16,185,129,0.04), 0 24px 64px rgba(0,0,0,0.3)',
          }}
        >
          {step === 'credentials' ? (
            <div className="fade-up" style={{ animationDuration: '300ms' }}>
              {/* Header */}
              <div className="mb-8">
                <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-5"
                  style={{ background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.18)' }}>
                  <ShieldCheck size={22} style={{ color: 'var(--accent)' }} strokeWidth={2.5} />
                </div>
                <h1 className="font-bold mb-1.5" style={{ color: 'var(--text-1)', fontSize: 26, letterSpacing: '-0.03em' }}>Welcome back</h1>
                <p style={{ fontSize: 14, color: 'var(--text-4)' }}>Sign in to your workspace</p>
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

              <form onSubmit={handleCredentials} className="space-y-5">
                <div className="space-y-2">
                  <label className="block font-bold uppercase tracking-[0.1em]" style={{ fontSize: 11, color: 'var(--text-4)' }}>
                    Email address
                  </label>
                  <input
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    required
                    className={inputBase}
                    style={inputStyle}
                    onFocus={onFocus}
                    onBlur={onBlur}
                  />
                </div>

                <div className="space-y-2">
                  <label className="block font-bold uppercase tracking-[0.1em]" style={{ fontSize: 11, color: 'var(--text-4)' }}>
                    Password
                  </label>
                  <div className="relative">
                    <input
                      type={showPw ? 'text' : 'password'}
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      placeholder="••••••••"
                      required
                      className={`${inputBase} pr-10`}
                      style={inputStyle}
                      onFocus={onFocus}
                      onBlur={onBlur}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPw(!showPw)}
                      className="absolute right-3 top-1/2 -translate-y-1/2"
                      style={{ color: 'var(--text-4)', transition: 'color 120ms ease' }}
                      onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-2)')}
                      onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-4)')}
                    >
                      {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full flex items-center justify-center gap-2 text-white font-bold rounded-lg py-3.5 pressable disabled:opacity-50 disabled:cursor-not-allowed mt-2"
                  style={{ fontSize: 15, background: 'var(--accent)', boxShadow: '0 0 24px rgba(16,185,129,0.22)', letterSpacing: '-0.01em' }}
                >
                  {loading ? (
                    <>
                      <svg className="animate-spin w-3.5 h-3.5" viewBox="0 0 24 24" fill="none">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                      </svg>
                      Signing in…
                    </>
                  ) : (
                    <>
                      Sign in
                      <ArrowRight size={14} />
                    </>
                  )}
                </button>
              </form>

              {ssoEnabled && (
                <>
                  <div className="flex items-center gap-3 my-5">
                    <div className="flex-1 h-px" style={{ background: 'var(--shimmer-a)' }} />
                    <span className="font-bold uppercase tracking-[0.12em]" style={{ fontSize: 9.5, color: 'var(--text-4)' }}>or</span>
                    <div className="flex-1 h-px" style={{ background: 'var(--shimmer-a)' }} />
                  </div>

                  <button
                    type="button"
                    onClick={() => { window.location.href = '/api/auth/saml/login' }}
                    disabled={loading}
                    className="flex w-full items-center justify-center gap-2.5 rounded-lg px-4 py-3.5 font-medium text-white pressable disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{ fontSize: 15, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border-mid)', transition: 'border-color 120ms ease, background 120ms ease' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--border-lit)'; e.currentTarget.style.background = 'var(--shimmer-a)' }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-mid)'; e.currentTarget.style.background = 'rgba(255,255,255,0.03)' }}
                  >
                    <svg width="14" height="14" viewBox="0 0 48 48">
                      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
                      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
                      <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
                      <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
                    </svg>
                    Continue with Google SSO
                  </button>
                </>
              )}
            </div>
          ) : (
            <div className="fade-up" style={{ animationDuration: '300ms' }}>
              <div className="mb-8">
                <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-5"
                  style={{ background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.18)' }}>
                  <Smartphone size={22} style={{ color: 'var(--accent)' }} />
                </div>
                <h1 className="font-bold mb-1.5" style={{ color: 'var(--text-1)', fontSize: 26, letterSpacing: '-0.03em' }}>Two-factor auth</h1>
                <p style={{ fontSize: 14, color: 'var(--text-4)' }}>Enter the 6-digit code from your authenticator app</p>
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

              <form onSubmit={handleTotp} className="space-y-5">
                <div className="space-y-2">
                  <label className="block font-bold uppercase tracking-[0.1em]" style={{ fontSize: 11, color: 'var(--text-4)' }}>
                    Authenticator code
                  </label>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="\d{6}"
                    maxLength={6}
                    value={totpCode}
                    onChange={e => setTotpCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="000 000"
                    required
                    autoFocus
                    className={`${inputBase} text-center font-mono tracking-[0.5em]`}
                    style={inputStyle}
                    onFocus={onFocus}
                    onBlur={onBlur}
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading || totpCode.length !== 6}
                  className="w-full flex items-center justify-center gap-2 text-white font-bold rounded-lg py-3.5 pressable disabled:opacity-40 disabled:cursor-not-allowed"
                  style={{ fontSize: 15, background: 'var(--accent)', boxShadow: '0 0 24px rgba(16,185,129,0.22)', letterSpacing: '-0.01em' }}
                >
                  {loading ? 'Verifying…' : <><span>Verify &amp; sign in</span><ArrowRight size={14} /></>}
                </button>

                <button
                  type="button"
                  onClick={() => { setStep('credentials'); setError(''); setTotpCode('') }}
                  className="w-full py-1 text-center"
                  style={{ fontSize: 12.5, color: 'var(--text-4)', transition: 'color 120ms ease' }}
                  onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-2)')}
                  onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-4)')}
                >
                  ← Back to sign in
                </button>
              </form>
            </div>
          )}
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
