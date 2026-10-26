import React, { useState, useEffect, useRef } from 'react'
import { Navigate, useSearchParams, useLocation } from 'react-router-dom'
import { Eye, EyeOff, AlertCircle, Smartphone, ShieldCheck, ArrowRight } from 'lucide-react'
import { gsap } from 'gsap'
import { useGSAP } from '@gsap/react'
import { useAuth } from '../hooks/useAuth'
import AuthLeftPanel from '../components/AuthLeftPanel'

gsap.registerPlugin(useGSAP)

type Step = 'credentials' | 'totp'

const SSO_ERRORS: Record<string, string> = {
  not_invited: 'Your account is not registered. Contact your administrator to request access.',
  account_disabled: 'Your account has been disabled. Contact your administrator.',
  wrong_auth_method: 'This account is not configured for SSO. Use the email and password form instead.',
}

export default function Login() {
  const loginRootRef = useRef<HTMLDivElement>(null)
  const previousStepRef = useRef<Step>('credentials')
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
  const [sso, setSso] = useState<{ enabled: boolean; provider: string; providerLabel: string } | null>(null)

  useEffect(() => {
    fetch('/api/auth/saml/status')
      .then(response => response.json())
      .then((saml) => {
      setSso({
        enabled: saml.enabled === true,
        provider: typeof saml.provider === 'string' ? saml.provider : 'generic',
        providerLabel: typeof saml.provider_label === 'string' ? saml.provider_label : 'SSO',
      })
      })
      .catch(() => setSso({ enabled: false, provider: 'generic', providerLabel: 'SSO' }))
  }, [])

  useGSAP(() => {
    const media = gsap.matchMedia()

    media.add(
      {
        isDesktop: '(min-width: 1024px)',
        reduceMotion: '(prefers-reduced-motion: reduce)',
      },
      (context) => {
        const { isDesktop, reduceMotion } = context.conditions as {
          isDesktop: boolean
          reduceMotion: boolean
        }
        if (reduceMotion) return

        const motionTargets = gsap.utils.toArray<HTMLElement>('[data-login-motion]')
        gsap.set(motionTargets, { willChange: 'transform, opacity' })

        const timeline = gsap.timeline({
          defaults: { duration: 0.62, ease: 'power3.out' },
          onComplete: () => {
            gsap.set(motionTargets, { clearProps: 'transform,opacity,visibility,willChange' })
          },
        })

        timeline
          .addLabel('open')
          .from('[data-login-brand]', { autoAlpha: 0, y: -10, duration: 0.45 }, 'open')
          .from('[data-login-hero]', { autoAlpha: 0, y: 28 }, 'open+=0.08')
          .from('[data-login-copy]', { autoAlpha: 0, y: 16 }, 'open+=0.2')
          .from('[data-login-index]', { autoAlpha: 0, y: 12 }, 'open+=0.3')
          .from('[data-login-row]', { autoAlpha: 0, y: 14, stagger: 0.075 }, 'open+=0.36')
          .from(
            '[data-login-form]',
            { autoAlpha: 0, x: isDesktop ? 18 : 0, y: isDesktop ? 0 : 16 },
            'open+=0.18',
          )
          .from('[data-login-footer]', { autoAlpha: 0, y: 8, duration: 0.45 }, 'open+=0.48')
      },
    )

    return () => media.revert()
  }, { scope: loginRootRef })

  useGSAP(() => {
    if (previousStepRef.current === step) return
    previousStepRef.current = step
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return

    gsap.fromTo(
      '[data-login-step]',
      { autoAlpha: 0, y: 12 },
      {
        autoAlpha: 1,
        y: 0,
        duration: 0.36,
        ease: 'power2.out',
        clearProps: 'transform,opacity,visibility',
      },
    )
  }, { dependencies: [step], scope: loginRootRef, revertOnUpdate: true })

  if (isAuthenticated) return <Navigate to={from} replace />

  const inputBase = "w-full min-h-11 text-[15px] rounded-[6px] px-4 py-3 focus:outline-none"
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
      const result = await login(email, password, undefined, 'local')
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
      await login(email, password, totpCode, 'local')
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Invalid 2FA code')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div ref={loginRootRef} className="min-h-[100dvh] flex" style={{ background: 'var(--surface-0)' }}>
      <AuthLeftPanel />

      {/* Right — form */}
      <main className="flex-1 flex flex-col items-center justify-center px-6 py-10 sm:px-10 relative overflow-hidden">
        {/* Mobile logo */}
        <div className="lg:hidden flex items-center gap-2.5 mb-10 relative z-10" data-login-brand data-login-motion>
          <div className="brand-mark">
            <ShieldCheck size={16} className="text-white" strokeWidth={2.5} />
          </div>
          <span className="font-bold text-lg tracking-tight" style={{ color: 'var(--text-1)' }}>SEC360</span>
        </div>

        {/* Form card */}
        <div
          className="auth-card w-full max-w-[390px] relative z-10"
          data-login-form
          data-login-motion
          style={{
            background: 'transparent',
          }}
        >
          {step === 'credentials' ? (
            <div data-login-step>
              {/* Header */}
              <div className="mb-9">
                <h1 className="font-semibold mb-2" style={{ color: 'var(--text-1)', fontSize: 28, letterSpacing: '-0.035em' }}>Sign in to SEC360</h1>
                <p style={{ fontSize: 14, color: 'var(--text-3)' }}>Continue to your security workspace.</p>
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
                  <label className="block font-medium" style={{ fontSize: 13, color: 'var(--text-2)' }}>
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
                  <label className="block font-medium" style={{ fontSize: 13, color: 'var(--text-2)' }}>
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
                  className="w-full min-h-11 flex items-center justify-center gap-2 font-semibold rounded-[6px] pressable disabled:opacity-50 disabled:cursor-not-allowed mt-2"
                  style={{ fontSize: 14, background: 'var(--text-1)', color: 'var(--surface-0)', letterSpacing: '-0.01em' }}
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

              {sso?.enabled && (
                <>
                  <div className="flex items-center gap-3 my-5">
                    <div className="flex-1 h-px" style={{ background: 'var(--shimmer-a)' }} />
                    <span className="font-medium" style={{ fontSize: 12, color: 'var(--text-3)' }}>or</span>
                    <div className="flex-1 h-px" style={{ background: 'var(--shimmer-a)' }} />
                  </div>

                  <button
                    type="button"
                    onClick={() => { window.location.href = '/api/auth/saml/login' }}
                    disabled={loading}
                    className="flex min-h-11 w-full items-center justify-center gap-2.5 rounded-[6px] px-4 font-medium pressable disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{ fontSize: 14, color: 'var(--text-1)', background: 'var(--surface-2)', border: '1px solid var(--border-mid)', transition: 'border-color 120ms ease, background 120ms ease' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--border-lit)'; e.currentTarget.style.background = 'var(--shimmer-a)' }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-mid)'; e.currentTarget.style.background = 'var(--surface-2)' }}
                  >
                    {sso.provider === 'google' ? (
                      <svg width="14" height="14" viewBox="0 0 48 48">
                        <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
                        <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
                        <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
                        <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
                      </svg>
                    ) : <ShieldCheck size={15} />}
                    Continue with {sso.providerLabel}
                  </button>
                </>
              )}
            </div>
          ) : (
            <div data-login-step>
              <div className="mb-8">
                <div className="mb-5 flex items-center gap-2" style={{ color: 'var(--accent)' }}><Smartphone size={18} /><span className="text-[13px] font-medium">Identity verification</span></div>
                <h1 className="font-semibold mb-1.5" style={{ color: 'var(--text-1)', fontSize: 28, letterSpacing: '-0.035em' }}>Two-factor authentication</h1>
                <p style={{ fontSize: 14, color: 'var(--text-3)' }}>Enter the six-digit code from your authenticator app.</p>
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
                  <label className="block font-medium" style={{ fontSize: 13, color: 'var(--text-2)' }}>
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
                  className="w-full min-h-11 flex items-center justify-center gap-2 font-semibold rounded-[6px] pressable disabled:opacity-40 disabled:cursor-not-allowed"
                  style={{ fontSize: 14, background: 'var(--text-1)', color: 'var(--surface-0)', letterSpacing: '-0.01em' }}
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
        <div className="mt-10 relative z-10 flex items-center gap-3" style={{ fontSize: 13, color: 'var(--text-3)' }} data-login-footer data-login-motion>
          <span>© 2026 SEC360</span>
          <span>·</span>
          <span>Secure access</span>
        </div>
      </main>
    </div>
  )
}
