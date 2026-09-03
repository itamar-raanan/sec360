import React, { useState, useEffect } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, CheckCircle2, AlertCircle, Loader2, Smartphone } from 'lucide-react'
import apiClient from '../api/client'
import { useAuthStore } from '../store/auth'

type Step = 'loading' | 'set-password' | 'setup-2fa' | 'success' | 'error'

const inputClass = "w-full text-sm text-white rounded-xl px-4 py-3 focus:outline-none transition-[border-color,box-shadow] duration-150"
const inputStyle = { background: 'var(--surface-3)', border: '1px solid var(--border-mid)' }

function focusHandlers() {
  return {
    onFocus: (e: React.FocusEvent<HTMLInputElement>) => {
      e.target.style.borderColor = 'var(--accent)'
      e.target.style.boxShadow = '0 0 0 3px var(--accent-ring)'
    },
    onBlur: (e: React.FocusEvent<HTMLInputElement>) => {
      e.target.style.borderColor = 'var(--border-mid)'
      e.target.style.boxShadow = 'none'
    },
  }
}

export default function AcceptInvite() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const { setAuth } = useAuthStore()
  const token = params.get('token') ?? ''

  const [step, setStep] = useState<Step>('loading')
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [qrCode, setQrCode] = useState('')
  const [mfaSecret, setMfaSecret] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!token) { setStep('error'); return }
    apiClient.get(`/auth/invite/${token}`)
      .then(res => { setInviteEmail(res.data.email); setInviteRole(res.data.role); setStep('set-password') })
      .catch(() => setStep('error'))
  }, [token])

  const handleSetPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (password.length < 8) { setError('Password must be at least 8 characters'); return }
    if (password !== confirmPw) { setError('Passwords do not match'); return }
    setError(''); setLoading(true)
    try {
      const res = await apiClient.post('/auth/invite/accept', { token, password })
      setAuth(res.data.user)
      const mfaRes = await apiClient.get('/settings/me/mfa/setup')
      setQrCode(mfaRes.data.qr_code)
      setMfaSecret(mfaRes.data.secret)
      setStep('setup-2fa')
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Failed to activate account')
    } finally { setLoading(false) }
  }

  const handleSetup2FA = async (e: React.FormEvent) => {
    e.preventDefault()
    if (totpCode.length !== 6) { setError('Enter the 6-digit code from your authenticator app'); return }
    setError(''); setLoading(true)
    try {
      await apiClient.post('/settings/me/mfa/enable', { code: totpCode })
      setStep('success')
      setTimeout(() => navigate('/dashboard'), 2000)
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Invalid code — try again')
    } finally { setLoading(false) }
  }

  const stepIndex = step === 'set-password' ? 0 : step === 'setup-2fa' ? 1 : -1

  return (
    <div className="min-h-[100dvh] flex items-center justify-center p-4" style={{ background: 'var(--surface-0)' }}>
      <div className="grain-overlay" aria-hidden />
      <div className="w-full max-w-[420px]">

        {/* Logo */}
        <div className="flex items-center justify-center gap-2.5 mb-8">
          <div className="w-9 h-9 rounded-xl flex items-center justify-center"
            style={{ background: 'var(--accent)', boxShadow: '0 0 16px rgba(16,185,129,0.25)' }}>
            <Shield size={17} className="text-white" strokeWidth={2.5} />
          </div>
          <span className="text-white font-bold text-lg tracking-tight">SEC360</span>
        </div>

        {/* Step stepper */}
        {stepIndex >= 0 && (
          <div className="flex items-center justify-center gap-2 mb-6">
            {['Set password', 'Enable 2FA'].map((label, i) => (
              <React.Fragment key={label}>
                <div className="flex items-center gap-1.5">
                  <div
                    className="w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-bold"
                    style={i < stepIndex
                      ? { background: '#10b981', color: '#fff' }
                      : i === stepIndex
                        ? { background: 'var(--accent)', color: '#fff' }
                        : { background: 'var(--surface-3)', color: 'var(--text-4)', border: '1px solid var(--border)' }
                    }
                  >
                    {i < stepIndex ? '✓' : i + 1}
                  </div>
                  <span className="text-[12px]" style={{ color: i === stepIndex ? '#f1f5f9' : '#52525e' }}>{label}</span>
                </div>
                {i < 1 && <div className="w-8 h-px" style={{ background: i < stepIndex ? 'var(--accent)' : 'var(--border)' }} />}
              </React.Fragment>
            ))}
          </div>
        )}

        {/* Card */}
        <div className="rounded-2xl p-8" style={{ background: 'var(--surface-2)', border: '1px solid var(--border-mid)' }}>

          {step === 'loading' && (
            <div className="flex flex-col items-center gap-3 py-8">
              <Loader2 size={24} className="animate-spin" style={{ color: 'var(--accent)' }} />
              <p className="text-[13px]" style={{ color: 'var(--text-3)' }}>Validating invitation…</p>
            </div>
          )}

          {step === 'error' && (
            <div className="flex flex-col items-center gap-3 py-8 text-center">
              <div className="w-12 h-12 rounded-full flex items-center justify-center"
                style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)' }}>
                <AlertCircle size={22} style={{ color: '#f87171' }} />
              </div>
              <h2 className="text-[15px] font-semibold text-white">Invalid or expired invitation</h2>
              <p className="text-[13px]" style={{ color: 'var(--text-4)' }}>This link may have been used already or expired (7 days).</p>
              <button onClick={() => navigate('/login')}
                className="mt-2 text-[13px] transition-[color] duration-150"
                style={{ color: 'var(--accent)' }}>
                Go to login →
              </button>
            </div>
          )}

          {step === 'success' && (
            <div className="flex flex-col items-center gap-3 py-8 text-center">
              <div className="w-12 h-12 rounded-full flex items-center justify-center"
                style={{ background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.15)' }}>
                <CheckCircle2 size={22} style={{ color: 'var(--accent)' }} />
              </div>
              <h2 className="text-[15px] font-semibold text-white">Account activated!</h2>
              <p className="text-[13px]" style={{ color: 'var(--text-4)' }}>Redirecting to your dashboard…</p>
            </div>
          )}

          {step === 'set-password' && (
            <div className="fade-in">
              <div className="mb-6">
                <h2 className="text-[17px] font-bold text-white tracking-tight">Set your password</h2>
                <p className="text-[13px] mt-1.5" style={{ color: 'var(--text-3)' }}>
                  Invited as <span className="text-white font-medium">{inviteEmail}</span>
                  {' '}· <span className="capitalize font-medium" style={{ color: 'var(--accent)' }}>{inviteRole}</span>
                </p>
              </div>

              {error && (
                <div className="flex items-center gap-2.5 rounded-xl p-3.5 mb-5 text-[13px]"
                  style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.15)', color: '#f87171' }}>
                  <AlertCircle size={14} className="flex-shrink-0" />{error}
                </div>
              )}

              <form onSubmit={handleSetPassword} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="block text-[11px] font-semibold uppercase tracking-widest" style={{ color: 'var(--text-4)' }}>New password</label>
                  <div className="relative">
                    <input type={showPw ? 'text' : 'password'} value={password}
                      onChange={e => setPassword(e.target.value)} placeholder="At least 8 characters"
                      required className={inputClass} style={inputStyle} {...focusHandlers()} />
                    <button type="button" onClick={() => setShowPw(!showPw)}
                      className="absolute right-3.5 top-1/2 -translate-y-1/2 transition-[color] duration-150"
                      style={{ color: 'var(--text-4)' }}>
                      {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="block text-[11px] font-semibold uppercase tracking-widest" style={{ color: 'var(--text-4)' }}>Confirm password</label>
                  <div className="relative">
                    <input type={showConfirm ? 'text' : 'password'} value={confirmPw}
                      onChange={e => setConfirmPw(e.target.value)} placeholder="Repeat password"
                      required className={inputClass} style={inputStyle} {...focusHandlers()} />
                    <button type="button" onClick={() => setShowConfirm(!showConfirm)}
                      className="absolute right-3.5 top-1/2 -translate-y-1/2 transition-[color] duration-150"
                      style={{ color: 'var(--text-4)' }}>
                      {showConfirm ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </div>

                <button type="submit" disabled={loading || !password || !confirmPw}
                  className="w-full text-white text-[13px] font-semibold py-3 px-4 rounded-xl pressable disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  style={{ background: 'var(--accent)', boxShadow: '0 0 20px rgba(16,185,129,0.15)' }}>
                  {loading ? <><Loader2 size={14} className="animate-spin" /> Setting up…</> : 'Continue →'}
                </button>
              </form>
            </div>
          )}

          {step === 'setup-2fa' && (
            <div className="fade-in">
              <div className="mb-5">
                <div className="flex items-center gap-2 mb-1.5">
                  <Smartphone size={16} style={{ color: 'var(--accent)' }} />
                  <h2 className="text-[17px] font-bold text-white tracking-tight">Set up two-factor authentication</h2>
                </div>
                <p className="text-[13px]" style={{ color: 'var(--text-3)' }}>
                  Scan the QR code with Google Authenticator or Authy, then enter the 6-digit code.
                </p>
              </div>

              {qrCode && (
                <div className="flex justify-center mb-5">
                  <div className="p-3 rounded-xl" style={{ background: '#fff' }}>
                    <img src={qrCode} alt="2FA QR Code" className="w-44 h-44 block" />
                  </div>
                </div>
              )}

              {mfaSecret && (
                <div className="mb-5 rounded-xl px-4 py-3" style={{ background: 'var(--surface-3)', border: '1px solid var(--border)' }}>
                  <p className="text-[10px] font-semibold uppercase tracking-widest mb-1.5" style={{ color: 'var(--text-4)' }}>Manual entry key</p>
                  <code className="text-[11px] tracking-widest break-all" style={{ color: 'var(--text-2)' }}>{mfaSecret}</code>
                </div>
              )}

              {error && (
                <div className="flex items-center gap-2.5 rounded-xl p-3.5 mb-5 text-[13px]"
                  style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.15)', color: '#f87171' }}>
                  <AlertCircle size={14} className="flex-shrink-0" />{error}
                </div>
              )}

              <form onSubmit={handleSetup2FA} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="block text-[11px] font-semibold uppercase tracking-widest" style={{ color: 'var(--text-4)' }}>Authenticator code</label>
                  <input type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength={6}
                    value={totpCode} onChange={e => setTotpCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="000 000" autoFocus
                    className={`${inputClass} text-center tracking-[0.5em] font-mono`}
                    style={inputStyle} {...focusHandlers()} />
                </div>
                <button type="submit" disabled={loading || totpCode.length !== 6}
                  className="w-full text-white text-[13px] font-semibold py-3 px-4 rounded-xl pressable disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  style={{ background: 'var(--accent)', boxShadow: '0 0 20px rgba(16,185,129,0.15)' }}>
                  {loading ? <><Loader2 size={14} className="animate-spin" /> Verifying…</> : 'Enable 2FA & finish'}
                </button>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
