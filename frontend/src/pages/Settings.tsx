import React, { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Users,
  Settings2,
  ClipboardList,
  User,
  Plus,
  Trash2,
  RotateCcw,
  ShieldCheck,
  ShieldOff,
  AlertCircle,
  CheckCircle2,
  Eye,
  EyeOff,
  Smartphone,
  Save,
  X,
  Crown,
  UserCheck,
  UserX,
  KeyRound,
  ExternalLink,
  Copy,
} from 'lucide-react'
import { useAuthStore } from '../store/auth'
import apiClient from '../api/client'

type Tab = 'users' | 'account' | 'platform' | 'sso' | 'audit'

// ── Types ────────────────────────────────────────────────────────────────────

interface AuthUserDetail {
  id: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  is_active: boolean
  mfa_enabled: boolean
  created_at: string
}

interface SystemSettings {
  offline_threshold_hours: number
  risk_weight_no_edr: number
  risk_weight_edr_version: number
  risk_weight_no_dlp: number
  risk_weight_dlp_version: number
  risk_weight_no_user: number
  auto_correlation: boolean
  enforce_mfa: boolean
  min_password_length: number
  session_timeout_hours: number
  platform_name: string
  min_s1_version: string
  min_dlp_version: string
  min_wss_version: string
}

interface AuditEntry {
  id: string
  action: string
  resource_type: string
  resource_id: string | null
  timestamp: string
  ip_address: string | null
  details: Record<string, unknown> | null
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function RoleBadge({ role }: { role: string }) {
  const styles: Record<string, React.CSSProperties> = {
    admin: { background: 'rgba(16,185,129,0.12)', color: '#34d399', borderColor: 'rgba(16,185,129,0.2)' },
    analyst: { background: 'rgba(16,185,129,0.08)', color: '#6ee7b7', borderColor: 'rgba(16,185,129,0.15)' },
    viewer: { background: 'rgba(113,113,122,0.12)', color: 'var(--text-2)', borderColor: 'rgba(113,113,122,0.2)' },
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border"
      style={styles[role] ?? styles.viewer}>
      {role === 'admin' && <Crown size={10} />}
      {role}
    </span>
  )
}

function Alert({ type, msg }: { type: 'error' | 'success'; msg: string }) {
  const Icon = type === 'error' ? AlertCircle : CheckCircle2
  const s: React.CSSProperties = type === 'error'
    ? { background: 'rgba(239,68,68,0.08)', borderColor: 'rgba(239,68,68,0.2)', color: '#f87171' }
    : { background: 'rgba(34,197,94,0.08)', borderColor: 'rgba(34,197,94,0.2)', color: '#4ade80' }
  return (
    <div className="flex items-center gap-2 border rounded-lg p-3 text-sm" style={s}>
      <Icon size={15} className="flex-shrink-0" />
      {msg}
    </div>
  )
}

// ── Users tab ────────────────────────────────────────────────────────────────

function UsersTab() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [createEmail, setCreateEmail] = useState('')
  const [createRole, setCreateRole] = useState<'admin' | 'analyst' | 'viewer'>('analyst')
  const [createErr, setCreateErr] = useState('')
  const [inviteSuccess, setInviteSuccess] = useState('')
  const [feedback, setFeedback] = useState<{ id: string; msg: string; type: 'success' | 'error' } | null>(null)

  const { data: users = [], isLoading } = useQuery<AuthUserDetail[]>({
    queryKey: ['settings-users'],
    queryFn: () => apiClient.get('/settings/users').then(r => r.data),
  })

  const createMutation = useMutation({
    mutationFn: (body: { email: string; role: string }) =>
      apiClient.post('/settings/users/invite', body),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['settings-users'] })
      setShowCreate(false)
      setCreateEmail('')
      setCreateRole('analyst')
      setCreateErr('')
      const emailSent = res.data?.email_sent
      setInviteSuccess(
        emailSent
          ? `Invitation sent to ${res.data.email}`
          : `User created. No SMTP configured — share the invite link manually.`
      )
      setTimeout(() => setInviteSuccess(''), 6000)
    },
    onError: (e: { response?: { data?: { detail?: string } } }) => {
      setCreateErr(e?.response?.data?.detail ?? 'Failed to invite user')
    },
  })

  const patchMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: { role?: string; is_active?: boolean } }) =>
      apiClient.patch(`/settings/users/${id}`, body),
    onSuccess: (_, { id }) => {
      qc.invalidateQueries({ queryKey: ['settings-users'] })
      setFeedback({ id, msg: 'Updated', type: 'success' })
      setTimeout(() => setFeedback(null), 2000)
    },
    onError: (e: { response?: { data?: { detail?: string } } }, { id }) => {
      setFeedback({ id, msg: e?.response?.data?.detail ?? 'Update failed', type: 'error' })
      setTimeout(() => setFeedback(null), 3000)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiClient.delete(`/settings/users/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings-users'] }),
  })

  const resetMfaMutation = useMutation({
    mutationFn: (id: string) => apiClient.post(`/settings/users/${id}/reset-mfa`),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ['settings-users'] })
      setFeedback({ id, msg: '2FA reset', type: 'success' })
      setTimeout(() => setFeedback(null), 2000)
    },
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-white">Users & Access</h2>
          <p className="text-xs text-zinc-500 mt-0.5">Manage platform accounts and roles</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium px-3.5 py-2 rounded-lg pressable"
        >
          <Plus size={15} /> Invite user
        </button>
      </div>

      {inviteSuccess && <Alert type="success" msg={inviteSuccess} />}

      {/* Invite user panel */}
      {showCreate && (
        <div className="rounded-xl p-5 space-y-3" style={{ background: 'var(--surface-inset-strong)', border: '1px solid var(--border-lit)' }}>
          <div className="flex items-center justify-between mb-1">
            <div>
              <span className="text-sm font-medium text-white">Invite new user</span>
              <p className="text-xs text-zinc-500 mt-0.5">They'll receive an email to set their password and configure 2FA.</p>
            </div>
            <button onClick={() => { setShowCreate(false); setCreateErr('') }}
              style={{ color: 'var(--text-3)', transition: 'color 150ms ease' }}
              onMouseEnter={e => (e.currentTarget.style.color = '#d4d4d8')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-3)')}>
              <X size={16} />
            </button>
          </div>
          {createErr && <Alert type="error" msg={createErr} />}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Email address</label>
              <input
                type="email"
                value={createEmail}
                onChange={e => setCreateEmail(e.target.value)}
                placeholder="user@company.com"
                className="w-full bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Role</label>
              <select
                value={createRole}
                onChange={e => setCreateRole(e.target.value as typeof createRole)}
                className="w-full bg-zinc-950 border border-white/[0.08] text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
              >
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>
          </div>
          <div className="flex gap-2 pt-1">
            <button
              onClick={() => createMutation.mutate({ email: createEmail, role: createRole })}
              disabled={createMutation.isPending || !createEmail}
              className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-900 disabled:cursor-not-allowed text-white text-sm font-medium px-4 py-2 rounded-lg pressable"
            >
              {createMutation.isPending ? 'Sending...' : 'Send invitation'}
            </button>
            <button onClick={() => { setShowCreate(false); setCreateErr('') }} className="text-sm px-3 py-2"
              style={{ color: 'var(--text-2)', transition: 'color 150ms ease' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-1)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-2)')}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Users table */}
      <div className="rounded-xl overflow-hidden" style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
        {isLoading ? (
          <div className="p-4 space-y-2">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="flex items-center gap-3 px-1 py-1.5">
                <div className="shimmer w-7 h-7 rounded-full flex-shrink-0" />
                <div className="shimmer h-3.5 rounded flex-1 max-w-[200px]" />
                <div className="shimmer h-3.5 rounded w-16 ml-auto" />
                <div className="shimmer h-3.5 rounded w-10" />
                <div className="shimmer h-3.5 rounded w-12" />
                <div className="shimmer h-3.5 rounded w-20" />
              </div>
            ))}
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-zinc-500 uppercase tracking-wider" style={{ borderBottom: '1px solid var(--border)' }}>
                <th className="text-left px-4 py-3">User</th>
                <th className="text-left px-4 py-3">Role</th>
                <th className="text-left px-4 py-3">2FA</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-left px-4 py-3">Created</th>
                <th className="text-right px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id} style={{ borderTop: '1px solid var(--border)' }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--hover-2)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <div className="w-7 h-7 bg-emerald-600/20 rounded-full flex items-center justify-center text-emerald-400 text-xs font-bold flex-shrink-0">
                        {u.email[0].toUpperCase()}
                      </div>
                      <span className="text-white font-medium">{u.email}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <select
                      value={u.role}
                      onChange={e => patchMutation.mutate({ id: u.id, body: { role: e.target.value } })}
                      className="bg-transparent border border-white/[0.08] text-zinc-300 rounded-md px-2 py-1 text-xs focus:outline-none focus:border-emerald-500 cursor-pointer"
                    >
                      <option value="admin">Admin</option>
                      <option value="analyst">Analyst</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </td>
                  <td className="px-4 py-3">
                    {u.mfa_enabled ? (
                      <span className="inline-flex items-center gap-1 text-xs text-emerald-300">
                        <ShieldCheck size={13} /> On
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-xs text-zinc-500">
                        <ShieldOff size={13} /> Off
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {!u.is_active && !u.mfa_enabled ? (
                      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border bg-yellow-500/10 text-yellow-400 border-yellow-500/20">
                        Pending invite
                      </span>
                    ) : (
                      <button
                        onClick={() => patchMutation.mutate({ id: u.id, body: { is_active: !u.is_active } })}
                        className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border"
                        style={{
                          background: u.is_active ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
                          color: u.is_active ? '#4ade80' : '#f87171',
                          borderColor: u.is_active ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)',
                          transition: 'background-color 150ms ease, color 150ms ease, border-color 150ms ease',
                        }}
                        onMouseEnter={e => {
                          e.currentTarget.style.background = u.is_active ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)'
                          e.currentTarget.style.color = u.is_active ? '#f87171' : '#4ade80'
                          e.currentTarget.style.borderColor = u.is_active ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)'
                        }}
                        onMouseLeave={e => {
                          e.currentTarget.style.background = u.is_active ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)'
                          e.currentTarget.style.color = u.is_active ? '#4ade80' : '#f87171'
                          e.currentTarget.style.borderColor = u.is_active ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)'
                        }}
                        title={u.is_active ? 'Click to disable' : 'Click to enable'}
                      >
                        {u.is_active ? <><UserCheck size={11} /> Active</> : <><UserX size={11} /> Disabled</>}
                      </button>
                    )}
                  </td>
                  <td className="px-4 py-3 text-zinc-500 text-xs">
                    {new Date(u.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1.5">
                      {feedback?.id === u.id && (
                        <span className={`text-xs ${feedback.type === 'success' ? 'text-emerald-300' : 'text-red-400'}`}>
                          {feedback.msg}
                        </span>
                      )}
                      {u.mfa_enabled && (
                        <button
                          onClick={() => { if (confirm(`Reset 2FA for ${u.email}?`)) resetMfaMutation.mutate(u.id) }}
                          className="p-1.5 rounded"
                          style={{ color: 'var(--text-4)', transition: 'color 150ms ease' }}
                          onMouseEnter={e => (e.currentTarget.style.color = '#facc15')}
                          onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-4)')}
                          title="Reset 2FA"
                        >
                          <RotateCcw size={14} />
                        </button>
                      )}
                      <button
                        onClick={() => { if (confirm(`Delete ${u.email}? This cannot be undone.`)) deleteMutation.mutate(u.id) }}
                        className="p-1.5 rounded"
                        style={{ color: 'var(--text-4)', transition: 'color 150ms ease' }}
                        onMouseEnter={e => (e.currentTarget.style.color = '#f87171')}
                        onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-4)')}
                        title="Delete user"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Role descriptions */}
      <div className="grid grid-cols-3 gap-3 pt-1">
        {[
          { role: 'Admin', color: '#34d399', desc: 'Full access including Settings & Integrations' },
          { role: 'Analyst', color: '#60a5fa', desc: 'Read/write on data pages, no Settings or Integrations' },
          { role: 'Viewer', color: 'var(--text-3)', desc: 'Read-only access to all data pages' },
        ].map(({ role, color, desc }) => (
          <div key={role} className="rounded-lg p-3" style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
            <div className="text-xs font-semibold mb-1" style={{ color }}>{role}</div>
            <div className="text-xs text-zinc-500">{desc}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── My Account tab ───────────────────────────────────────────────────────────

function AccountTab() {
  const { user } = useAuthStore()
  const [pwCurrent, setPwCurrent] = useState('')
  const [pwNew, setPwNew] = useState('')
  const [pwConfirm, setPwConfirm] = useState('')
  const [pwShowCurrent, setPwShowCurrent] = useState(false)
  const [pwShowNew, setPwShowNew] = useState(false)
  const [pwMsg, setPwMsg] = useState<{ type: 'error' | 'success'; msg: string } | null>(null)

  // MFA state
  const [mfaStep, setMfaStep] = useState<'idle' | 'setup' | 'disable'>('idle')
  const [qrData, setQrData] = useState<{ secret: string; uri: string; qr_code: string } | null>(null)
  const [mfaCode, setMfaCode] = useState('')
  const [mfaMsg, setMfaMsg] = useState<{ type: 'error' | 'success'; msg: string } | null>(null)
  const [mfaLoading, setMfaLoading] = useState(false)

  // We re-fetch "me" to get current mfa_enabled state
  const { data: me, refetch: refetchMe } = useQuery({
    queryKey: ['settings-me'],
    queryFn: () => apiClient.get('/settings/me').then(r => r.data as AuthUserDetail),
  })

  const changePw = async (e: React.FormEvent) => {
    e.preventDefault()
    setPwMsg(null)
    if (pwNew !== pwConfirm) { setPwMsg({ type: 'error', msg: 'New passwords do not match' }); return }
    if (pwNew.length < 8) { setPwMsg({ type: 'error', msg: 'Password must be at least 8 characters' }); return }
    try {
      await apiClient.post('/settings/me/password', { current_password: pwCurrent, new_password: pwNew })
      setPwMsg({ type: 'success', msg: 'Password changed successfully' })
      setPwCurrent(''); setPwNew(''); setPwConfirm('')
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Failed to change password'
      setPwMsg({ type: 'error', msg })
    }
  }

  const startMfaSetup = async () => {
    setMfaLoading(true)
    setMfaMsg(null)
    try {
      const res = await apiClient.get('/settings/me/mfa/setup')
      setQrData(res.data)
      setMfaStep('setup')
      setMfaCode('')
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Error starting 2FA setup'
      setMfaMsg({ type: 'error', msg })
    } finally {
      setMfaLoading(false)
    }
  }

  const enableMfa = async () => {
    setMfaLoading(true)
    setMfaMsg(null)
    try {
      await apiClient.post('/settings/me/mfa/enable', { code: mfaCode })
      setMfaMsg({ type: 'success', msg: '2FA enabled! You will be prompted for a code at each login.' })
      setMfaStep('idle')
      setMfaCode('')
      setQrData(null)
      refetchMe()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Invalid code'
      setMfaMsg({ type: 'error', msg })
    } finally {
      setMfaLoading(false)
    }
  }

  const disableMfa = async () => {
    setMfaLoading(true)
    setMfaMsg(null)
    try {
      await apiClient.delete('/settings/me/mfa', { data: { code: mfaCode } })
      setMfaMsg({ type: 'success', msg: '2FA disabled' })
      setMfaStep('idle')
      setMfaCode('')
      refetchMe()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Invalid code'
      setMfaMsg({ type: 'error', msg })
    } finally {
      setMfaLoading(false)
    }
  }

  const mfaEnabled = me?.mfa_enabled ?? false

  return (
    <div className="space-y-6 max-w-lg">
      {/* Profile info */}
      <div className="rounded-xl p-5" style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 bg-emerald-600/20 rounded-full flex items-center justify-center text-emerald-400 font-bold">
            {user?.email?.[0]?.toUpperCase()}
          </div>
          <div>
            <div className="text-white font-medium">{user?.email}</div>
            <RoleBadge role={user?.role ?? 'viewer'} />
          </div>
        </div>
      </div>

      {/* Change password */}
      <div className="rounded-xl p-5" style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
        <h3 className="text-sm font-semibold text-white mb-4">Change password</h3>
        {pwMsg && <div className="mb-3"><Alert type={pwMsg.type} msg={pwMsg.msg} /></div>}
        <form onSubmit={changePw} className="space-y-3">
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Current password</label>
            <div className="relative">
              <input
                type={pwShowCurrent ? 'text' : 'password'}
                value={pwCurrent}
                onChange={e => setPwCurrent(e.target.value)}
                required
                className="w-full bg-zinc-950 border border-white/[0.08] text-white rounded-lg px-3 py-2 pr-9 text-sm focus:outline-none focus:border-emerald-500"
              />
              <button type="button" onClick={() => setPwShowCurrent(!pwShowCurrent)} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300">
                {pwShowCurrent ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>
          <div>
            <label className="block text-xs text-zinc-400 mb-1">New password</label>
            <div className="relative">
              <input
                type={pwShowNew ? 'text' : 'password'}
                value={pwNew}
                onChange={e => setPwNew(e.target.value)}
                required
                className="w-full bg-zinc-950 border border-white/[0.08] text-white rounded-lg px-3 py-2 pr-9 text-sm focus:outline-none focus:border-emerald-500"
              />
              <button type="button" onClick={() => setPwShowNew(!pwShowNew)} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300">
                {pwShowNew ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Confirm new password</label>
            <input
              type="password"
              value={pwConfirm}
              onChange={e => setPwConfirm(e.target.value)}
              required
              className="w-full bg-zinc-950 border border-white/[0.08] text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
            />
          </div>
          <button
            type="submit"
            className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium px-4 py-2 rounded-lg pressable mt-1"
          >
            <Save size={14} /> Update password
          </button>
        </form>
      </div>

      {/* Two-factor authentication */}
      <div className="rounded-xl p-5" style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-semibold text-white">Two-factor authentication</h3>
            <p className="text-xs text-zinc-500 mt-0.5">Adds an extra layer of security using an authenticator app</p>
          </div>
          {mfaEnabled ? (
            <span className="flex items-center gap-1 text-xs text-emerald-300 font-medium bg-emerald-500/10 border border-green-500/20 px-2.5 py-1 rounded-full">
              <ShieldCheck size={13} /> Enabled
            </span>
          ) : (
            <span className="flex items-center gap-1 text-xs text-zinc-500 bg-gray-700/50 border border-gray-600 px-2.5 py-1 rounded-full">
              <ShieldOff size={13} /> Disabled
            </span>
          )}
        </div>

        {mfaMsg && <div className="mb-3"><Alert type={mfaMsg.type} msg={mfaMsg.msg} /></div>}

        {mfaStep === 'idle' && (
          <div>
            {!mfaEnabled ? (
              <button
                onClick={startMfaSetup}
                disabled={mfaLoading}
                className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-900 disabled:cursor-not-allowed text-white text-sm font-medium px-4 py-2 rounded-lg pressable"
              >
                <Smartphone size={14} /> {mfaLoading ? 'Loading…' : 'Enable 2FA'}
              </button>
            ) : (
              <button
                onClick={() => { setMfaStep('disable'); setMfaCode(''); setMfaMsg(null) }}
                className="flex items-center gap-1.5 bg-red-600/80 hover:bg-red-600 text-white text-sm font-medium px-4 py-2 rounded-lg pressable"
              >
                <ShieldOff size={14} /> Disable 2FA
              </button>
            )}
          </div>
        )}

        {mfaStep === 'setup' && qrData && (
          <div className="space-y-4">
            <div className="text-xs text-zinc-400 space-y-1.5">
              <p>1. Install <strong className="text-white">Google Authenticator</strong> or any TOTP app on your phone.</p>
              <p>2. Scan the QR code below, or enter the secret key manually.</p>
              <p>3. Enter the 6-digit code from the app to confirm.</p>
            </div>
            <div className="flex gap-4 items-start">
              <div className="bg-white p-2 rounded-lg flex-shrink-0">
                <img src={qrData.qr_code} alt="QR code" className="w-32 h-32" />
              </div>
              <div className="space-y-2 min-w-0">
                <div className="text-xs text-zinc-500">Secret key (manual entry)</div>
                <code className="block text-xs text-emerald-300 bg-zinc-950 border border-white/[0.08] rounded px-3 py-2 font-mono break-all">
                  {qrData.secret}
                </code>
              </div>
            </div>
            <div className="space-y-2">
              <label className="block text-xs text-zinc-400">Verification code</label>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                value={mfaCode}
                onChange={e => setMfaCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000000"
                className="w-40 bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-2 text-sm font-mono tracking-widest text-center focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div className="flex gap-2">
              <button
                onClick={enableMfa}
                disabled={mfaLoading || mfaCode.length !== 6}
                className="flex items-center gap-1.5 bg-green-600 hover:bg-emerald-500 disabled:bg-green-800 disabled:cursor-not-allowed text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
              >
                {mfaLoading ? 'Verifying…' : 'Activate 2FA'}
              </button>
              <button onClick={() => { setMfaStep('idle'); setQrData(null); setMfaCode(''); setMfaMsg(null) }} className="text-sm px-3 py-2"
                style={{ color: 'var(--text-2)', transition: 'color 150ms ease' }}
                onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-1)')}
                onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-2)')}>
                Cancel
              </button>
            </div>
          </div>
        )}

        {mfaStep === 'disable' && (
          <div className="space-y-3">
            <p className="text-xs text-zinc-400">Enter your current authenticator code to confirm disabling 2FA.</p>
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={mfaCode}
              onChange={e => setMfaCode(e.target.value.replace(/\D/g, ''))}
              placeholder="000000"
              autoFocus
              className="w-40 bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-2 text-sm font-mono tracking-widest text-center focus:outline-none focus:border-emerald-500"
            />
            <div className="flex gap-2">
              <button
                onClick={disableMfa}
                disabled={mfaLoading || mfaCode.length !== 6}
                className="flex items-center gap-1.5 bg-red-600 hover:bg-red-500 disabled:bg-red-900 disabled:cursor-not-allowed text-white text-sm font-medium px-4 py-2 rounded-lg pressable"
              >
                {mfaLoading ? 'Verifying…' : 'Confirm disable'}
              </button>
              <button onClick={() => { setMfaStep('idle'); setMfaCode(''); setMfaMsg(null) }} className="text-sm px-3 py-2"
                style={{ color: 'var(--text-2)', transition: 'color 150ms ease' }}
                onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-1)')}
                onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-2)')}>
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Platform settings tab ─────────────────────────────────────────────────────

function PlatformTab() {
  const { data: cfg, isLoading, refetch } = useQuery<SystemSettings>({
    queryKey: ['system-settings'],
    queryFn: () => apiClient.get('/settings/system').then(r => r.data),
  })

  const [form, setForm] = useState<SystemSettings | null>(null)
  const [msg, setMsg] = useState<{ type: 'error' | 'success'; msg: string } | null>(null)
  const [saving, setSaving] = useState(false)

  React.useEffect(() => {
    if (cfg) setForm(current => current ?? cfg)
  }, [cfg])

  if (isLoading || !form) return (
    <div className="space-y-5 max-w-2xl py-2">
      {[180, 280, 240, 320, 200].map((w, i) => (
        <div key={i} className="rounded-xl overflow-hidden" style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
          <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
            <div className="shimmer h-3 rounded w-32" />
          </div>
          {[...Array(i === 1 ? 4 : 2)].map((_, j) => (
            <div key={j} className="flex items-center justify-between px-4 py-3" style={j > 0 ? { borderTop: '1px solid var(--border)' } : {}}>
              <div className="shimmer h-3.5 rounded" style={{ width: w - j * 20 }} />
              <div className="shimmer h-8 rounded-lg w-24" />
            </div>
          ))}
        </div>
      ))}
    </div>
  )

  const set = <K extends keyof SystemSettings>(key: K, val: SystemSettings[K]) =>
    setForm(f => f ? { ...f, [key]: val } : f)

  const save = async () => {
    setSaving(true)
    setMsg(null)
    try {
      await apiClient.put('/settings/system', form)
      setMsg({ type: 'success', msg: 'Settings saved' })
      refetch()
    } catch {
      setMsg({ type: 'error', msg: 'Failed to save settings' })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-5 max-w-2xl">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-white">Platform settings</h2>
          <p className="text-xs text-zinc-500 mt-0.5">Configure system behaviour and security policies</p>
        </div>
        {msg && <Alert type={msg.type} msg={msg.msg} />}
      </div>

      {/* Branding */}
      <Section title="Branding">
        <Field label="Platform name">
          <input
            type="text"
            value={form.platform_name}
            onChange={e => set('platform_name', e.target.value)}
            className="bg-zinc-950 border border-white/[0.08] text-white rounded-lg px-3 py-2 text-sm w-64 focus:outline-none focus:border-emerald-500"
          />
        </Field>
      </Section>

      {/* Agent version requirements */}
      <Section title="Minimum agent versions" hint="Setting a version marks it as required and adds it to compliance. Leave blank to skip.">
        <Field label="SentinelOne minimum version" hint="e.g. 23.1.0.0">
          <input
            type="text"
            value={form.min_s1_version}
            onChange={e => set('min_s1_version', e.target.value)}
            placeholder="e.g. 23.1.0.0"
            className="bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-1.5 text-sm w-44 font-mono focus:outline-none focus:border-emerald-500"
          />
        </Field>
        <Field label="Symantec DLP minimum version" hint="e.g. 15.7.0">
          <input
            type="text"
            value={form.min_dlp_version}
            onChange={e => set('min_dlp_version', e.target.value)}
            placeholder="e.g. 15.7.0"
            className="bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-1.5 text-sm w-44 font-mono focus:outline-none focus:border-emerald-500"
          />
        </Field>
        <Field label="Symantec WSS minimum version" hint="e.g. 9.8.1 — also marks WSS as required">
          <input
            type="text"
            value={form.min_wss_version}
            onChange={e => set('min_wss_version', e.target.value)}
            placeholder="e.g. 9.8.1"
            className="bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-1.5 text-sm w-44 font-mono focus:outline-none focus:border-emerald-500"
          />
        </Field>
      </Section>

      {/* Endpoint monitoring */}
      <Section title="Endpoint monitoring">
        <Field label="Offline threshold" hint="Hours before an endpoint is considered offline">
          <NumberInput value={form.offline_threshold_hours} min={1} max={720} onChange={v => set('offline_threshold_hours', v)} suffix="hours" />
        </Field>
      </Section>

      {/* Risk weights */}
      <Section title="Risk score weights" hint="Each weight contributes to the endpoint's risk score (0–100)">
        {([
          ['EDR not installed', 'risk_weight_no_edr'],
          ['EDR version outdated', 'risk_weight_edr_version'],
          ['DLP not installed', 'risk_weight_no_dlp'],
          ['DLP version outdated', 'risk_weight_dlp_version'],
          ['No user assigned', 'risk_weight_no_user'],
        ] as [string, keyof SystemSettings][]).map(([label, key]) => (
          <Field key={key} label={label}>
            <NumberInput value={form[key] as number} min={0} max={100} step={5} onChange={v => set(key, v)} suffix="pts" />
          </Field>
        ))}
      </Section>

      {/* Security policies */}
      <Section title="Security policies">
        <Field label="Enforce 2FA for all users" hint="Users without 2FA will be warned on login">
          <Toggle checked={form.enforce_mfa} onChange={v => set('enforce_mfa', v)} />
        </Field>
        <Field label="Minimum password length">
          <NumberInput value={form.min_password_length} min={6} max={64} onChange={v => set('min_password_length', v)} suffix="chars" />
        </Field>
        <Field label="Session timeout">
          <NumberInput value={form.session_timeout_hours} min={1} max={720} onChange={v => set('session_timeout_hours', v)} suffix="hours" />
        </Field>
      </Section>

      {/* Automation */}
      <Section title="Automation">
        <Field label="Auto-correlation" hint="Automatically correlate users and endpoints across data sources">
          <Toggle checked={form.auto_correlation} onChange={v => set('auto_correlation', v)} />
        </Field>
      </Section>

      <button
        onClick={save}
        disabled={saving}
        className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-900 text-white text-sm font-semibold px-5 py-2.5 rounded-lg pressable"
      >
        <Save size={14} /> {saving ? 'Saving…' : 'Save changes'}
      </button>
    </div>
  )
}

function Section({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl overflow-hidden" style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
      <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border)', background: 'var(--surface-inset-strong)' }}>
        <div className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">{title}</div>
        {hint && <div className="text-xs text-zinc-500 mt-0.5">{hint}</div>}
      </div>
      <div style={{ '--divide-color': 'var(--border)' } as React.CSSProperties}>
        {React.Children.map(children, (child, i) =>
          i === 0 ? child : <div style={{ borderTop: '1px solid var(--border)' }}>{child}</div>
        )}
      </div>
    </div>
  )
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between px-4 py-3">
      <div>
        <div className="text-sm text-zinc-300">{label}</div>
        {hint && <div className="text-xs text-zinc-500 mt-0.5">{hint}</div>}
      </div>
      <div>{children}</div>
    </div>
  )
}

function NumberInput({ value, min, max, step = 1, onChange, suffix }: {
  value: number; min: number; max: number; step?: number;
  onChange: (v: number) => void; suffix?: string
}) {
  return (
    <div className="flex items-center gap-2">
      <input
        type="number"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={e => onChange(Number(e.target.value))}
        className="w-20 bg-zinc-950 border border-white/[0.08] text-white rounded-lg px-3 py-1.5 text-sm text-right focus:outline-none focus:border-emerald-500"
      />
      {suffix && <span className="text-xs text-zinc-500">{suffix}</span>}
    </div>
  )
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className="relative inline-flex h-5 w-9 items-center rounded-full pressable"
      style={{
        background: checked ? 'var(--accent)' : 'var(--surface-3)',
        border: '1px solid var(--border-mid)',
        transition: 'background-color 150ms ease',
      }}
    >
      <span
        className="inline-block h-3.5 w-3.5 rounded-full bg-white"
        style={{
          transform: checked ? 'translateX(18px)' : 'translateX(3px)',
          transition: 'transform 150ms ease',
          boxShadow: '0 1px 3px rgba(0,0,0,0.4)',
        }}
      />
    </button>
  )
}

// ── Google SSO (SAML) tab ─────────────────────────────────────────────────────

interface SamlSettings {
  saml_enabled: boolean
  saml_sp_entity_id: string
  saml_sp_acs_url: string
  saml_idp_entity_id: string
  saml_idp_sso_url: string
  saml_idp_cert: string
  saml_default_role: string
  saml_allowed_emails: string
  saml_require_mfa: boolean
  saml_sp_cert: string
  has_sp_key: boolean
}

function parseIdpMetadata(xml: string): { entityId: string; ssoUrl: string; cert: string } {
  const doc = new DOMParser().parseFromString(xml, 'application/xml')
  if (doc.querySelector('parsererror')) throw new Error('Invalid XML — could not parse the metadata file.')

  const entityId = doc.documentElement.getAttribute('entityID') ?? ''

  const ssoEl = Array.from(doc.querySelectorAll('SingleSignOnService')).find(
    el => el.getAttribute('Binding')?.includes('HTTP-Redirect'),
  )
  const ssoUrl = ssoEl?.getAttribute('Location') ?? ''

  // Prefer the signing cert; fall back to any cert present
  const signingKey = Array.from(doc.querySelectorAll('KeyDescriptor')).find(
    el => el.getAttribute('use') === 'signing',
  )
  const cert = (signingKey ?? doc).querySelector?.('X509Certificate')?.textContent?.replace(/\s+/g, '') ?? ''

  return { entityId, ssoUrl, cert }
}

function SsoTab() {
  const { data: remote, isLoading, refetch } = useQuery<SamlSettings>({
    queryKey: ['saml-settings'],
    queryFn: () => apiClient.get('/settings/saml').then(r => r.data),
  })

  const [form, setForm] = useState<(SamlSettings & { saml_sp_key: string }) | null>(null)
  const [msg, setMsg] = useState<{ type: 'error' | 'success'; msg: string } | null>(null)
  const [saving, setSaving] = useState(false)
  const [copied, setCopied] = useState(false)
  const [metaMsg, setMetaMsg] = useState<{ type: 'error' | 'success'; msg: string } | null>(null)
  const metaInputRef = useRef<HTMLInputElement>(null)

  const handleMetadataUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      try {
        const { entityId, ssoUrl, cert } = parseIdpMetadata(reader.result as string)
        setForm(f => f ? {
          ...f,
          saml_idp_entity_id: entityId || f.saml_idp_entity_id,
          saml_idp_sso_url:   ssoUrl   || f.saml_idp_sso_url,
          saml_idp_cert:      cert     || f.saml_idp_cert,
        } : f)
        setMetaMsg({ type: 'success', msg: `Metadata loaded from "${file.name}" — review the fields below and save.` })
      } catch (err: unknown) {
        setMetaMsg({ type: 'error', msg: (err as Error).message ?? 'Failed to parse metadata file.' })
      }
    }
    reader.readAsText(file)
    // reset so the same file can be re-uploaded
    e.target.value = ''
  }

  React.useEffect(() => {
    if (remote) {
      setForm(current => current ?? {
        ...remote,
        saml_sp_entity_id:   remote.saml_sp_entity_id   || window.location.origin,
        saml_sp_acs_url:     remote.saml_sp_acs_url     || `${window.location.origin}/api/auth/saml/acs`,
        saml_allowed_emails: remote.saml_allowed_emails ?? '',
        saml_require_mfa:    remote.saml_require_mfa    ?? false,
        saml_sp_key: '',
      })
    }
  }, [remote])

  if (isLoading || !form) return (
    <div className="space-y-5 max-w-2xl py-2">
      {[...Array(4)].map((_, i) => (
        <div key={i} className="rounded-xl overflow-hidden" style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
          <div className="px-4 py-3" style={{ borderBottom: '1px solid var(--border)' }}>
            <div className="shimmer h-3 rounded w-28" />
          </div>
          {[...Array(2)].map((_, j) => (
            <div key={j} className="flex items-center justify-between px-4 py-3" style={j > 0 ? { borderTop: '1px solid var(--border)' } : {}}>
              <div className="shimmer h-3.5 rounded w-40" />
              <div className="shimmer h-8 rounded-lg w-20" />
            </div>
          ))}
        </div>
      ))}
    </div>
  )

  const set = <K extends keyof typeof form>(key: K, val: (typeof form)[K]) =>
    setForm(f => f ? { ...f, [key]: val } : f)

  const metadataUrl = `${window.location.origin}/api/auth/saml/metadata`

  const copyAcsUrl = () => {
    navigator.clipboard.writeText(form.saml_sp_acs_url || `${window.location.origin}/api/auth/saml/acs`)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const save = async () => {
    setSaving(true)
    setMsg(null)
    try {
      await apiClient.put('/settings/saml', form)
      setMsg({ type: 'success', msg: 'SSO settings saved' })
      refetch()
    } catch (e: unknown) {
      const detail = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setMsg({ type: 'error', msg: detail ?? 'Failed to save SSO settings' })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-5 max-w-2xl">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-white">Google SSO (SAML 2.0)</h2>
          <p className="text-xs text-zinc-500 mt-0.5">Allow users to sign in with their Google Workspace account</p>
        </div>
        {msg && <Alert type={msg.type} msg={msg.msg} />}
      </div>

      {/* Enable toggle */}
      <Section title="SSO Status">
        <Field label="Enable Google SSO" hint="When enabled, a 'Sign in with Google SSO' button appears on the login page">
          <Toggle checked={form.saml_enabled} onChange={v => set('saml_enabled', v)} />
        </Field>
        <Field label="Default role for new SSO users" hint="Applied when a user logs in via SSO for the first time">
          <select
            value={form.saml_default_role}
            onChange={e => set('saml_default_role', e.target.value)}
            className="bg-zinc-950 border border-white/[0.08] text-white rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-emerald-500"
          >
            <option value="viewer">Viewer</option>
            <option value="analyst">Analyst</option>
            <option value="admin">Admin</option>
          </select>
        </Field>
        <Field label="Require 2FA after SSO" hint="Users must enter their authenticator code after Google sign-in">
          <Toggle checked={form.saml_require_mfa} onChange={v => set('saml_require_mfa', v)} />
        </Field>
      </Section>

      {/* Service Provider config */}
      <Section title="Service Provider (this app)" hint="Enter these values when creating the SAML app in Google Admin Console">
        <Field label="SP Entity ID" hint="A unique URI identifying this service provider">
          <input
            type="text"
            value={form.saml_sp_entity_id}
            onChange={e => set('saml_sp_entity_id', e.target.value)}
            placeholder={`${window.location.origin}`}
            className="bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-1.5 text-sm w-80 focus:outline-none focus:border-emerald-500"
          />
        </Field>
        <Field label="ACS URL" hint="Where Google POSTs the SAML response — register this in Google Admin">
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={form.saml_sp_acs_url}
              onChange={e => set('saml_sp_acs_url', e.target.value)}
              placeholder={`${window.location.origin}/api/auth/saml/acs`}
              className="bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-1.5 text-sm w-80 focus:outline-none focus:border-emerald-500"
            />
            <button
              type="button"
              onClick={copyAcsUrl}
              title="Copy ACS URL"
              className="p-1.5"
              style={{ color: 'var(--text-4)', transition: 'color 150ms ease' }}
              onMouseEnter={e => (e.currentTarget.style.color = '#34d399')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-4)')}
            >
              {copied ? <CheckCircle2 size={15} className="text-emerald-300" /> : <Copy size={15} />}
            </button>
          </div>
        </Field>
        <Field label="SP Metadata" hint="Upload this XML to Google Admin to auto-configure the IdP settings">
          <a
            href={metadataUrl}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 text-sm"
            style={{ color: 'var(--accent)', transition: 'color 150ms ease' }}
            onMouseEnter={e => (e.currentTarget.style.color = '#6ee7b7')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--accent)')}
          >
            <ExternalLink size={13} /> Download metadata XML
          </a>
        </Field>
      </Section>

      {/* IdP metadata upload */}
      <div className="rounded-xl p-4 space-y-3" style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
        <div>
          <div className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">Import IdP metadata</div>
          <p className="text-xs text-zinc-500 mt-1">
            Download the metadata XML from Google Admin Console and upload it here to auto-fill all IdP fields.
            In Google Admin go to <em>Apps &gt; Web and mobile apps &gt; your SAML app &gt; Download metadata</em>.
          </p>
        </div>
        {metaMsg && <Alert type={metaMsg.type} msg={metaMsg.msg} />}
        <div className="flex items-center gap-3">
          <input
            ref={metaInputRef}
            type="file"
            accept=".xml,text/xml,application/xml"
            className="hidden"
            onChange={handleMetadataUpload}
          />
          <button
            type="button"
            onClick={() => metaInputRef.current?.click()}
            className="flex items-center gap-2 text-white text-sm font-medium px-4 py-2 rounded-lg pressable"
            style={{ background: 'var(--surface-3)', border: '1px solid var(--border-mid)', transition: 'background-color 150ms ease, border-color 150ms ease' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--text-4)'; e.currentTarget.style.background = '#27272a' }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border-mid)'; e.currentTarget.style.background = 'var(--surface-3)' }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
            </svg>
            Upload metadata XML
          </button>
          <span className="text-xs text-zinc-500">or fill in the fields manually below</span>
        </div>
      </div>

      {/* Identity Provider config */}
      <Section title="Identity Provider (Google)" hint="These fields are populated automatically when you upload the metadata XML above">
        <Field label="IdP Entity ID">
          <input
            type="text"
            value={form.saml_idp_entity_id}
            onChange={e => set('saml_idp_entity_id', e.target.value)}
            placeholder="https://accounts.google.com/o/saml2?idpid=..."
            className="bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-1.5 text-sm w-80 focus:outline-none focus:border-emerald-500"
          />
        </Field>
        <Field label="SSO URL">
          <input
            type="text"
            value={form.saml_idp_sso_url}
            onChange={e => set('saml_idp_sso_url', e.target.value)}
            placeholder="https://accounts.google.com/o/saml2/idp?idpid=..."
            className="bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-1.5 text-sm w-80 focus:outline-none focus:border-emerald-500"
          />
        </Field>
        <div className="px-4 py-3">
          <div className="text-sm text-zinc-300 mb-1.5">IdP Certificate</div>
          <div className="text-xs text-zinc-500 mb-2">Paste the x509 certificate from Google Admin (no <code className="text-zinc-400">-----BEGIN/END CERTIFICATE-----</code> headers)</div>
          <textarea
            value={form.saml_idp_cert}
            onChange={e => set('saml_idp_cert', e.target.value)}
            placeholder="MIID...paste certificate here...=="
            rows={4}
            className="w-full bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500 resize-y"
          />
        </div>
      </Section>

      {/* Optional SP signing */}
      <Section title="SP Signing (optional)" hint="Only needed if Google requires signed AuthnRequests">
        <div className="px-4 py-3">
          <div className="text-sm text-zinc-300 mb-1.5">SP Certificate</div>
          <textarea
            value={form.saml_sp_cert}
            onChange={e => set('saml_sp_cert', e.target.value)}
            placeholder="Leave blank if SP signing is not required"
            rows={3}
            className="w-full bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500 resize-y"
          />
        </div>
        <div className="px-4 py-3">
          <div className="flex items-center gap-2 mb-1.5">
            <div className="text-sm text-zinc-300">SP Private Key</div>
            {remote?.has_sp_key && (
              <span className="inline-flex items-center gap-1 text-xs text-emerald-300 bg-emerald-500/10 border border-green-500/20 px-2 py-0.5 rounded-full">
                <KeyRound size={10} /> Key saved
              </span>
            )}
          </div>
          <textarea
            value={form.saml_sp_key}
            onChange={e => set('saml_sp_key', e.target.value)}
            placeholder={remote?.has_sp_key ? 'Leave blank to keep the existing key' : 'Paste private key here (PEM format, no headers)'}
            rows={3}
            className="w-full bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-2 text-xs font-mono focus:outline-none focus:border-emerald-500 resize-y"
          />
        </div>
      </Section>

      {/* Setup instructions */}
      <div className="bg-emerald-500/5 border border-emerald-500/10 rounded-xl p-4 text-xs text-zinc-400 space-y-1.5">
        <div className="text-emerald-400 font-semibold mb-2 text-sm">Google Admin setup steps</div>
        <p>1. In <strong className="text-white">Google Admin Console</strong> go to <em>Apps &gt; Web and mobile apps &gt; Add app &gt; Add custom SAML app</em></p>
        <p>2. Name the app (e.g. "SEC360"), then click <em>Continue</em></p>
        <p>3. Copy the <strong className="text-white">SSO URL</strong>, <strong className="text-white">Entity ID</strong>, and <strong className="text-white">Certificate</strong> into the fields above</p>
        <p>4. Set <strong className="text-white">ACS URL</strong> to the value shown above and <strong className="text-white">Entity ID</strong> to your SP Entity ID</p>
        <p>5. Set <strong className="text-white">Name ID format</strong> to <em>EMAIL</em> and <strong className="text-white">Name ID</strong> to <em>Basic Information &gt; Primary email</em></p>
        <p>6. Save, enable the app for your org units, then toggle SSO on above and save</p>
      </div>

      <button
        onClick={save}
        disabled={saving}
        className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-900 text-white text-sm font-semibold px-5 py-2.5 rounded-lg pressable"
      >
        <Save size={14} /> {saving ? 'Saving…' : 'Save SSO settings'}
      </button>
    </div>
  )
}

// ── Audit log tab ─────────────────────────────────────────────────────────────

function AuditTab() {
  const [page, setPage] = useState(0)
  const limit = 25

  const { data, isLoading } = useQuery<{ total: number; items: AuditEntry[] }>({
    queryKey: ['audit-log', page],
    queryFn: () => apiClient.get(`/settings/audit?limit=${limit}&offset=${page * limit}`).then(r => r.data),
  })

  const total = data?.total ?? 0
  const items = data?.items ?? []
  const totalPages = Math.max(1, Math.ceil(total / limit))

  const actionColor: Record<string, string> = {
    create: 'text-emerald-300',
    update: 'text-emerald-400',
    delete: 'text-red-400',
    login: 'text-yellow-400',
    logout: 'text-zinc-400',
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-white">Audit log</h2>
          <p className="text-xs text-zinc-500 mt-0.5">{total.toLocaleString()} events recorded</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-zinc-400">
          <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
            className="px-2.5 py-1 rounded disabled:opacity-40"
            style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', transition: 'border-color 150ms ease' }}
            onMouseEnter={e => !e.currentTarget.disabled && (e.currentTarget.style.borderColor = 'var(--border-mid)')}
            onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}>
            ← Prev
          </button>
          <span>Page {page + 1} / {totalPages}</span>
          <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
            className="px-2.5 py-1 rounded disabled:opacity-40"
            style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', transition: 'border-color 150ms ease' }}
            onMouseEnter={e => !e.currentTarget.disabled && (e.currentTarget.style.borderColor = 'var(--border-mid)')}
            onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}>
            Next →
          </button>
        </div>
      </div>

      <div className="rounded-xl overflow-hidden" style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
        {isLoading ? (
          <div className="p-4 space-y-2">
            {[...Array(8)].map((_, i) => (
              <div key={i} className="flex items-center gap-3 px-1 py-1.5">
                <div className="shimmer h-3 rounded w-32 flex-shrink-0" />
                <div className="shimmer h-3 rounded w-16" />
                <div className="shimmer h-3 rounded w-28" />
                <div className="shimmer h-3 rounded w-20" />
                <div className="shimmer h-3 rounded flex-1 max-w-[200px]" />
              </div>
            ))}
          </div>
        ) : items.length === 0 ? (
          <div className="text-center py-12 text-zinc-600 text-sm">No audit events yet</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-zinc-500 uppercase tracking-wider" style={{ borderBottom: '1px solid var(--border)' }}>
                <th className="text-left px-4 py-3">Timestamp</th>
                <th className="text-left px-4 py-3">Action</th>
                <th className="text-left px-4 py-3">Resource</th>
                <th className="text-left px-4 py-3">IP</th>
                <th className="text-left px-4 py-3">Details</th>
              </tr>
            </thead>
            <tbody>
              {items.map(entry => (
                <tr key={entry.id} style={{ borderTop: '1px solid var(--border)' }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--hover-2)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                  <td className="px-4 py-3 text-zinc-400 text-xs whitespace-nowrap">{fmtDate(entry.timestamp)}</td>
                  <td className="px-4 py-3">
                    <span className={`font-medium text-xs ${actionColor[entry.action?.toLowerCase()] ?? 'text-zinc-300'}`}>
                      {entry.action}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-zinc-400">
                    {entry.resource_type}{entry.resource_id ? ` · ${entry.resource_id.slice(0, 8)}…` : ''}
                  </td>
                  <td className="px-4 py-3 text-xs text-zinc-500">{entry.ip_address ?? '—'}</td>
                  <td className="px-4 py-3 text-xs text-zinc-500 max-w-xs truncate">
                    {entry.details ? JSON.stringify(entry.details) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

// ── Main Settings page ────────────────────────────────────────────────────────

export default function Settings() {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const [tab, setTab] = useState<Tab>(isAdmin ? 'users' : 'account')

  const tabs: { id: Tab; label: string; icon: React.ElementType; adminOnly: boolean }[] = [
    { id: 'users', label: 'Users & Access', icon: Users, adminOnly: true },
    { id: 'account', label: 'My Account', icon: User, adminOnly: false },
    { id: 'platform', label: 'Platform', icon: Settings2, adminOnly: true },
    { id: 'sso', label: 'Google SSO', icon: KeyRound, adminOnly: true },
    { id: 'audit', label: 'Audit Log', icon: ClipboardList, adminOnly: true },
  ]

  const visibleTabs = tabs.filter(t => !t.adminOnly || isAdmin)

  return (
    <div className="absolute inset-0 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex-shrink-0 px-6 pt-6 pb-0">
        <h1 className="text-xl font-bold text-white mb-4">Settings</h1>
        {/* Tab bar */}
        <div className="flex gap-0.5 border-b border-white/[0.06]">
          {visibleTabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className="flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px"
              style={{
                color: tab === id ? '#34d399' : '#71717a',
                borderBottomColor: tab === id ? 'var(--accent)' : 'transparent',
                transition: 'color 150ms ease, border-color 150ms ease',
              }}
              onMouseEnter={e => { if (tab !== id) e.currentTarget.style.color = '#d4d4d8' }}
              onMouseLeave={e => { if (tab !== id) e.currentTarget.style.color = 'var(--text-3)' }}
            >
              <Icon size={15} />
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto px-6 py-5">
        {tab === 'users' && isAdmin && <UsersTab />}
        {tab === 'account' && <AccountTab />}
        {tab === 'platform' && isAdmin && <PlatformTab />}
        {tab === 'sso' && isAdmin && <SsoTab />}
        {tab === 'audit' && isAdmin && <AuditTab />}
      </div>
    </div>
  )
}
