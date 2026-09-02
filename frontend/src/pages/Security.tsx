import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Users,
  ClipboardList,
  Plus,
  Trash2,
  RotateCcw,
  ShieldCheck,
  ShieldOff,
  AlertCircle,
  CheckCircle2,
  X,
  UserCheck,
  UserX,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  Globe,
  LogIn,
  LogOut,
  Edit3,
  PlusCircle,
  MinusCircle,
  Key,
} from 'lucide-react'
import { useAuthStore } from '../store/auth'
import apiClient from '../api/client'

// ── Types ──────────────────────────────────────────────────────────────────────

interface AuthUserDetail {
  id: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
  is_active: boolean
  mfa_enabled: boolean
  created_at: string
}

interface AuditEntry {
  id: string
  action: string
  resource_type: string | null
  resource_id: string | null
  timestamp: string
  ip_address: string | null
  details: Record<string, unknown> | null
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function fmtDateShort(iso: string) {
  return new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
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

// ── Action metadata ─────────────────────────────────────────────────────────────

function getActionMeta(action: string): { icon: React.ElementType; color: string; label: string; category: string } {
  const a = action?.toLowerCase() ?? ''
  if (a.includes('login'))        return { icon: LogIn,       color: '#34d399', label: action, category: 'auth' }
  if (a.includes('logout'))       return { icon: LogOut,      color: 'var(--text-3)', label: action, category: 'auth' }
  if (a.includes('create') || a.includes('invite'))
                                   return { icon: PlusCircle,  color: '#4ade80', label: action, category: 'create' }
  if (a.includes('delete') || a.includes('remove'))
                                   return { icon: MinusCircle, color: '#f87171', label: action, category: 'delete' }
  if (a.includes('update') || a.includes('change') || a.includes('patch'))
                                   return { icon: Edit3,       color: '#60a5fa', label: action, category: 'update' }
  if (a.includes('mfa') || a.includes('password') || a.includes('token'))
                                   return { icon: Key,         color: '#f59e0b', label: action, category: 'auth' }
  return { icon: ClipboardList, color: 'var(--text-2)', label: action, category: 'other' }
}

const ACTION_CATEGORIES = [
  { id: 'all',    label: 'All events' },
  { id: 'auth',   label: 'Auth' },
  { id: 'create', label: 'Created' },
  { id: 'update', label: 'Updated' },
  { id: 'delete', label: 'Deleted' },
]

// ── Users tab ──────────────────────────────────────────────────────────────────

function UsersTab() {
  const qc = useQueryClient()
  const { user: me } = useAuthStore()
  const [showCreate, setShowCreate] = useState(false)
  const [createEmail, setCreateEmail] = useState('')
  const [createRole, setCreateRole] = useState<'admin' | 'analyst' | 'viewer'>('analyst')
  const [createErr, setCreateErr] = useState('')
  const [inviteSuccess, setInviteSuccess] = useState('')
  const [feedback, setFeedback] = useState<{ id: string; msg: string; type: 'success' | 'error' } | null>(null)

  const { data: users = [], isLoading } = useQuery<AuthUserDetail[]>({
    queryKey: ['security-users'],
    queryFn: () => apiClient.get('/settings/users').then(r => r.data),
  })

  const createMutation = useMutation({
    mutationFn: (body: { email: string; role: string }) =>
      apiClient.post('/settings/users/invite', body),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['security-users'] })
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
      qc.invalidateQueries({ queryKey: ['security-users'] })
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
    onSuccess: () => qc.invalidateQueries({ queryKey: ['security-users'] }),
  })

  const resetMfaMutation = useMutation({
    mutationFn: (id: string) => apiClient.post(`/settings/users/${id}/reset-mfa`),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ['security-users'] })
      setFeedback({ id, msg: '2FA reset', type: 'success' })
      setTimeout(() => setFeedback(null), 2000)
    },
  })

  const activeCount = users.filter(u => u.is_active).length
  const pendingCount = users.filter(u => !u.is_active && !u.mfa_enabled).length
  const mfaCount = users.filter(u => u.mfa_enabled).length

  return (
    <div className="space-y-5">
      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total users',    value: users.length, color: 'var(--text-2)' },
          { label: 'Active',         value: activeCount,  color: '#4ade80' },
          { label: 'Pending invite', value: pendingCount, color: '#fbbf24' },
          { label: '2FA enabled',    value: `${mfaCount} / ${users.length}`, color: '#34d399' },
        ].map(({ label, value, color }) => (
          <div key={label} className="rounded-xl px-4 py-3.5"
            style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
            <div className="text-xs text-zinc-500 mb-1">{label}</div>
            <div className="text-xl font-bold" style={{ color }}>{value}</div>
          </div>
        ))}
      </div>

      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-white">Platform users</h2>
          <p className="text-xs text-zinc-500 mt-0.5">Manage accounts, roles, and authentication</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1.5 text-white text-sm font-medium px-3.5 py-2 rounded-lg"
          style={{ background: 'var(--accent)', transition: 'opacity 150ms ease' }}
          onMouseEnter={e => (e.currentTarget.style.opacity = '0.85')}
          onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
        >
          <Plus size={15} /> Invite user
        </button>
      </div>

      {inviteSuccess && <Alert type="success" msg={inviteSuccess} />}

      {/* Invite panel */}
      {showCreate && (
        <div className="rounded-xl p-5 space-y-3"
          style={{ background: 'var(--surface-inset-strong)', border: '1px solid var(--border-lit)' }}>
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
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Email address</label>
              <input
                type="email" value={createEmail} onChange={e => setCreateEmail(e.target.value)}
                placeholder="user@company.com"
                className="w-full bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Role</label>
              <select value={createRole} onChange={e => setCreateRole(e.target.value as typeof createRole)}
                className="w-full bg-zinc-950 border border-white/[0.08] text-white rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500">
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
              className="flex items-center gap-1.5 text-white text-sm font-medium px-4 py-2 rounded-lg disabled:cursor-not-allowed"
              style={{ background: 'var(--accent)', opacity: (createMutation.isPending || !createEmail) ? 0.5 : 1 }}
            >
              {createMutation.isPending ? 'Sending…' : 'Send invitation'}
            </button>
            <button onClick={() => { setShowCreate(false); setCreateErr('') }}
              className="text-sm px-3 py-2"
              style={{ color: 'var(--text-2)', transition: 'color 150ms ease' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-1)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-2)')}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="rounded-xl overflow-hidden"
        style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
        {isLoading ? (
          <div className="p-4 space-y-2">
            {[...Array(5)].map((_, i) => (
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
              <tr className="text-xs text-zinc-500 uppercase tracking-wider"
                style={{ borderBottom: '1px solid var(--border)' }}>
                <th className="text-left px-4 py-3">User</th>
                <th className="text-left px-4 py-3">Role</th>
                <th className="text-left px-4 py-3">2FA</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-left px-4 py-3">Joined</th>
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
                      <div>
                        <div className="text-white font-medium">{u.email}</div>
                        {u.id === me?.id && (
                          <div className="text-[10px] text-zinc-600 mt-0.5">You</div>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <select value={u.role}
                      onChange={e => patchMutation.mutate({ id: u.id, body: { role: e.target.value } })}
                      className="bg-transparent border border-white/[0.08] text-zinc-300 rounded-md px-2 py-1 text-xs focus:outline-none focus:border-emerald-500 cursor-pointer">
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
                          transition: 'background 150ms, color 150ms, border-color 150ms',
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
                        title={u.is_active ? 'Click to disable' : 'Click to enable'}>
                        {u.is_active ? <><UserCheck size={11} /> Active</> : <><UserX size={11} /> Disabled</>}
                      </button>
                    )}
                  </td>
                  <td className="px-4 py-3 text-zinc-500 text-xs">
                    {fmtDateShort(u.created_at)}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
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
                          title="Reset 2FA">
                          <RotateCcw size={14} />
                        </button>
                      )}
                      <button
                        onClick={() => { if (confirm(`Delete ${u.email}? This cannot be undone.`)) deleteMutation.mutate(u.id) }}
                        className="p-1.5 rounded"
                        style={{ color: 'var(--text-4)', transition: 'color 150ms ease' }}
                        onMouseEnter={e => (e.currentTarget.style.color = '#f87171')}
                        onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-4)')}
                        title="Delete user">
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

      {/* Role legend */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { role: 'Admin',   color: '#34d399', desc: 'Full access including Settings & Integrations' },
          { role: 'Analyst', color: '#93c5fd', desc: 'Read/write on data pages, no admin functions' },
          { role: 'Viewer',  color: 'var(--text-3)', desc: 'Read-only access to all data pages' },
        ].map(({ role, color, desc }) => (
          <div key={role} className="rounded-lg p-3"
            style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
            <div className="text-xs font-semibold mb-1" style={{ color }}>{role}</div>
            <div className="text-xs text-zinc-500">{desc}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Audit Log tab ──────────────────────────────────────────────────────────────

function AuditTab() {
  const [page, setPage] = useState(0)
  const [actorSearch, setActorSearch] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const limit = 30

  const { data, isLoading } = useQuery<{ total: number; items: AuditEntry[] }>({
    queryKey: ['security-audit', page],
    queryFn: () => apiClient.get(`/settings/audit?limit=${limit}&offset=${page * limit}`).then(r => r.data),
  })

  const allItems = data?.items ?? []
  const total = data?.total ?? 0

  // Client-side filter (within loaded page)
  const items = allItems.filter(entry => {
    const actor = String(entry.details?.actor_email ?? '').toLowerCase()
    const matchesActor = !actorSearch || actor.includes(actorSearch.toLowerCase())
    const category = getActionMeta(entry.action).category
    const matchesCat = categoryFilter === 'all' || category === categoryFilter
    return matchesActor && matchesCat
  })

  const totalPages = Math.max(1, Math.ceil(total / limit))

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-white">Audit log</h2>
          <p className="text-xs text-zinc-500 mt-0.5">{total.toLocaleString()} events recorded — showing real client IP</p>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-3">
        {/* Actor search */}
        <div className="relative flex-1 max-w-xs">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none" />
          <input
            type="text"
            value={actorSearch}
            onChange={e => { setActorSearch(e.target.value); setPage(0) }}
            placeholder="Filter by user email…"
            className="w-full bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg pl-8 pr-3 py-1.5 text-sm focus:outline-none focus:border-emerald-500"
          />
          {actorSearch && (
            <button onClick={() => setActorSearch('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500"
              onMouseEnter={e => (e.currentTarget.style.color = '#d4d4d8')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-3)')}>
              <X size={12} />
            </button>
          )}
        </div>

        {/* Category pills */}
        <div className="flex items-center gap-1.5">
          <Filter size={13} className="text-zinc-600" />
          {ACTION_CATEGORIES.map(cat => (
            <button key={cat.id} onClick={() => { setCategoryFilter(cat.id); setPage(0) }}
              className="px-2.5 py-1 rounded-full text-xs font-medium"
              style={{
                background: categoryFilter === cat.id ? 'rgba(16,185,129,0.15)' : 'var(--hover-1)',
                color: categoryFilter === cat.id ? '#34d399' : '#71717a',
                border: `1px solid ${categoryFilter === cat.id ? 'rgba(16,185,129,0.3)' : 'var(--border)'}`,
                transition: 'all 150ms ease',
              }}>
              {cat.label}
            </button>
          ))}
        </div>

        {/* Pagination */}
        <div className="flex items-center gap-1.5 ml-auto text-xs text-zinc-400">
          <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
            className="p-1.5 rounded disabled:opacity-30"
            style={{ color: 'var(--text-3)', transition: 'color 150ms ease' }}
            onMouseEnter={e => !e.currentTarget.disabled && (e.currentTarget.style.color = '#d4d4d8')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-3)')}>
            <ChevronLeft size={15} />
          </button>
          <span className="px-1">Page {page + 1} / {totalPages}</span>
          <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
            className="p-1.5 rounded disabled:opacity-30"
            style={{ color: 'var(--text-3)', transition: 'color 150ms ease' }}
            onMouseEnter={e => !e.currentTarget.disabled && (e.currentTarget.style.color = '#d4d4d8')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-3)')}>
            <ChevronRight size={15} />
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl overflow-hidden"
        style={{ background: 'var(--surface-inset)', border: '1px solid var(--border)' }}>
        {isLoading ? (
          <div className="p-4 space-y-2">
            {[...Array(8)].map((_, i) => (
              <div key={i} className="flex items-center gap-4 px-1 py-1.5">
                <div className="shimmer h-3 rounded w-32 flex-shrink-0" />
                <div className="shimmer h-3 rounded w-44" />
                <div className="shimmer h-3 rounded w-24" />
                <div className="shimmer h-3 rounded w-28" />
                <div className="shimmer h-3 rounded flex-1 max-w-[180px]" />
              </div>
            ))}
          </div>
        ) : items.length === 0 ? (
          <div className="text-center py-16 text-zinc-600 text-sm">
            {actorSearch || categoryFilter !== 'all' ? 'No events match these filters' : 'No audit events yet'}
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-zinc-500 uppercase tracking-wider"
                style={{ borderBottom: '1px solid var(--border)' }}>
                <th className="text-left px-4 py-3">Timestamp</th>
                <th className="text-left px-4 py-3">Actor</th>
                <th className="text-left px-4 py-3">Action</th>
                <th className="text-left px-4 py-3">Resource</th>
                <th className="text-left px-4 py-3">
                  <span className="inline-flex items-center gap-1">
                    <Globe size={11} /> IP Address
                  </span>
                </th>
                <th className="text-left px-4 py-3">Details</th>
              </tr>
            </thead>
            <tbody>
              {items.map(entry => {
                const meta = getActionMeta(entry.action)
                const ActionIcon = meta.icon
                const actorEmail = String(entry.details?.actor_email ?? '—')
                // Separate known detail keys from actor metadata
                const extraDetails = entry.details
                  ? Object.fromEntries(
                      Object.entries(entry.details).filter(([k]) => !['actor_id', 'actor_email'].includes(k))
                    )
                  : {}
                const hasDetails = Object.keys(extraDetails).length > 0

                return (
                  <tr key={entry.id} style={{ borderTop: '1px solid var(--border)' }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'var(--hover-2)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>

                    {/* Timestamp */}
                    <td className="px-4 py-3 text-zinc-400 text-xs whitespace-nowrap font-mono">
                      {fmtDate(entry.timestamp)}
                    </td>

                    {/* Actor */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-5 h-5 rounded-full bg-emerald-600/20 flex items-center justify-center text-emerald-400 text-[9px] font-bold flex-shrink-0">
                          {actorEmail !== '—' ? actorEmail[0].toUpperCase() : '?'}
                        </div>
                        <span className="text-xs text-zinc-300 truncate max-w-[160px]" title={actorEmail}>
                          {actorEmail}
                        </span>
                      </div>
                    </td>

                    {/* Action */}
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1.5 text-xs font-medium"
                        style={{ color: meta.color }}>
                        <ActionIcon size={12} strokeWidth={2} />
                        {entry.action}
                      </span>
                    </td>

                    {/* Resource */}
                    <td className="px-4 py-3 text-xs text-zinc-400">
                      {entry.resource_type
                        ? <>
                            <span className="text-zinc-300">{entry.resource_type}</span>
                            {entry.resource_id && (
                              <span className="text-zinc-600"> · {entry.resource_id.slice(0, 8)}…</span>
                            )}
                          </>
                        : <span className="text-zinc-600">—</span>
                      }
                    </td>

                    {/* IP Address */}
                    <td className="px-4 py-3">
                      {entry.ip_address ? (
                        <span className="inline-flex items-center gap-1 text-xs font-mono text-zinc-300">
                          {entry.ip_address}
                        </span>
                      ) : (
                        <span className="text-xs text-zinc-600">—</span>
                      )}
                    </td>

                    {/* Details */}
                    <td className="px-4 py-3 text-xs text-zinc-500 max-w-[200px] truncate"
                      title={hasDetails ? JSON.stringify(extraDetails) : undefined}>
                      {hasDetails ? JSON.stringify(extraDetails) : <span className="text-zinc-700">—</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

type Tab = 'users' | 'audit'

export default function Security() {
  const [tab, setTab] = useState<Tab>('users')

  const tabs: { id: Tab; label: string; icon: React.ElementType }[] = [
    { id: 'users', label: 'Users & Access', icon: Users },
    { id: 'audit', label: 'Audit Log',      icon: ClipboardList },
  ]

  return (
    <div className="absolute inset-0 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex-shrink-0 px-6 pt-6 pb-0">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: 'var(--accent-dim)', border: '1px solid rgba(16,185,129,0.2)' }}>
            <ShieldCheck size={16} className="text-emerald-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white leading-none">Security</h1>
            <p className="text-xs text-zinc-500 mt-0.5">User access, roles, and audit trail</p>
          </div>
        </div>

        {/* Tab bar */}
        <div className="flex gap-0.5 border-b border-white/[0.06]">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setTab(id)}
              className="flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px"
              style={{
                color: tab === id ? '#34d399' : '#71717a',
                borderBottomColor: tab === id ? 'var(--accent)' : 'transparent',
                transition: 'color 150ms ease, border-color 150ms ease',
              }}
              onMouseEnter={e => { if (tab !== id) e.currentTarget.style.color = '#d4d4d8' }}
              onMouseLeave={e => { if (tab !== id) e.currentTarget.style.color = 'var(--text-3)' }}>
              <Icon size={15} />
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto px-6 py-5">
        {tab === 'users' && <UsersTab />}
        {tab === 'audit' && <AuditTab />}
      </div>
    </div>
  )
}
