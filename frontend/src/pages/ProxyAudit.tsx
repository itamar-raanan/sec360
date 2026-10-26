import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import {
  AlertCircle, CheckCircle2, ChevronLeft, ChevronRight, FileCode2,
  History, KeyRound, Loader2, RefreshCw, Search, Settings2, ShieldAlert,
  ShieldCheck, X,
} from 'lucide-react'

import {
  fetchProxyAuditConnection, fetchProxyAuditEvent, fetchProxyAuditEvents,
  fetchProxyAuditSummary, saveProxyAuditConnection, syncProxyAudit,
  testProxyAuditConnection, type ProxyAuditConnectionInput, type ProxyAuditEvent,
} from '../api/proxyAudit'
import { useAuthStore } from '../store/auth'

const PAGE_SIZE = 50

function errorText(error: unknown, fallback = 'The request could not be completed.') {
  return (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail || fallback
}

function dateTime(value: string | null) {
  if (!value) return 'Never'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

function relative(value: string | null) {
  if (!value) return 'Never'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : formatDistanceToNow(date, { addSuffix: true })
}

function Metric({ label, value, detail }: { label: string; value: string | number; detail: string }) {
  return <div className="ui-metric py-4"><p className="ui-context">{label}</p><p className="mt-2 font-mono text-[24px] font-semibold tracking-[-.05em]" style={{ color: 'var(--text-1)' }}>{typeof value === 'number' ? value.toLocaleString() : value}</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>{detail}</p></div>
}

function ConnectionDialog({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const connection = useQuery({ queryKey: ['proxy-audit-connection'], queryFn: fetchProxyAuditConnection })
  const [form, setForm] = useState<ProxyAuditConnectionInput>({ base_url: '', username: '', password: '', verify_ssl: true, timeout_seconds: 60 })
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)

  useEffect(() => {
    if (connection.data) setForm({
      base_url: connection.data.base_url,
      username: connection.data.username,
      password: '',
      verify_ssl: connection.data.verify_ssl,
      timeout_seconds: connection.data.timeout_seconds,
    })
  }, [connection.data])
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => event.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  const testMutation = useMutation({
    mutationFn: () => testProxyAuditConnection(form),
    onSuccess: result => {
      setTestResult(result)
      queryClient.invalidateQueries({ queryKey: ['proxy-audit-connection'] })
    },
  })
  const saveMutation = useMutation({
    mutationFn: () => saveProxyAuditConnection(form),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['proxy-audit-connection'] })
      onClose()
    },
  })
  const set = <K extends keyof ProxyAuditConnectionInput>(key: K, value: ProxyAuditConnectionInput[K]) => setForm(current => ({ ...current, [key]: value }))
  const canSubmit = Boolean(form.base_url.trim() && form.username.trim() && (form.password || connection.data?.configured))
  const mutationError = testMutation.error || saveMutation.error

  return <div className="dialog-backdrop" onMouseDown={onClose}>
    <section className="w-full max-w-[620px] overflow-hidden rounded-2xl border shadow-2xl fade-up" style={{ background: 'var(--surface-2)', borderColor: 'var(--border-lit)' }} onMouseDown={event => event.stopPropagation()} role="dialog" aria-modal="true" aria-label="Management Center connection">
      <header className="flex items-start justify-between border-b px-5 py-5" style={{ borderColor: 'var(--border)' }}><div className="flex items-start gap-3"><span className="dialog-icon"><KeyRound size={16} /></span><div><h2 className="text-[15px] font-semibold" style={{ color: 'var(--text-1)' }}>Management Center connection</h2><p className="mt-1 max-w-lg text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>Connect directly to the on-prem API. SEC360 bypasses environment proxies and encrypts the saved credential.</p></div></div><button className="ui-icon-button" onClick={onClose} aria-label="Close connection settings"><X size={15} /></button></header>
      <div className="space-y-4 p-5">
        {connection.isLoading ? <div className="space-y-3"><div className="shimmer h-14 rounded-lg" /><div className="shimmer h-14 rounded-lg" /><div className="shimmer h-14 rounded-lg" /></div> : <>
          <label className="block"><span className="ui-context">Management Center URL</span><input className="ui-control mt-2 w-full px-3 text-[11px]" value={form.base_url} onChange={event => set('base_url', event.target.value)} placeholder="https://management-center.example:8082" autoComplete="url" /><span className="mt-1.5 block text-[9px]" style={{ color: 'var(--text-4)' }}>Enter the server origin. SEC360 appends <code>/api</code>.</span></label>
          <div className="grid gap-4 sm:grid-cols-2"><label className="block"><span className="ui-context">API username</span><input className="ui-control mt-2 w-full px-3 text-[11px]" value={form.username} onChange={event => set('username', event.target.value)} autoComplete="username" /></label><label className="block"><span className="ui-context">API password</span><input className="ui-control mt-2 w-full px-3 text-[11px]" type="password" value={form.password} onChange={event => set('password', event.target.value)} placeholder={connection.data?.configured ? 'Leave blank to keep saved password' : 'Required'} autoComplete="new-password" /></label></div>
          <div className="grid gap-3 sm:grid-cols-[1fr_170px]"><label className="flex items-start gap-3 rounded-xl border p-3" style={{ borderColor: 'var(--border)', background: 'var(--surface-inset)' }}><input type="checkbox" checked={form.verify_ssl} onChange={event => set('verify_ssl', event.target.checked)} className="mt-0.5 accent-emerald-500" /><span><span className="block text-[11px] font-semibold" style={{ color: 'var(--text-2)' }}>Verify TLS certificate</span><span className="mt-1 block text-[9px] leading-4" style={{ color: 'var(--text-4)' }}>Recommended. Disable only for an internal self-signed certificate.</span></span></label><label className="block"><span className="ui-context">Timeout</span><select className="ui-control mt-2 w-full px-3 text-[11px]" value={form.timeout_seconds} onChange={event => set('timeout_seconds', Number(event.target.value))}><option value={30}>30 seconds</option><option value={60}>60 seconds</option><option value={120}>120 seconds</option></select></label></div>
          {!form.verify_ssl && <div className="flex items-start gap-2 rounded-lg border px-3 py-2.5 text-[10px]" style={{ borderColor: 'rgba(251,191,36,.23)', color: '#fbbf24', background: 'rgba(251,191,36,.05)' }}><ShieldAlert size={13} className="mt-0.5 shrink-0" />TLS identity verification is disabled. Traffic remains encrypted, but SEC360 cannot verify the server identity.</div>}
          {testResult && <div className="flex items-start gap-2 rounded-lg border px-3 py-2.5 text-[10px]" style={{ borderColor: testResult.success ? 'rgba(52,211,153,.23)' : 'rgba(251,113,133,.23)', color: testResult.success ? '#34d399' : '#fb7185', background: testResult.success ? 'rgba(52,211,153,.05)' : 'rgba(251,113,133,.05)' }}>{testResult.success ? <CheckCircle2 size={13} className="mt-0.5 shrink-0" /> : <AlertCircle size={13} className="mt-0.5 shrink-0" />}{testResult.message}</div>}
          {mutationError && <div className="flex items-start gap-2 rounded-lg border px-3 py-2.5 text-[10px]" style={{ borderColor: 'rgba(251,113,133,.23)', color: '#fb7185', background: 'rgba(251,113,133,.05)' }}><AlertCircle size={13} className="mt-0.5 shrink-0" />{errorText(mutationError)}</div>}
        </>}
      </div>
      <footer className="flex flex-wrap justify-end gap-2 border-t px-5 py-4" style={{ borderColor: 'var(--border)' }}><button className="ui-secondary-button" onClick={onClose}>Cancel</button><button className="ui-secondary-button disabled:opacity-40" disabled={!canSubmit || testMutation.isPending} onClick={() => { setTestResult(null); testMutation.mutate() }}>{testMutation.isPending ? <Loader2 size={13} className="animate-spin" /> : <ShieldCheck size={13} />} Test connection</button><button className="ui-primary-button disabled:opacity-40" disabled={!canSubmit || saveMutation.isPending} onClick={() => saveMutation.mutate()}>{saveMutation.isPending ? <Loader2 size={13} className="animate-spin" /> : <Settings2 size={13} />} Save connection</button></footer>
    </section>
  </div>
}

function ChangeDrawer({ eventId, onClose }: { eventId: string; onClose: () => void }) {
  const event = useQuery({ queryKey: ['proxy-audit-event', eventId], queryFn: () => fetchProxyAuditEvent(eventId) })
  useEffect(() => {
    const onKeyDown = (keyboardEvent: KeyboardEvent) => keyboardEvent.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  return <div className="dialog-backdrop justify-items-end p-0" onMouseDown={onClose}><aside className="flex h-[100dvh] w-full max-w-[760px] flex-col border-l shadow-2xl fade-up" style={{ background: 'var(--surface-1)', borderColor: 'var(--border-lit)' }} onMouseDown={click => click.stopPropagation()} role="dialog" aria-modal="true" aria-label="Policy revision details"><header className="flex items-start justify-between border-b px-5 py-5" style={{ borderColor: 'var(--border)' }}><div><p className="ui-context">Revision evidence</p><h2 className="mt-2 text-[16px] font-semibold" style={{ color: 'var(--text-1)' }}>{event.data?.policy_name || 'Loading revision…'}</h2><p className="mt-1 font-mono text-[9px]" style={{ color: 'var(--text-4)' }}>{event.data?.policy_uuid}</p></div><button className="ui-icon-button" onClick={onClose} aria-label="Close revision details"><X size={15} /></button></header><div className="flex-1 overflow-y-auto p-5">{event.isLoading ? <div className="space-y-4"><div className="shimmer h-24 rounded-xl" /><div className="shimmer h-96 rounded-xl" /></div> : event.isError || !event.data ? <div className="flex items-start gap-2 rounded-xl border p-4 text-[11px] text-red-400" style={{ borderColor: 'rgba(251,113,133,.2)' }}><AlertCircle size={14} />{errorText(event.error, 'Revision details could not be loaded.')}</div> : <ChangeDetail item={event.data} />}</div></aside></div>
}

function ChangeDetail({ item }: { item: ProxyAuditEvent }) {
  const lines = (item.diff_text || '').split('\n').filter((line, index, all) => line || index < all.length - 1)
  return <div><div className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border sm:grid-cols-4" style={{ borderColor: 'var(--border)', background: 'var(--border)' }}><Detail label="Type" value={item.object_type === 'shared_object' ? 'Shared Object' : 'Policy'} /><Detail label="Author" value={item.author || 'Unknown'} /><Detail label="Version" value={item.revision_number} mono /><Detail label="Date" value={dateTime(item.revision_date)} /></div><section className="mt-5"><p className="ui-context">Comment</p><p className="mt-2 whitespace-pre-wrap text-[11px] leading-5" style={{ color: 'var(--text-3)' }}>{item.comment || 'No revision comment was provided.'}</p></section><section className="mt-5 overflow-hidden rounded-xl border" style={{ borderColor: 'var(--border)' }}><header className="flex items-center justify-between border-b px-4 py-3" style={{ borderColor: 'var(--border)', background: 'var(--table-header)' }}><div><p className="ui-context">What changed</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-3)' }}>{item.change_summary}</p></div><div className="flex gap-2 font-mono text-[10px]"><span className="text-emerald-400">+{item.additions}</span><span className="text-red-400">−{item.deletions}</span></div></header>{lines.length ? <pre className="max-h-[58vh] overflow-auto p-4 font-mono text-[10px] leading-5" style={{ background: 'var(--surface-inset)' }}>{lines.map((line, index) => <div key={`${index}-${line.slice(0, 12)}`} className="min-w-max px-2" style={{ color: line.startsWith('+') && !line.startsWith('+++') ? '#34d399' : line.startsWith('-') && !line.startsWith('---') ? '#fb7185' : line.startsWith('@@') ? '#60a5fa' : 'var(--text-3)', background: line.startsWith('+') && !line.startsWith('+++') ? 'rgba(52,211,153,.045)' : line.startsWith('-') && !line.startsWith('---') ? 'rgba(251,113,133,.045)' : 'transparent' }}>{line || ' '}</div>)}</pre> : <div className="px-5 py-12 text-center"><FileCode2 size={22} className="mx-auto" style={{ color: 'var(--text-4)' }} /><p className="mt-3 text-[11px] font-semibold" style={{ color: 'var(--text-2)' }}>{item.change_summary}</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>There is no line-level diff for this revision.</p></div>}</section></div>
}

function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div className="min-w-0 p-3" style={{ background: 'var(--surface-inset)' }}><p className="ui-context">{label}</p><p className={`mt-1.5 truncate text-[10px] ${mono ? 'font-mono' : ''}`} style={{ color: 'var(--text-2)' }}>{value}</p></div>
}

export default function ProxyAudit() {
  const user = useAuthStore(state => state.user)
  const queryClient = useQueryClient()
  const [connectionOpen, setConnectionOpen] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [debounced, setDebounced] = useState('')
  const [objectType, setObjectType] = useState<'' | 'policy' | 'shared_object'>('')
  const [author, setAuthor] = useState('')
  const [page, setPage] = useState(1)
  const wasSyncing = useRef(false)

  useEffect(() => { const timer = window.setTimeout(() => setDebounced(search.trim()), 250); return () => window.clearTimeout(timer) }, [search])
  useEffect(() => setPage(1), [debounced, objectType, author])

  const connection = useQuery({ queryKey: ['proxy-audit-connection'], queryFn: fetchProxyAuditConnection, refetchInterval: query => query.state.data?.sync_in_progress ? 2_500 : 30_000 })
  const summary = useQuery({ queryKey: ['proxy-audit-summary'], queryFn: fetchProxyAuditSummary })
  const events = useQuery({ queryKey: ['proxy-audit-events', debounced, objectType, author, page], queryFn: () => fetchProxyAuditEvents({ search: debounced || undefined, object_type: objectType || undefined, author: author || undefined, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }) })
  const sync = useMutation({ mutationFn: syncProxyAudit, onSuccess: () => queryClient.invalidateQueries({ queryKey: ['proxy-audit-connection'] }) })

  useEffect(() => {
    const syncing = Boolean(connection.data?.sync_in_progress)
    if (wasSyncing.current && !syncing) {
      queryClient.invalidateQueries({ queryKey: ['proxy-audit-events'] })
      queryClient.invalidateQueries({ queryKey: ['proxy-audit-summary'] })
    }
    wasSyncing.current = syncing
  }, [connection.data?.sync_in_progress, queryClient])

  const authors = useMemo(() => Array.from(new Set((events.data?.items || []).map(item => item.author).filter((value): value is string => Boolean(value)))).sort(), [events.data?.items])
  const totalPages = Math.max(1, Math.ceil((events.data?.total || 0) / PAGE_SIZE))
  const failed = connection.isError || summary.isError || events.isError
  const syncing = Boolean(connection.data?.sync_in_progress)

  return <div className="ui-page"><div className="ui-page-container">
    <header className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end"><div className="max-w-2xl"><div className="mb-3 flex items-center gap-2"><span className="status-pulse" data-status={connection.data?.status === 'connected' ? 'healthy' : connection.data?.status === 'error' ? 'error' : 'warning'} /><p className="ui-context">Policy change intelligence</p></div><h1 className="text-[clamp(1.65rem,3vw,2.4rem)] font-semibold leading-[1.03] tracking-[-.05em]" style={{ color: 'var(--text-1)' }}>Proxy Audit</h1><p className="mt-3 max-w-xl text-[12px] leading-5" style={{ color: 'var(--text-3)' }}>A source-faithful timeline of Symantec Management Center policy and shared-object revisions, with exact line-level changes.</p></div><div className="flex flex-wrap gap-2">{user?.role === 'admin' && <button className="ui-secondary-button" onClick={() => setConnectionOpen(true)}><Settings2 size={13} /> Connection</button>}{user?.role === 'admin' && <button className="ui-primary-button disabled:opacity-40" disabled={!connection.data?.configured || syncing || sync.isPending} onClick={() => sync.mutate()}>{syncing || sync.isPending ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}{syncing ? 'Syncing…' : 'Sync now'}</button>}</div></header>

    <section className="mt-6 flex flex-col justify-between gap-3 rounded-xl border px-4 py-3 sm:flex-row sm:items-center" style={{ borderColor: 'var(--border)', background: 'var(--surface-inset)' }}><div className="flex items-center gap-3"><span className="grid h-8 w-8 place-items-center rounded-lg" style={{ background: connection.data?.status === 'connected' ? 'rgba(52,211,153,.08)' : 'var(--surface-3)', color: connection.data?.status === 'connected' ? '#34d399' : 'var(--text-4)' }}>{connection.data?.status === 'connected' ? <ShieldCheck size={15} /> : <KeyRound size={15} />}</span><div><p className="text-[11px] font-semibold" style={{ color: 'var(--text-2)' }}>{connection.data?.configured ? connection.data.base_url : 'Management Center is not configured'}</p><p className="mt-0.5 text-[9px]" style={{ color: 'var(--text-4)' }}>{syncing ? 'Collecting policy history now' : connection.data?.last_sync ? `Last sync ${relative(connection.data.last_sync)} · ${connection.data.records_synced.toLocaleString()} revisions scanned` : 'Connect the API, then run the first sync'}</p></div></div>{connection.data?.last_error && <p className="max-w-xl truncate text-[9px] text-red-400" title={connection.data.last_error}>{connection.data.last_error}</p>}</section>

    {failed ? <section className="ui-command-surface mt-5 flex items-start gap-3 p-5"><AlertCircle size={18} className="mt-0.5 text-red-400" /><div><p className="text-[12px] font-semibold text-red-300">Proxy audit data is unavailable</p><p className="mt-1 text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>{errorText(connection.error || summary.error || events.error)}</p></div></section> : <>
      <section className="ui-command-surface mt-5 grid grid-cols-2 divide-x divide-y overflow-hidden lg:grid-cols-4 lg:divide-y-0"><Metric label="Tracked objects" value={summary.data?.objects || 0} detail="Policies and shared objects" /><Metric label="Policy revisions" value={summary.data?.revisions || 0} detail="Retained change events" /><Metric label="Change authors" value={summary.data?.authors || 0} detail="Distinct administrators" /><Metric label="Latest change" value={relative(summary.data?.last_change || null)} detail={summary.data?.last_change ? dateTime(summary.data.last_change) : 'Waiting for first sync'} /></section>

      <section className="ui-command-surface mt-5 overflow-hidden"><div className="border-b px-4 py-4 sm:px-5" style={{ borderColor: 'var(--border)' }}><div className="flex flex-col gap-3 xl:flex-row xl:items-end xl:justify-between"><div><p className="ui-context">Revision timeline</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>{events.data?.total || 0} matching revisions</p></div><div className="grid gap-2 sm:grid-cols-[minmax(230px,1fr)_150px_150px]"><label><span className="sr-only">Search policy revisions</span><span className="ui-control flex items-center gap-2 px-3"><Search size={13} style={{ color: 'var(--text-4)' }} /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Policy, author, comment, change…" className="min-w-0 flex-1 bg-transparent text-[11px] outline-none" /></span></label><label><span className="sr-only">Object type</span><select className="ui-control w-full px-3 text-[10px]" value={objectType} onChange={event => setObjectType(event.target.value as typeof objectType)}><option value="">All object types</option><option value="policy">Policies</option><option value="shared_object">Shared objects</option></select></label><label><span className="sr-only">Author</span><select className="ui-control w-full px-3 text-[10px]" value={author} onChange={event => setAuthor(event.target.value)}><option value="">All authors</option>{authors.map(value => <option key={value}>{value}</option>)}</select></label></div></div></div>
        <div className="overflow-x-auto"><div className="min-w-[1050px]"><div className="grid grid-cols-[minmax(190px,1.25fr)_125px_125px_145px_80px_minmax(170px,1fr)_minmax(190px,1.2fr)] gap-4 border-b px-5 py-2.5 text-[9px] font-semibold uppercase tracking-[.09em]" style={{ color: 'var(--text-4)', background: 'var(--table-header)', borderColor: 'var(--border)' }}><span>Policy Name</span><span>Policy / Shared Object</span><span>Author</span><span>Date</span><span>Version</span><span>Comment</span><span>What Changed</span></div><div className="divide-y" style={{ borderColor: 'var(--border)' }}>{events.isLoading && [...Array(6)].map((_, index) => <div key={index} className="grid grid-cols-7 gap-4 px-5 py-4"><div className="shimmer h-4 rounded" /><div className="shimmer h-4 rounded" /><div className="shimmer h-4 rounded" /><div className="shimmer h-4 rounded" /><div className="shimmer h-4 rounded" /><div className="shimmer h-4 rounded" /><div className="shimmer h-4 rounded" /></div>)}{events.data?.items.map(item => <button key={item.id} onClick={() => setSelected(item.id)} className="ui-data-row grid w-full grid-cols-[minmax(190px,1.25fr)_125px_125px_145px_80px_minmax(170px,1fr)_minmax(190px,1.2fr)] items-center gap-4 px-5 py-3 text-left"><div className="min-w-0"><p className="truncate text-[11px] font-semibold" style={{ color: 'var(--text-1)' }}>{item.policy_name}</p><p className="mt-1 truncate font-mono text-[8px]" style={{ color: 'var(--text-4)' }}>{item.policy_uuid}</p></div><span className="w-fit rounded-md border px-2 py-1 text-[9px] font-semibold" style={{ color: item.object_type === 'shared_object' ? '#60a5fa' : '#34d399', borderColor: item.object_type === 'shared_object' ? 'rgba(96,165,250,.2)' : 'rgba(52,211,153,.2)', background: item.object_type === 'shared_object' ? 'rgba(96,165,250,.05)' : 'rgba(52,211,153,.05)' }}>{item.object_type === 'shared_object' ? 'Shared Object' : 'Policy'}</span><span className="truncate text-[10px]" style={{ color: 'var(--text-3)' }}>{item.author || 'Unknown'}</span><div><p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{dateTime(item.revision_date)}</p><p className="mt-0.5 text-[8px]" style={{ color: 'var(--text-4)' }}>{relative(item.revision_date)}</p></div><span className="font-mono text-[10px] font-semibold" style={{ color: 'var(--text-2)' }}>{item.revision_number}</span><span className="line-clamp-2 text-[10px] leading-4" style={{ color: 'var(--text-3)' }}>{item.comment || 'No comment'}</span><div className="min-w-0"><p className="truncate text-[10px] font-medium" style={{ color: 'var(--text-2)' }}>{item.change_summary}</p><p className="mt-1 font-mono text-[9px]"><span className="text-emerald-400">+{item.additions}</span><span className="ml-2 text-red-400">−{item.deletions}</span></p></div></button>)}{!events.isLoading && !events.data?.items.length && <div className="px-5 py-16 text-center"><History size={25} className="mx-auto" style={{ color: 'var(--text-4)' }} /><p className="mt-3 text-[12px] font-semibold" style={{ color: 'var(--text-2)' }}>{debounced || objectType || author ? 'No revisions match these filters' : connection.data?.configured ? 'No policy revisions collected yet' : 'Connect Management Center to begin'}</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>{debounced || objectType || author ? 'Clear the filters to return to the full timeline.' : user?.role === 'admin' ? 'Configure the API connection and run the first sync.' : 'An administrator must configure the Management Center connection.'}</p>{user?.role === 'admin' && !connection.data?.configured && <button className="ui-secondary-button mt-4" onClick={() => setConnectionOpen(true)}><Settings2 size={13} /> Configure connection</button>}</div>}</div></div></div>
        {(events.data?.total || 0) > PAGE_SIZE && <div className="flex items-center justify-between border-t px-5 py-3" style={{ borderColor: 'var(--border)' }}><p className="text-[10px]" style={{ color: 'var(--text-4)' }}>Page {page} of {totalPages}</p><div className="flex gap-1"><button className="ui-icon-button" disabled={page === 1} onClick={() => setPage(value => value - 1)}><ChevronLeft size={14} /></button><button className="ui-icon-button" disabled={page === totalPages} onClick={() => setPage(value => value + 1)}><ChevronRight size={14} /></button></div></div>}
      </section>
    </>}
    {sync.isError && <div className="mt-3 flex items-center gap-2 text-[10px] text-red-400"><AlertCircle size={12} />{errorText(sync.error, 'The sync could not be started.')}</div>}
    {connectionOpen && <ConnectionDialog onClose={() => setConnectionOpen(false)} />}
    {selected && <ChangeDrawer eventId={selected} onClose={() => setSelected(null)} />}
  </div></div>
}
