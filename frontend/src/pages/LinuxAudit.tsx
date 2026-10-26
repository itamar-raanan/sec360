import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { useNavigate, useParams } from 'react-router-dom'
import {
  AlertCircle, ArrowLeft, ArrowRight, Check, ChevronDown, ChevronLeft,
  ChevronRight, Clipboard, FileJson, FileSearch, HardDrive, Info, KeyRound,
  Loader2, Monitor, Plus, RefreshCw, Search, Server, ShieldCheck, Trash2, Upload, X,
} from 'lucide-react'

import {
  createLinuxAuditIngestToken, fetchLinuxAudit, fetchLinuxAuditIngestTokens,
  fetchLinuxAudits, fetchLinuxAuditSummary, revokeLinuxAuditIngestToken,
  uploadLinuxAudit, type LinuxAuditIngestToken, type LinuxAuditReport,
} from '../api/linuxAudits'
import { useConfirm } from '../components/shared/ConfirmDialog'
import { useAuthStore } from '../store/auth'
import { usePanelStore } from '../store/panels'

const PAGE_SIZE = 50
const STATUS_ORDER = ['FAIL', 'ERROR', 'REVIEW', 'PASS', 'EXCLUDED', 'NOT_APPLICABLE']

const statusStyle: Record<string, { color: string; background: string }> = {
  PASS: { color: '#34d399', background: 'rgba(52,211,153,.09)' },
  FAIL: { color: '#fb7185', background: 'rgba(251,113,133,.09)' },
  ERROR: { color: '#f87171', background: 'rgba(248,113,113,.09)' },
  REVIEW: { color: '#fbbf24', background: 'rgba(251,191,36,.09)' },
  EXCLUDED: { color: '#94a3b8', background: 'rgba(148,163,184,.08)' },
  NOT_APPLICABLE: { color: '#94a3b8', background: 'rgba(148,163,184,.08)' },
}

function dateTime(value: string | null) {
  if (!value) return 'Not available'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

function relative(value: string | null) {
  if (!value) return 'No audits yet'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : formatDistanceToNow(date, { addSuffix: true })
}

function errorText(error: unknown, fallback: string) {
  return (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail || fallback
}

function printable(value: unknown) {
  if (value === null || value === undefined || value === '') return 'No evidence was recorded.'
  if (typeof value === 'string') return value
  return JSON.stringify(value, null, 2)
}

function StatusBadge({ status }: { status?: string }) {
  const normalized = (status || 'UNKNOWN').toUpperCase()
  const style = statusStyle[normalized] || { color: 'var(--text-3)', background: 'var(--surface-inset)' }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[9px] font-bold tracking-[.08em]"
      style={{ color: style.color, background: style.background, borderColor: `color-mix(in srgb, ${style.color} 28%, transparent)` }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: style.color }} />
      {normalized.split('_').join(' ')}
    </span>
  )
}

function Score({ report, compact = false }: { report: LinuxAuditReport; compact?: boolean }) {
  const color = report.fail_count || report.error_count ? '#fb7185' : '#34d399'
  return (
    <div className="flex items-center gap-2.5">
      <div className={`${compact ? 'h-8 w-8 text-[10px]' : 'h-11 w-11 text-[12px]'} grid flex-shrink-0 place-items-center rounded-full border font-mono font-bold`}
        style={{ color, borderColor: `${color}55`, background: `${color}0d` }}>
        {Math.round(report.pass_rate)}%
      </div>
      {!compact && <div><p className="text-[11px] font-semibold" style={{ color: 'var(--text-2)' }}>{report.fail_count + report.error_count ? 'Action required' : 'Baseline passed'}</p><p className="mt-0.5 text-[9px]" style={{ color: 'var(--text-4)' }}>{report.pass_count} of {report.pass_count + report.fail_count + report.error_count} scored controls</p></div>}
    </div>
  )
}

function Metric({ label, value, detail, color = 'var(--text-1)' }: { label: string; value: number | string; detail: string; color?: string }) {
  return <div className="ui-metric py-4"><p className="ui-context">{label}</p><p className="mt-2 font-mono text-[24px] font-semibold tracking-[-.05em]" style={{ color }}>{typeof value === 'number' ? value.toLocaleString() : value}</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>{detail}</p></div>
}

function UploadDialog({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const inputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [ipAddress, setIpAddress] = useState('')
  const [dragging, setDragging] = useState(false)

  const mutation = useMutation({
    mutationFn: () => uploadLinuxAudit(file!, ipAddress),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['linux-audits'] }),
        queryClient.invalidateQueries({ queryKey: ['linux-audit-summary'] }),
      ])
      onClose()
    },
  })

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => event.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  const choose = (candidate?: File) => {
    if (candidate) setFile(candidate)
  }

  return (
    <div className="dialog-backdrop" onMouseDown={onClose}>
      <section className="w-full max-w-[520px] overflow-hidden rounded-2xl border shadow-2xl fade-up"
        style={{ background: 'var(--surface-2)', borderColor: 'var(--border-lit)' }} onMouseDown={event => event.stopPropagation()} role="dialog" aria-modal="true" aria-label="Upload Linux audit report">
        <header className="flex items-start justify-between border-b px-5 py-5" style={{ borderColor: 'var(--border)' }}>
          <div className="flex items-start gap-3"><span className="dialog-icon"><Upload size={16} /></span><div><h2 className="text-[15px] font-semibold" style={{ color: 'var(--text-1)' }}>Upload audit evidence</h2><p className="mt-1 text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>Use <span className="font-mono">reports/&lt;hostname&gt;/cis_report_*.json</span>, generated alongside the HTML report.</p></div></div>
          <button className="ui-icon-button" onClick={onClose} aria-label="Close upload"><X size={15} /></button>
        </header>
        <div className="space-y-4 p-5">
          <button type="button" onClick={() => inputRef.current?.click()}
            onDragOver={event => { event.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={event => { event.preventDefault(); setDragging(false); choose(event.dataTransfer.files[0]) }}
            className="flex min-h-[150px] w-full flex-col items-center justify-center border border-dashed px-5 text-center"
            style={{ borderRadius: 12, borderColor: dragging ? 'var(--accent)' : 'var(--border-mid)', background: dragging ? 'var(--accent-dim)' : 'var(--surface-inset)' }}>
            <FileJson size={25} style={{ color: file ? 'var(--accent)' : 'var(--text-4)' }} />
            <p className="mt-3 text-[12px] font-semibold" style={{ color: 'var(--text-2)' }}>{file ? file.name : 'Drop a CIS JSON report here'}</p>
            <p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>{file ? `${(file.size / 1024).toFixed(1)} KB selected` : 'or click to browse · maximum 15 MB'}</p>
            <input ref={inputRef} type="file" accept="application/json,.json" className="hidden" onChange={event => choose(event.target.files?.[0])} />
          </button>

          <label className="block"><span className="ui-context">Server IP override <span className="normal-case tracking-normal" style={{ color: 'var(--text-4)' }}>· optional</span></span><input value={ipAddress} onChange={event => setIpAddress(event.target.value)} placeholder="Uses the report IP by default, or enter 10.0.0.12" className="ui-control mt-2 w-full px-3 text-[11px]" /></label>
          <div className="flex items-start gap-2 rounded-lg border px-3 py-2.5" style={{ borderColor: 'var(--border)', background: 'var(--surface-inset)' }}><Info size={13} className="mt-0.5 flex-shrink-0" style={{ color: 'var(--info)' }} /><p className="text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>SEC360 imports the report IP, then correlates the server to Endpoints using hostname, FQDN, and all reported IPs. The override is only needed to correct an older report.</p></div>
          {mutation.isError && <div className="flex items-start gap-2 rounded-lg border px-3 py-2.5 text-[10px]" style={{ borderColor: 'rgba(251,113,133,.25)', color: '#fb7185', background: 'rgba(251,113,133,.06)' }}><AlertCircle size={13} className="mt-0.5 flex-shrink-0" /><span>{errorText(mutation.error, 'The report could not be uploaded.')}</span></div>}
        </div>
        <footer className="flex justify-end gap-2 border-t px-5 py-4" style={{ borderColor: 'var(--border)' }}><button className="ui-secondary-button" onClick={onClose}>Cancel</button><button className="ui-primary-button disabled:opacity-40" disabled={!file || mutation.isPending} onClick={() => mutation.mutate()}>{mutation.isPending ? <RefreshCw size={13} className="animate-spin" /> : <Upload size={13} />}{mutation.isPending ? 'Importing…' : 'Import report'}</button></footer>
      </section>
    </div>
  )
}

function AutomationDialog({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const confirm = useConfirm()
  const [name, setName] = useState('')
  const [issued, setIssued] = useState<LinuxAuditIngestToken | null>(null)
  const [copied, setCopied] = useState(false)
  const tokens = useQuery({ queryKey: ['linux-audit-ingest-tokens'], queryFn: fetchLinuxAuditIngestTokens })
  const createToken = useMutation({
    mutationFn: () => createLinuxAuditIngestToken(name.trim()),
    onSuccess: async value => {
      setIssued(value)
      setName('')
      await queryClient.invalidateQueries({ queryKey: ['linux-audit-ingest-tokens'] })
    },
  })
  const revokeToken = useMutation({
    mutationFn: revokeLinuxAuditIngestToken,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['linux-audit-ingest-tokens'] }),
  })

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => event.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  const copyToken = async () => {
    if (!issued?.token) return
    await navigator.clipboard.writeText(issued.token)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1800)
  }
  const revoke = async (item: LinuxAuditIngestToken) => {
    const approved = await confirm({
      title: 'Revoke upload token?',
      message: `${item.name} will immediately stop uploading reports. This cannot be undone.`,
      confirmLabel: 'Revoke token',
      tone: 'danger',
    })
    if (approved) revokeToken.mutate(item.id)
  }

  return <div className="dialog-backdrop" onMouseDown={onClose}>
    <section className="flex max-h-[88vh] w-full max-w-[720px] flex-col overflow-hidden rounded-2xl border shadow-2xl fade-up" style={{ background: 'var(--surface-2)', borderColor: 'var(--border-lit)' }} onMouseDown={event => event.stopPropagation()} role="dialog" aria-modal="true" aria-label="Linux audit automation">
      <header className="flex items-start justify-between border-b px-5 py-5" style={{ borderColor: 'var(--border)' }}>
        <div className="flex items-start gap-3"><span className="dialog-icon"><KeyRound size={16} /></span><div><h2 className="text-[15px] font-semibold" style={{ color: 'var(--text-1)' }}>Automatic report delivery</h2><p className="mt-1 max-w-xl text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>Create a revocable machine token for debian13-cis-audit. SEC360 stores only a cryptographic hash of the credential.</p></div></div>
        <button className="ui-icon-button" onClick={onClose} aria-label="Close automation settings"><X size={15} /></button>
      </header>

      <div className="overflow-y-auto p-5">
        {issued?.token && <section className="mb-5 rounded-xl border p-4" style={{ borderColor: 'rgba(251,191,36,.28)', background: 'rgba(251,191,36,.055)' }}>
          <div className="flex items-start gap-3"><ShieldCheck size={16} className="mt-0.5 shrink-0 text-amber-300" /><div><p className="text-[12px] font-semibold text-amber-200">Copy this token now</p><p className="mt-1 text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>This is the only time the complete credential will be shown. Store it in Ansible Vault or another secrets manager.</p></div></div>
          <div className="mt-3 flex items-center gap-2 rounded-lg border p-2" style={{ borderColor: 'var(--border)', background: 'var(--surface-inset)' }}><code className="min-w-0 flex-1 select-all overflow-x-auto whitespace-nowrap px-2 text-[10px] text-amber-100">{issued.token}</code><button onClick={copyToken} className="ui-secondary-button shrink-0">{copied ? <Check size={13} /> : <Clipboard size={13} />}{copied ? 'Copied' : 'Copy'}</button></div>
        </section>}

        <section className="rounded-xl border p-4" style={{ borderColor: 'var(--border)', background: 'var(--surface-inset)' }}>
          <label className="block"><span className="ui-context">Credential name</span><div className="mt-2 flex flex-col gap-2 sm:flex-row"><input value={name} onChange={event => setName(event.target.value)} onKeyDown={event => { if (event.key === 'Enter' && name.trim()) createToken.mutate() }} placeholder="Production Debian audit" className="ui-control min-w-0 flex-1 px-3 text-[11px]" maxLength={120} /><button onClick={() => createToken.mutate()} disabled={!name.trim() || createToken.isPending} className="ui-primary-button shrink-0 disabled:opacity-40">{createToken.isPending ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />} Create token</button></div></label>
          {createToken.isError && <p className="mt-2 text-[10px] text-red-400">{errorText(createToken.error, 'The upload token could not be created.')}</p>}
        </section>

        <div className="mt-5 flex items-end justify-between gap-3"><div><p className="ui-context">Upload credentials</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>POST JSON to <code className="select-all" style={{ color: 'var(--text-3)' }}>/api/linux-audits/ingest</code> using Bearer authentication.</p></div><span className="text-[9px]" style={{ color: 'var(--text-4)' }}>{tokens.data?.filter(item => !item.revoked_at).length || 0} active</span></div>
        <div className="mt-3 overflow-hidden rounded-xl border" style={{ borderColor: 'var(--border)' }}>
          {tokens.isLoading && <div className="space-y-3 p-4">{[0, 1].map(value => <div key={value} className="shimmer h-12 rounded-lg" />)}</div>}
          {tokens.isError && <div className="flex items-start gap-2 p-4 text-[10px] text-red-400"><AlertCircle size={13} className="mt-0.5 shrink-0" />{errorText(tokens.error, 'Upload credentials could not be loaded.')}</div>}
          {!tokens.isLoading && !tokens.isError && !tokens.data?.length && <div className="px-5 py-10 text-center"><KeyRound size={22} className="mx-auto" style={{ color: 'var(--text-4)' }} /><p className="mt-3 text-[11px] font-semibold" style={{ color: 'var(--text-2)' }}>No automation credentials yet</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>Create one for the audit controller that sends reports.</p></div>}
          <div className="divide-y" style={{ borderColor: 'var(--border)' }}>{tokens.data?.map(item => <article key={item.id} className="flex items-center justify-between gap-4 px-4 py-3" style={{ opacity: item.revoked_at ? .55 : 1 }}><div className="min-w-0"><div className="flex items-center gap-2"><span className={`h-1.5 w-1.5 rounded-full ${item.revoked_at ? 'bg-slate-500' : 'bg-emerald-400'}`} /><p className="truncate text-[11px] font-semibold" style={{ color: 'var(--text-2)' }}>{item.name}</p><code className="text-[9px]" style={{ color: 'var(--text-4)' }}>{item.token_prefix}…</code></div><p className="mt-1 text-[9px]" style={{ color: 'var(--text-4)' }}>{item.revoked_at ? `Revoked ${relative(item.revoked_at)}` : item.last_used_at ? `Last used ${relative(item.last_used_at)}${item.last_used_ip ? ` from ${item.last_used_ip}` : ''}` : `Created ${relative(item.created_at)} · never used`}</p></div>{!item.revoked_at && <button onClick={() => revoke(item)} disabled={revokeToken.isPending} className="ui-icon-button shrink-0" aria-label={`Revoke ${item.name}`} title="Revoke token"><Trash2 size={13} /></button>}</article>)}</div>
        </div>
        {revokeToken.isError && <p className="mt-2 text-[10px] text-red-400">{errorText(revokeToken.error, 'The token could not be revoked.')}</p>}
      </div>
      <footer className="flex justify-end border-t px-5 py-4" style={{ borderColor: 'var(--border)' }}><button className="ui-secondary-button" onClick={onClose}>Done</button></footer>
    </section>
  </div>
}

function AuditDetail({ reportId }: { reportId: string }) {
  const navigate = useNavigate()
  const { openPanel } = usePanelStore()
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const report = useQuery({ queryKey: ['linux-audit', reportId], queryFn: () => fetchLinuxAudit(reportId) })

  const results = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return (report.data?.results || []).filter(result => {
      if (status && (result.status || '').toUpperCase() !== status) return false
      if (!needle) return true
      return [result.id, result.title, result.expected, result.actual, result.evidence_text]
        .some(value => printable(value).toLowerCase().includes(needle))
    }).sort((a, b) => {
      const aRank = STATUS_ORDER.indexOf((a.status || '').toUpperCase())
      const bRank = STATUS_ORDER.indexOf((b.status || '').toUpperCase())
      return (aRank < 0 ? STATUS_ORDER.length : aRank) - (bRank < 0 ? STATUS_ORDER.length : bRank)
    })
  }, [report.data?.results, search, status])

  if (report.isLoading) return <div className="ui-page"><div className="ui-page-container space-y-4"><div className="shimmer h-8 w-48 rounded" /><div className="shimmer h-36 rounded-xl" /><div className="shimmer h-80 rounded-xl" /></div></div>
  if (report.isError || !report.data) return <div className="flex h-full items-center justify-center p-8"><div className="max-w-md text-center"><AlertCircle className="mx-auto text-red-400" /><h1 className="mt-3 text-lg font-semibold" style={{ color: 'var(--text-1)' }}>Audit report unavailable</h1><p className="mt-1 text-sm" style={{ color: 'var(--text-4)' }}>{errorText(report.error, 'The report may have been removed or access is unavailable.')}</p><button onClick={() => navigate('/linux-audit')} className="ui-secondary-button mt-5"><ArrowLeft size={13} /> Back to Linux Audit</button></div></div>

  const item = report.data
  const availableStatuses = Array.from(new Set((item.results || []).map(row => (row.status || 'UNKNOWN').toUpperCase())))
  return <div className="ui-page"><div className="ui-page-container">
    <button onClick={() => navigate('/linux-audit')} className="ui-text-action"><ArrowLeft size={13} /> Linux Audit</button>
    <header className="mt-5 flex flex-col justify-between gap-5 lg:flex-row lg:items-end"><div><div className="mb-3 flex items-center gap-2"><span className="status-pulse" data-status={item.fail_count || item.error_count ? 'error' : 'healthy'} /><p className="ui-context">CIS audit evidence</p></div><h1 className="font-mono text-[clamp(1.45rem,3vw,2.1rem)] font-semibold tracking-[-.045em]" style={{ color: 'var(--text-1)' }}>{item.hostname}</h1><p className="mt-2 text-[11px]" style={{ color: 'var(--text-3)' }}>{item.benchmark_name}{item.benchmark_version ? ` · v${item.benchmark_version}` : ''} · {dateTime(item.generated_at)}</p></div><Score report={item} /></header>

    <section className="ui-command-surface mt-6 grid grid-cols-2 divide-x divide-y overflow-hidden md:grid-cols-4 md:divide-y-0"><Metric label="Passed" value={item.pass_count} detail="Automated controls" color="#34d399" /><Metric label="Failed" value={item.fail_count} detail="Configuration changes" color="#fb7185" /><Metric label="Review" value={item.review_count} detail="Human decisions" color="#fbbf24" /><Metric label="Errors" value={item.error_count} detail="Audit execution issues" color="#f87171" /></section>

    <section className="mt-5 grid gap-px overflow-hidden rounded-xl border sm:grid-cols-2 lg:grid-cols-4" style={{ borderColor: 'var(--border)', background: 'var(--border)' }}>
      {[
        ['Server', item.hostname],
        ['FQDN', item.fqdn || 'Not reported'],
        ['Primary IP', item.ip_address || 'Not reported'],
        ['Operating system', item.os_name || 'Not reported'],
        ['Kernel', item.kernel || 'Not reported'],
        ['Architecture', item.architecture || 'Not reported'],
        ['Virtualization', item.virtualization_type || 'Not reported'],
        ['Profile', item.profile || 'Not reported'],
      ].map(([label, value]) => <div key={label} className="p-4" style={{ background: 'var(--surface-inset)' }}><p className="ui-context">{label}</p><p className="mt-2 truncate font-mono text-[11px]" style={{ color: 'var(--text-2)' }}>{value}</p></div>)}
    </section>
    <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2 text-[9px]" style={{ color: 'var(--text-4)' }}>
      {item.ip_addresses.length > 1 && <span>All IPs: <span className="break-all font-mono" style={{ color: 'var(--text-3)' }}>{item.ip_addresses.join(', ')}</span></span>}
      {item.machine_id_hash && <span title={item.machine_id_hash}>Machine identity: <span className="font-mono" style={{ color: 'var(--text-3)' }}>{item.machine_id_hash.slice(0, 12)}…</span></span>}
      {item.audit_tool_version && <span>Audit tool: <span className="font-mono" style={{ color: 'var(--text-3)' }}>v{item.audit_tool_version}{item.audit_tool_git_commit ? ` · ${item.audit_tool_git_commit}` : ''}</span></span>}
      {item.schema_version && <span>Schema: <span className="font-mono" style={{ color: 'var(--text-3)' }}>v{item.schema_version}</span></span>}
    </div>
    {item.endpoint_id && <button onClick={() => openPanel('endpoint', item.endpoint_id!, item.hostname)} className="ui-text-action mt-3"><Monitor size={12} /> Open matched endpoint</button>}

    <section className="ui-command-surface mt-5 overflow-hidden">
      <div className="flex flex-col gap-3 border-b px-4 py-4 sm:flex-row sm:items-center sm:justify-between" style={{ borderColor: 'var(--border)' }}><div><p className="ui-context">Control evidence</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>{results.length} of {item.total_count} controls shown</p></div><div className="flex gap-2"><label className="ui-control flex min-w-0 flex-1 items-center gap-2 px-3 sm:w-64"><Search size={13} style={{ color: 'var(--text-4)' }} /><input value={search} onChange={event => setSearch(event.target.value)} className="min-w-0 flex-1 bg-transparent text-[11px] outline-none" placeholder="Search controls or evidence…" /></label><select value={status} onChange={event => setStatus(event.target.value)} className="ui-control px-2 text-[10px]"><option value="">All status</option>{STATUS_ORDER.filter(value => availableStatuses.includes(value)).map(value => <option key={value}>{value}</option>)}</select></div></div>
      <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
        {results.map((result, index) => {
          const key = `${result.id || index}-${index}`
          const isOpen = expanded === key
          return <article key={key} className="ui-data-row"><button className="grid w-full grid-cols-[75px_minmax(0,1fr)_105px_18px] items-center gap-3 px-4 py-3 text-left sm:grid-cols-[90px_minmax(0,1fr)_120px_18px] sm:px-5" onClick={() => setExpanded(isOpen ? null : key)}><span className="font-mono text-[10px] font-semibold" style={{ color: 'var(--text-3)' }}>{result.id || '—'}</span><span className="min-w-0 truncate text-[11px] font-medium" style={{ color: 'var(--text-2)' }}>{result.title || 'Untitled control'}</span><StatusBadge status={result.status} /><ChevronDown size={13} className="transition-transform" style={{ color: 'var(--text-4)', transform: isOpen ? 'rotate(180deg)' : 'none' }} /></button>{isOpen && <div className="border-t px-4 py-5 sm:px-5" style={{ borderColor: 'var(--border)', background: 'var(--surface-inset)' }}><div className="grid gap-5 lg:grid-cols-2"><EvidenceBlock label="Expected state" value={result.expected} /><EvidenceBlock label="Collected evidence" value={result.evidence_text ?? result.actual} mono /><EvidenceBlock label={result.status === 'REVIEW' ? 'How to review' : 'How to check'} value={result.review_guidance ?? result.how_to_check} mono={!result.review_guidance} /><EvidenceBlock label="Remediation guidance" value={result.remediation} /></div></div>}</article>
        })}
        {!results.length && <div className="px-5 py-14 text-center"><FileSearch size={24} className="mx-auto" style={{ color: 'var(--text-4)' }} /><p className="mt-3 text-[12px] font-semibold" style={{ color: 'var(--text-2)' }}>No controls match this view</p><button onClick={() => { setSearch(''); setStatus('') }} className="ui-text-action mt-2">Clear filters</button></div>}
      </div>
    </section>
    <p className="mt-4 text-[9px] leading-4" style={{ color: 'var(--text-4)' }}>Uploaded by {item.uploaded_by_email} {relative(item.uploaded_at)} · {item.filename}</p>
  </div></div>
}

function EvidenceBlock({ label, value, mono = false }: { label: string; value: unknown; mono?: boolean }) {
  return <div className="min-w-0"><p className="ui-context">{label}</p><pre className={`mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words text-[10px] leading-5 ${mono ? 'font-mono' : 'font-sans'}`} style={{ color: 'var(--text-3)' }}>{printable(value)}</pre></div>
}

function AuditInventory() {
  const user = useAuthStore(state => state.user)
  const navigate = useNavigate()
  const [uploadOpen, setUploadOpen] = useState(false)
  const [automationOpen, setAutomationOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [debounced, setDebounced] = useState('')
  const [result, setResult] = useState<'' | 'pass' | 'attention'>('')
  const [profile, setProfile] = useState('')
  const [page, setPage] = useState(1)

  useEffect(() => { const timer = window.setTimeout(() => setDebounced(search.trim()), 250); return () => window.clearTimeout(timer) }, [search])
  useEffect(() => setPage(1), [debounced, result, profile])

  const summary = useQuery({ queryKey: ['linux-audit-summary'], queryFn: fetchLinuxAuditSummary })
  const reports = useQuery({
    queryKey: ['linux-audits', debounced, result, profile, page],
    queryFn: () => fetchLinuxAudits({ search: debounced || undefined, result: result || undefined, profile: profile || undefined, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }),
  })
  const profiles = Array.from(new Set((reports.data?.items || []).map(item => item.profile).filter((value): value is string => Boolean(value))))
  const totalPages = Math.max(1, Math.ceil((reports.data?.total || 0) / PAGE_SIZE))
  const failed = summary.isError || reports.isError

  return <div className="ui-page"><div className="ui-page-container">
    <header className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end"><div className="max-w-2xl"><div className="mb-3 flex items-center gap-2"><span className="status-pulse" data-status={(summary.data?.failed_controls || 0) + (summary.data?.error_controls || 0) > 0 ? 'warning' : 'healthy'} /><p className="ui-context">CIS evidence workspace</p></div><h1 className="ui-page-title">Linux Audit</h1><p className="ui-page-description">A searchable server inventory for Debian 13 CIS results, collected evidence, and remediation guidance.</p></div>{user?.role !== 'viewer' && <div className="flex flex-wrap gap-2">{user?.role === 'admin' && <button onClick={() => setAutomationOpen(true)} className="ui-secondary-button"><KeyRound size={13} /> Automation</button>}<button onClick={() => setUploadOpen(true)} className="ui-primary-button"><Upload size={13} /> Upload report</button></div>}</header>

    {failed ? <section className="ui-command-surface mt-6 flex items-start gap-3 p-5"><AlertCircle size={18} className="mt-0.5 text-red-400" /><div><p className="text-[12px] font-semibold text-red-300">Linux audit data is unavailable</p><p className="mt-1 text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>{errorText(summary.error || reports.error, 'Try refreshing the page or verify the feature is enabled.')}</p></div></section> : <>
      <section className="ui-command-surface mt-6 grid grid-cols-2 divide-x divide-y overflow-hidden lg:grid-cols-4 lg:divide-y-0"><Metric label="Audited servers" value={summary.data?.servers || 0} detail={`${summary.data?.reports || 0} uploaded reports`} /><Metric label="Failed controls" value={summary.data?.failed_controls || 0} detail="Across retained reports" color={(summary.data?.failed_controls || 0) ? '#fb7185' : '#34d399'} /><Metric label="Audit errors" value={summary.data?.error_controls || 0} detail="Collection issues" color={(summary.data?.error_controls || 0) ? '#f87171' : 'var(--text-1)'} /><Metric label="Latest audit" value={relative(summary.data?.last_audit || null)} detail={summary.data?.last_audit ? dateTime(summary.data.last_audit) : 'Upload the first JSON report'} /></section>

      <section className="ui-command-surface mt-5 overflow-hidden">
        <div className="border-b px-4 py-4 sm:px-5" style={{ borderColor: 'var(--border)' }}><div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between"><div><p className="ui-context">Server audit inventory</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>{reports.data?.total || 0} matching reports</p></div><div className="grid gap-2 sm:grid-cols-[minmax(220px,1fr)_130px_140px]"><label className="ui-control flex items-center gap-2 px-3"><Search size={13} style={{ color: 'var(--text-4)' }} /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Server, IP, OS, benchmark…" className="min-w-0 flex-1 bg-transparent text-[11px] outline-none" /></label><select value={result} onChange={event => setResult(event.target.value as typeof result)} className="ui-control px-2 text-[10px]"><option value="">All results</option><option value="attention">Needs attention</option><option value="pass">Passed</option></select><select value={profile} onChange={event => setProfile(event.target.value)} className="ui-control px-2 text-[10px]"><option value="">All profiles</option>{profiles.map(value => <option key={value}>{value}</option>)}</select></div></div></div>

        <div className="hidden grid-cols-[minmax(180px,1.2fr)_135px_145px_120px_120px_96px] gap-4 border-b px-5 py-2.5 text-[9px] font-semibold uppercase tracking-[.09em] lg:grid" style={{ color: 'var(--text-4)', background: 'var(--table-header)', borderColor: 'var(--border)' }}><span>Server</span><span>IP address</span><span>Platform</span><span>Audit time</span><span>Result</span><span /></div>
        <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
          {reports.isLoading && [...Array(5)].map((_, index) => <div key={index} className="grid grid-cols-[1fr_120px] gap-4 px-5 py-4 lg:grid-cols-[minmax(180px,1.2fr)_135px_145px_120px_120px_96px]"><div className="shimmer h-4 rounded" /><div className="shimmer h-4 rounded" /><div className="shimmer hidden h-4 rounded lg:block" /><div className="shimmer hidden h-4 rounded lg:block" /><div className="shimmer hidden h-4 rounded lg:block" /><div className="shimmer hidden h-4 rounded lg:block" /></div>)}
          {reports.data?.items.map(item => <button key={item.id} onClick={() => navigate(`/linux-audit/${item.id}`)} className="ui-data-row grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-4 px-4 py-3 text-left sm:px-5 lg:grid-cols-[minmax(180px,1.2fr)_135px_145px_120px_120px_96px]"><div className="min-w-0"><div className="flex items-center gap-2"><Server size={13} style={{ color: 'var(--accent)' }} /><span className="truncate font-mono text-[11px] font-semibold" style={{ color: 'var(--text-1)' }}>{item.hostname}</span></div><p className="mt-1 truncate text-[9px]" style={{ color: 'var(--text-4)' }}>{item.fqdn && item.fqdn !== item.hostname ? item.fqdn : item.virtualization_type || 'Linux server'}</p><p className="mt-1 truncate text-[9px] lg:hidden" style={{ color: 'var(--text-4)' }}>{item.ip_address || 'No IP'} · {item.os_name || item.benchmark_name}</p></div><span className="hidden truncate font-mono text-[10px] lg:block" style={{ color: 'var(--text-3)' }}>{item.ip_address || '—'}</span><div className="hidden min-w-0 lg:block"><p className="truncate text-[10px]" style={{ color: 'var(--text-2)' }}>{item.os_name || 'Linux'}</p><p className="mt-0.5 truncate text-[9px]" style={{ color: 'var(--text-4)' }}>{[item.architecture, item.profile].filter(Boolean).join(' · ') || 'No profile'}</p></div><div className="hidden lg:block"><p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{dateTime(item.generated_at)}</p><p className="mt-0.5 text-[9px]" style={{ color: 'var(--text-4)' }}>{relative(item.generated_at)}</p></div><div className="hidden lg:block"><Score report={item} compact /></div><span className="flex items-center justify-end gap-1 text-[10px] font-semibold" style={{ color: 'var(--accent)' }}>Open <ArrowRight size={12} /></span></button>)}
          {!reports.isLoading && !reports.data?.items.length && <div className="px-5 py-16 text-center"><HardDrive size={25} className="mx-auto" style={{ color: 'var(--text-4)' }} /><p className="mt-3 text-[12px] font-semibold" style={{ color: 'var(--text-2)' }}>{debounced || result || profile ? 'No reports match these filters' : 'No Linux audit reports yet'}</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>{debounced || result || profile ? 'Clear the filters to return to the full inventory.' : 'Upload the JSON output from debian13-cis-audit to begin.'}</p></div>}
        </div>
        {(reports.data?.total || 0) > PAGE_SIZE && <div className="flex items-center justify-between border-t px-5 py-3" style={{ borderColor: 'var(--border)' }}><p className="text-[10px]" style={{ color: 'var(--text-4)' }}>Page {page} of {totalPages}</p><div className="flex gap-1"><button className="ui-icon-button" disabled={page === 1} onClick={() => setPage(value => value - 1)}><ChevronLeft size={14} /></button><button className="ui-icon-button" disabled={page === totalPages} onClick={() => setPage(value => value + 1)}><ChevronRight size={14} /></button></div></div>}
      </section>
    </>}
    {uploadOpen && <UploadDialog onClose={() => setUploadOpen(false)} />}
    {automationOpen && <AutomationDialog onClose={() => setAutomationOpen(false)} />}
  </div></div>
}

export default function LinuxAudit() {
  const { reportId } = useParams()
  return reportId ? <AuditDetail reportId={reportId} /> : <AuditInventory />
}
