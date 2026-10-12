import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle, Camera, CheckCircle2, ChevronDown, ChevronRight,
  ExternalLink, Globe2, History, Info, Loader2, Play, Radar,
  RefreshCw, Search, ShieldAlert, ShieldCheck, Trash2, XCircle,
} from 'lucide-react'
import {
  createInvestigation, deleteInvestigation, fetchInvestigation,
  fetchInvestigationHistory, previewIndicator, runActiveOperation,
  type Investigation, type InvestigationPreview, type ProviderResult,
} from '../api/urlInvestigations'
import { useAuthStore } from '../store/auth'
import ThreatIntelligenceSetup from '../components/ThreatIntelligenceSetup'

const TERMINAL = new Set(['completed', 'no_data', 'not_configured', 'unsupported', 'awaiting_consent', 'rate_limited', 'timeout', 'authentication_error', 'failed'])

function errorMessage(error: unknown) {
  return (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail
    ?? (error as Error)?.message
    ?? 'The request failed.'
}

function StatusPill({ status }: { status: string }) {
  const styles: Record<string, string> = {
    completed: 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300',
    running: 'border-blue-500/25 bg-blue-500/10 text-blue-300',
    queued: 'border-blue-500/25 bg-blue-500/10 text-blue-300',
    no_data: 'border-zinc-500/25 bg-zinc-500/10 text-zinc-400',
    not_configured: 'border-zinc-500/25 bg-zinc-500/10 text-zinc-400',
    unsupported: 'border-zinc-500/25 bg-zinc-500/10 text-zinc-400',
    awaiting_consent: 'border-amber-500/25 bg-amber-500/10 text-amber-300',
    rate_limited: 'border-amber-500/25 bg-amber-500/10 text-amber-300',
    timeout: 'border-red-500/25 bg-red-500/10 text-red-300',
    authentication_error: 'border-red-500/25 bg-red-500/10 text-red-300',
    failed: 'border-red-500/25 bg-red-500/10 text-red-300',
  }
  const Icon = status === 'completed' ? CheckCircle2 : status === 'running' || status === 'queued' ? Loader2 : status === 'failed' || status === 'timeout' || status === 'authentication_error' ? XCircle : Info
  return <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-1 text-[10px] font-medium ${styles[status] ?? styles.no_data}`}><Icon size={10} className={status === 'running' || status === 'queued' ? 'animate-spin' : ''} />{status.replace(/_/g, ' ')}</span>
}

function RiskGauge({ result }: { result: Investigation }) {
  const score = result.risk_score
  const tone = result.risk_level === 'critical' ? 'text-red-400' : result.risk_level === 'high' ? 'text-orange-400' : result.risk_level === 'moderate' ? 'text-amber-300' : result.risk_level === 'low' ? 'text-emerald-400' : 'text-zinc-400'
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-2)] p-5">
      <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">Sec360 risk</p>
      <div className="mt-2 flex items-end gap-2"><span className={`text-4xl font-bold tabular-nums ${tone}`}>{score ?? '—'}</span>{score !== null && <span className="mb-1 text-xs text-zinc-600">/ 100</span>}</div>
      <p className={`mt-1 text-sm font-semibold capitalize ${tone}`}>{result.risk_level === 'low' ? 'Low observed risk' : result.risk_level}</p>
      <p className="mt-2 text-[11px] leading-4 text-zinc-500">Triage heuristic, not a probability or vendor-supplied score.</p>
    </div>
  )
}

function ProviderCard({ result, investigationId, onRefresh }: { result: ProviderResult; investigationId: string; onRefresh: () => void }) {
  const [expanded, setExpanded] = useState(false)
  const action = useMutation({
    mutationFn: (operation: 'scan' | 'screenshot') => runActiveOperation(investigationId, result.provider, operation),
    onSuccess: onRefresh,
  })
  const canScan = result.provider === 'virustotal' || result.provider === 'cloudflare_url_scanner'
  const canScreenshot = result.provider === 'site_shot'
  const run = (operation: 'scan' | 'screenshot') => {
    const disclosure = operation === 'scan'
      ? 'This actively submits the target to the provider for scanning. Provider policies may store or share it.'
      : 'This sends the target to Site-Shot, which will actively load the page to capture a screenshot.'
    if (window.confirm(`${disclosure}\n\nContinue?`)) action.mutate(operation)
  }
  const finding = result.findings.find(item => typeof item.summary === 'string')?.summary as string | undefined
  return (
    <div className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface-2)]">
      <button className="flex w-full items-start gap-3 p-4 text-left" onClick={() => setExpanded(value => !value)}>
        <div className="mt-0.5 rounded-lg border border-white/[0.06] bg-white/[0.03] p-2 text-zinc-400"><Radar size={15} /></div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold text-zinc-100">{result.label}</span><StatusPill status={result.status} />{result.cache_status === 'cached' && <span className="text-[10px] text-zinc-500">cached</span>}</div>
          <p className="mt-1 truncate text-xs text-zinc-500">Checked: {result.queried_indicator} · {result.queried_scope.replace(/_/g, ' ')}</p>
          <p className="mt-2 text-xs leading-5 text-zinc-300">{finding ?? result.error_message ?? (result.status === 'no_data' ? 'No existing report was available. This is not a clean verdict.' : 'No provider conclusion available.')}</p>
        </div>
        {expanded ? <ChevronDown size={16} className="mt-1 text-zinc-600" /> : <ChevronRight size={16} className="mt-1 text-zinc-600" />}
      </button>
      {expanded && <div className="space-y-4 border-t border-[var(--border)] px-4 py-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <div><p className="text-[10px] uppercase tracking-wide text-zinc-600">Native verdict</p><p className="mt-1 text-xs font-medium text-zinc-300">{result.native_verdict?.replace(/_/g, ' ') ?? 'Not provided'}</p></div>
          <div><p className="text-[10px] uppercase tracking-wide text-zinc-600">Observed</p><p className="mt-1 text-xs text-zinc-300">{result.observed_at ? new Date(result.observed_at).toLocaleString() : 'Not provided'}</p></div>
          <div><p className="text-[10px] uppercase tracking-wide text-zinc-600">Operation</p><p className="mt-1 text-xs text-zinc-300">{result.operation}</p></div>
        </div>
        {Object.keys(result.native_metrics).length > 0 && <div><p className="mb-2 text-[10px] uppercase tracking-wide text-zinc-600">Provider-native metrics</p><div className="flex flex-wrap gap-2">{Object.entries(result.native_metrics).map(([key, value]) => <span key={key} className="rounded-md border border-white/[0.06] bg-zinc-950 px-2 py-1 text-[11px] text-zinc-400">{key.replace(/_/g, ' ')}: <b className="text-zinc-200">{String(value)}</b></span>)}</div></div>}
        {result.provider === 'abuseipdb' && <p className="rounded-lg border border-amber-500/15 bg-amber-500/[0.05] p-3 text-[11px] leading-5 text-amber-200/80">IP reputation / infrastructure context only. Shared hosting and CDN infrastructure may be used by many domains.</p>}
        {result.artifacts.map(artifact => <img key={artifact.id} src={artifact.url} alt={`${result.label} screenshot evidence`} referrerPolicy="no-referrer" className="max-h-[480px] w-full rounded-lg border border-[var(--border)] object-contain bg-zinc-950" />)}
        {Object.keys(result.evidence).length > 0 && <details><summary className="cursor-pointer text-xs text-zinc-400">Evidence details</summary><pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap rounded-lg bg-zinc-950 p-3 text-[10px] leading-5 text-zinc-500">{JSON.stringify(result.evidence, null, 2)}</pre></details>}
        {(result.operations?.length ?? 0) > 1 && <details><summary className="cursor-pointer text-xs text-zinc-400">Operation snapshots ({result.operations?.length})</summary><div className="mt-2 space-y-2">{result.operations?.map(operation => <div key={operation.id} className="rounded-lg border border-white/[0.06] bg-zinc-950 p-3"><div className="flex items-center justify-between"><span className="text-[11px] font-medium text-zinc-300">{operation.operation}</span><StatusPill status={operation.status} /></div><p className="mt-1 text-[10px] text-zinc-600">{operation.fetched_at ? new Date(operation.fetched_at).toLocaleString() : 'Pending'} · {operation.queried_scope.replace(/_/g, ' ')}</p></div>)}</div></details>}
        <details><summary className="cursor-pointer text-xs text-zinc-400">Sanitized raw provider data</summary><pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap rounded-lg bg-zinc-950 p-3 text-[10px] leading-5 text-zinc-500">{JSON.stringify(result.raw_response ?? result.evidence, null, 2)}</pre></details>
        <div className="flex flex-wrap gap-2">
          {result.report_url && <a href={result.report_url} target="_blank" rel="noreferrer noopener" referrerPolicy="no-referrer" onClick={event => { if (!window.confirm('Open the provider report? The provider will receive this navigation and may retain the investigated indicator.')) event.preventDefault() }} className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] px-3 py-2 text-xs text-zinc-300 hover:text-white">Trusted provider report <ExternalLink size={12} /></a>}
          {canScan && !['queued', 'running', 'not_configured'].includes(result.status) && <button onClick={() => run('scan')} disabled={action.isPending} className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/20 bg-amber-500/[0.07] px-3 py-2 text-xs text-amber-300 disabled:opacity-50"><Play size={12} />Submit new scan</button>}
          {canScreenshot && !['queued', 'running', 'not_configured'].includes(result.status) && <button onClick={() => run('screenshot')} disabled={action.isPending} className="inline-flex items-center gap-1.5 rounded-lg border border-purple-500/20 bg-purple-500/[0.07] px-3 py-2 text-xs text-purple-300 disabled:opacity-50"><Camera size={12} />Capture screenshot</button>}
        </div>
        {action.isError && <p className="text-xs text-red-400">{errorMessage(action.error)}</p>}
      </div>}
    </div>
  )
}

function ResultView({ result, refresh, rerun, rerunning }: { result: Investigation; refresh: () => void; rerun: () => void; rerunning: boolean }) {
  const pending = result.providers?.some(provider => !TERMINAL.has(provider.status))
  return <div className="space-y-5">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><div className="flex items-center gap-2"><h2 className="text-lg font-bold text-white">{result.indicator_preview}</h2>{pending && <StatusPill status="running" />}</div><p className="mt-1 text-xs text-zinc-500">{result.indicator_type} · hostname {result.hostname} · registrable domain {result.registrable_domain}</p></div>
      <div className="flex gap-2"><button onClick={rerun} disabled={rerunning} className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/20 px-3 py-2 text-xs text-emerald-300 disabled:opacity-50"><Play size={12} />Rerun checks</button><button onClick={refresh} className="rounded-lg border border-white/[0.08] p-2 text-zinc-500 hover:text-white" aria-label="Refresh investigation"><RefreshCw size={14} /></button></div>
    </div>
    <div className="grid gap-3 md:grid-cols-[220px_1fr]">
      <RiskGauge result={result} />
      <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-2)] p-5">
        <div className="flex flex-wrap gap-4 text-xs"><span className="text-zinc-500">Confidence <b className="ml-1 capitalize text-zinc-200">{result.evidence_confidence}</b></span><span className="text-zinc-500">Coverage <b className="ml-1 text-zinc-200">{result.coverage.label ?? 'Pending'}</b></span><span className="text-zinc-500">Model <b className="ml-1 text-zinc-200">{result.scoring_version}</b></span></div>
        <div className="mt-4 space-y-2">{result.reasons.map(reason => <div key={reason} className="flex items-start gap-2 text-xs leading-5 text-zinc-300"><ShieldCheck size={13} className="mt-1 shrink-0 text-emerald-500" />{reason}</div>)}</div>
      </div>
    </div>
    <div><h3 className="mb-3 text-sm font-semibold text-white">Provider comparison</h3><div className="space-y-2">{result.providers?.map(provider => <ProviderCard key={provider.provider} result={provider} investigationId={result.id} onRefresh={refresh} />)}</div></div>
    <details className="rounded-xl border border-[var(--border)] bg-[var(--surface-2)] p-4"><summary className="cursor-pointer text-sm font-semibold text-zinc-200">Scoring explanation</summary><pre className="mt-3 overflow-auto whitespace-pre-wrap rounded-lg bg-zinc-950 p-3 text-[10px] leading-5 text-zinc-500">{JSON.stringify(result.provider_contributions, null, 2)}</pre></details>
  </div>
}

export default function UrlInvestigation() {
  const user = useAuthStore(state => state.user)
  const qc = useQueryClient()
  const [input, setInput] = useState('')
  const [preview, setPreview] = useState<InvestigationPreview | null>(null)
  const [acknowledged, setAcknowledged] = useState(false)
  const [forceRefresh, setForceRefresh] = useState(false)
  const [advanced, setAdvanced] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const previewMutation = useMutation({ mutationFn: () => previewIndicator(input), onSuccess: data => { setPreview(data); setAcknowledged(false); setMessage(null) }, onError: error => setMessage(errorMessage(error)) })
  const createMutation = useMutation({ mutationFn: () => createInvestigation(input, forceRefresh), onSuccess: data => { setSelectedId(data.id); setMessage(data.deduplicated ? 'Opened the matching investigation already in progress.' : null); void qc.invalidateQueries({ queryKey: ['url-investigation-history'] }) }, onError: error => setMessage(errorMessage(error)) })
  const rerunMutation = useMutation({ mutationFn: (indicator: string) => createInvestigation(indicator, true), onSuccess: data => { setSelectedId(data.id); void qc.invalidateQueries({ queryKey: ['url-investigation-history'] }) }, onError: error => setMessage(errorMessage(error)) })
  const history = useQuery({ queryKey: ['url-investigation-history'], queryFn: fetchInvestigationHistory, refetchInterval: selectedId ? 5000 : false })
  const detail = useQuery({ queryKey: ['url-investigation', selectedId], queryFn: () => fetchInvestigation(selectedId!), enabled: Boolean(selectedId), refetchInterval: query => query.state.data?.status === 'completed' ? false : 1500 })
  const remove = useMutation({ mutationFn: deleteInvestigation, onSuccess: () => { setSelectedId(null); void qc.invalidateQueries({ queryKey: ['url-investigation-history'] }) } })

  useEffect(() => { setPreview(null); setAcknowledged(false) }, [input])
  const enabledCount = useMemo(() => preview?.providers.filter(provider => provider.enabled).length ?? 0, [preview])
  return <div className="h-full overflow-y-auto">
    <div className="mx-auto max-w-6xl space-y-6 px-4 py-5 pb-12 sm:px-6 lg:px-8">
    <div><div className="flex items-center gap-2"><Globe2 size={18} className="text-emerald-400" /><h1 className="text-xl font-bold text-white">URL & Domain Investigation</h1></div><p className="mt-1 text-sm text-zinc-500">Correlate direct reputation, infrastructure context, and static screenshot evidence in one explainable assessment.</p></div>
    <ThreatIntelligenceSetup />
    <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface-1)] p-5">
      <form onSubmit={event => { event.preventDefault(); previewMutation.mutate() }} className="flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1"><Search size={15} className="absolute left-3 top-3 text-zinc-600" /><input value={input} onChange={event => setInput(event.target.value)} placeholder="example.com or https://example.com/path?query=value" className="w-full rounded-xl border border-white/[0.08] bg-zinc-950 py-2.5 pl-9 pr-3 text-sm text-white outline-none focus:border-emerald-500" /></div>
        <button disabled={!input.trim() || previewMutation.isPending} className="inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-zinc-950 disabled:opacity-40">{previewMutation.isPending ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}Review investigation</button>
      </form>
      <button onClick={() => setAdvanced(value => !value)} className="mt-3 flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-300">{advanced ? <ChevronDown size={13} /> : <ChevronRight size={13} />}Advanced options</button>
      {advanced && <label className="mt-3 flex items-center gap-2 text-xs text-zinc-400"><input type="checkbox" checked={forceRefresh} onChange={event => setForceRefresh(event.target.checked)} className="accent-emerald-500" />Bypass valid cached provider results (still respects quotas and rate limits)</label>}
      {message && <div className="mt-4 flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-500/[0.07] p-3 text-xs text-red-300"><AlertTriangle size={13} className="mt-0.5 shrink-0" />{message}</div>}
      {preview && <div className="mt-5 space-y-4 border-t border-[var(--border)] pt-5">
        <div className="grid gap-3 md:grid-cols-3"><div className="rounded-lg bg-[var(--surface-2)] p-3"><p className="text-[10px] uppercase tracking-wide text-zinc-600">Normalized target</p><p className="mt-1 break-all text-xs text-zinc-200">{preview.indicator.preview}</p></div><div className="rounded-lg bg-[var(--surface-2)] p-3"><p className="text-[10px] uppercase tracking-wide text-zinc-600">Scope</p><p className="mt-1 text-xs text-zinc-200">{preview.indicator.indicator_type === 'url' ? 'Exact URL' : 'Exact hostname'}</p><p className="mt-1 text-[10px] text-zinc-600">Active scan target: {preview.indicator.scan_target}</p></div><div className="rounded-lg bg-[var(--surface-2)] p-3"><p className="text-[10px] uppercase tracking-wide text-zinc-600">Providers</p><p className="mt-1 text-xs text-zinc-200">{enabledCount} enabled · 5 always visible</p></div></div>
        {preview.indicator.is_sensitive && <div className="flex items-start gap-2 rounded-lg border border-red-500/25 bg-red-500/[0.08] p-3 text-xs leading-5 text-red-300"><ShieldAlert size={14} className="mt-0.5 shrink-0" /><span>Potentially sensitive URL: {preview.indicator.sensitive_reasons.join(', ')}. {user?.role === 'admin' ? 'Administrator approval will be recorded.' : 'Use a domain-only investigation or ask an administrator.'}</span></div>}
        <div className="grid gap-2 sm:grid-cols-2">{preview.providers.map(provider => <div key={provider.provider} className="rounded-lg border border-white/[0.06] bg-[var(--surface-2)] p-3"><div className="flex items-center justify-between"><span className="text-xs font-semibold text-zinc-200">{provider.label}</span><span className={`text-[10px] ${provider.enabled ? 'text-emerald-400' : 'text-zinc-600'}`}>{provider.enabled ? 'enabled' : provider.provider === 'cisco_talos' ? 'manual' : 'not configured'}</span></div><p className="mt-1 text-[11px] text-zinc-500">{provider.scope}</p></div>)}</div>
        <label className="flex items-start gap-2 rounded-lg border border-amber-500/15 bg-amber-500/[0.05] p-3 text-xs leading-5 text-zinc-400"><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} className="mt-1 accent-amber-500" /><span><b className="text-amber-200">Disclosure notice:</b> {preview.disclosure_notice} {preview.sensitive_notice}</span></label>
        <button onClick={() => createMutation.mutate()} disabled={!acknowledged || createMutation.isPending || (preview.indicator.is_sensitive && user?.role !== 'admin')} className="inline-flex items-center gap-2 rounded-xl bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-zinc-950 disabled:opacity-40">{createMutation.isPending ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}Run investigation</button>
      </div>}
    </div>
    {detail.data && <ResultView result={detail.data} refresh={() => void detail.refetch()} rerun={() => { if (window.confirm('Rerun all configured lookups and bypass cached results? The indicator will be disclosed to those providers again.')) rerunMutation.mutate(detail.data?.indicator?.original ?? detail.data!.indicator_preview) }} rerunning={rerunMutation.isPending} />}
    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-1)]">
      <div className="flex items-center gap-2 border-b border-[var(--border)] px-4 py-3"><History size={14} className="text-zinc-500" /><h2 className="text-sm font-semibold text-white">Investigation history</h2></div>
      <div className="divide-y divide-[var(--border)]">{history.data?.map(item => <div key={item.id} className="flex items-center gap-3 px-4 py-3"><button onClick={() => setSelectedId(item.id)} className="min-w-0 flex-1 text-left"><div className="flex items-center gap-2"><span className="truncate text-xs font-medium text-zinc-200">{item.indicator_preview}</span><StatusPill status={item.status === 'completed' ? 'completed' : 'running'} /></div><p className="mt-1 text-[10px] text-zinc-600">{new Date(item.created_at).toLocaleString()} · {item.requested_by} · {item.coverage.label ?? 'No coverage yet'}</p></button><span className="text-sm font-bold tabular-nums text-zinc-300">{item.risk_score ?? '—'}</span>{(user?.role === 'admin' || item.requested_by === user?.email) && <button onClick={() => { if (window.confirm('Delete this investigation snapshot and its screenshots?')) remove.mutate(item.id) }} className="rounded-md p-1.5 text-zinc-700 hover:text-red-400" aria-label="Delete investigation"><Trash2 size={13} /></button>}</div>)}{history.data?.length === 0 && <p className="px-4 py-8 text-center text-xs text-zinc-600">No investigations yet.</p>}</div>
    </div>
    </div>
  </div>
}
