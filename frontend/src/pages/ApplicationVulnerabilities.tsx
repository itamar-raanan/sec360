import React, { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import {
  AlertCircle, ArrowRight, CheckCircle2, ChevronLeft, ChevronRight,
  Download, ExternalLink, Flame, PackageSearch,
  RefreshCw, Search, ShieldAlert, Sparkles, X,
} from 'lucide-react'
import {
  exportApplicationVulnerabilities, fetchApplicationVulnerabilities,
  fetchApplicationVulnerability, fetchVulnerabilityFacets, fetchVulnerabilitySummary,
  type ApplicationVulnerability, type VulnerabilityParams,
} from '../api/applicationVulnerabilities'
import { usePanelStore } from '../store/panels'

const PAGE_SIZE = 75
const severityColor: Record<string, string> = {
  CRITICAL: '#fb7185', HIGH: '#fb923c', MEDIUM: '#facc15', LOW: '#60a5fa', UNKNOWN: '#94a3b8',
}

function relative(value: string | null) {
  if (!value) return 'Never'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'Unknown' : formatDistanceToNow(date, { addSuffix: true })
}

function dateTime(value: string | null) {
  if (!value) return 'Not reported'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

function Metric({ label, value, detail, color = 'var(--text-1)' }: { label: string; value: number; detail: string; color?: string }) {
  return <div className="ui-metric py-4"><p className="ui-eyebrow">{label}</p><p className="mt-2 font-mono text-[25px] font-semibold tracking-[-0.05em]" style={{ color }}>{value.toLocaleString()}</p><p className="mt-1 truncate text-[10px]" style={{ color: 'var(--text-4)' }}>{detail}</p></div>
}

function SeverityBadge({ severity }: { severity: string | null }) {
  const label = severity || 'UNKNOWN'
  const color = severityColor[label] || severityColor.UNKNOWN
  return <span className="inline-flex min-w-[70px] items-center justify-center gap-1.5 rounded-md border px-2 py-1 text-[9px] font-bold tracking-[0.08em]" style={{ color, borderColor: `${color}32`, background: `${color}10` }}><span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />{label}</span>
}

function DetailValue({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return <div className="min-w-0"><p className="ui-eyebrow">{label}</p><div className={`mt-1.5 break-words text-[11px] leading-5 ${mono ? 'font-mono' : ''}`} style={{ color: value ? 'var(--text-2)' : 'var(--text-4)' }}>{value || 'Not reported'}</div></div>
}

function FindingDrawer({ item, onClose }: { item: ApplicationVulnerability; onClose: () => void }) {
  const { openPanel } = usePanelStore()
  const detail = useQuery({ queryKey: ['application-vulnerability', item.id], queryFn: () => fetchApplicationVulnerability(item.id) })
  const finding = detail.data || item
  const fields = [
    ['SentinelOne risk ID', finding.sentinelone_id], ['SentinelOne endpoint ID', finding.sentinelone_endpoint_id],
    ['CVSS version', finding.cvss_version], ['NVD CVSS version', finding.nvd_cvss_version],
    ['Report confidence', finding.report_confidence], ['Remediation level', finding.remediation_level],
    ['Last scan result', finding.last_scan_result], ['Endpoint type', finding.endpoint_type],
    ['Marked by', finding.marked_by], ['Mark type', finding.mark_type],
  ]
  return <div className="fixed inset-0 z-40 bg-black/45 backdrop-blur-[2px]" onMouseDown={onClose}>
    <aside className="absolute inset-y-0 right-0 flex w-full max-w-[580px] flex-col border-l shadow-2xl slide-in-right" style={{ background: 'var(--surface-1)', borderColor: 'var(--border-lit)' }} onMouseDown={event => event.stopPropagation()} aria-label="Vulnerability evidence">
      <header className="flex items-start justify-between border-b px-5 py-5" style={{ borderColor: 'var(--border)' }}><div className="min-w-0 pr-4"><div className="flex items-center gap-2"><SeverityBadge severity={finding.severity} /><span className="font-mono text-[11px]" style={{ color: 'var(--text-3)' }}>{finding.cve_id}</span></div><h2 className="mt-3 truncate text-[20px] font-semibold tracking-[-0.035em]" style={{ color: 'var(--text-1)' }}>{finding.application}</h2><p className="mt-1 text-[11px]" style={{ color: 'var(--text-4)' }}>{finding.application_vendor || 'Unknown vendor'}</p></div><button onClick={onClose} className="rounded-md p-2 hover:bg-white/[0.05]" style={{ color: 'var(--text-3)' }} aria-label="Close evidence"><X size={16} /></button></header>
      <div className="flex-1 overflow-y-auto px-5 py-5">
        <section className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border" style={{ background: 'var(--border)', borderColor: 'var(--border)' }}>
          {[['NVD base score', finding.nvd_base_score], ['SentinelOne risk', finding.risk_score], ['Status', finding.status], ['Mitigation', finding.mitigation_status]].map(([label, value]) => <div key={String(label)} className="p-4" style={{ background: 'var(--surface-inset)' }}><DetailValue label={String(label)} value={value} mono={typeof value === 'number'} /></div>)}
        </section>
        <section className="mt-5 border-y py-5" style={{ borderColor: 'var(--border)' }}><p className="ui-eyebrow">Affected endpoint</p><div className="mt-3 flex items-center justify-between gap-3"><div className="min-w-0"><p className="truncate font-mono text-[12px] font-semibold" style={{ color: 'var(--text-1)' }}>{finding.endpoint_name}</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>{finding.os_type || 'Unknown OS'}{finding.endpoint?.owner_email ? ` · ${finding.endpoint.owner_email}` : ''}</p></div>{finding.endpoint && <button onClick={() => openPanel('endpoint', finding.endpoint!.id, finding.endpoint!.hostname)} className="ui-text-action">Open endpoint <ExternalLink size={11} /></button>}</div></section>
        <section className="mt-5 grid grid-cols-2 gap-x-5 gap-y-5">{fields.map(([label, value]) => <DetailValue key={String(label)} label={String(label)} value={value as React.ReactNode} mono={String(label).includes('ID')} />)}</section>
        <section className="mt-6"><p className="ui-eyebrow">Exposure timeline</p><div className="mt-3 space-y-3 border-l pl-4" style={{ borderColor: 'var(--border-mid)' }}><DetailValue label="Published" value={dateTime(finding.published_date)} /><DetailValue label="First detected" value={dateTime(finding.detection_date)} /><DetailValue label="Last vulnerability scan" value={dateTime(finding.last_scan_date)} /></div></section>
        <section className="mt-6 rounded-xl border p-4" style={{ borderColor: finding.exploit_code_maturity && finding.exploit_code_maturity.toLowerCase() !== 'unknown' ? 'rgba(251,113,133,.24)' : 'var(--border)', background: 'var(--surface-inset)' }}><div className="flex items-start gap-3"><Flame size={15} style={{ color: finding.exploit_code_maturity && finding.exploit_code_maturity.toLowerCase() !== 'unknown' ? '#fb7185' : 'var(--text-4)' }} /><div><p className="text-[11px] font-semibold" style={{ color: 'var(--text-2)' }}>Exploit maturity</p><p className="mt-1 text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>{finding.exploit_code_maturity || 'SentinelOne did not report exploit maturity.'}</p></div></div></section>
        {(finding.reason || finding.mitigation_status_reason) && <section className="mt-5"><DetailValue label="SentinelOne reason" value={finding.mitigation_status_reason || finding.reason} /></section>}
        {detail.isLoading && <div className="mt-5 flex items-center gap-2 text-[10px]" style={{ color: 'var(--text-4)' }}><RefreshCw size={11} className="animate-spin" /> Loading exact source payload…</div>}
      </div>
    </aside>
  </div>
}

export default function ApplicationVulnerabilities() {
  const [search, setSearch] = useState('')
  const [debounced, setDebounced] = useState('')
  const [severity, setSeverity] = useState(() => new URLSearchParams(window.location.search).get('severity') || '')
  const [status, setStatus] = useState('')
  const [mitigation, setMitigation] = useState('')
  const [osType, setOsType] = useState('')
  const [exploitOnly, setExploitOnly] = useState(false)
  const [sort, setSort] = useState('severity')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<ApplicationVulnerability | null>(null)
  const [exporting, setExporting] = useState(false)

  useEffect(() => { const timer = window.setTimeout(() => setDebounced(search.trim()), 250); return () => window.clearTimeout(timer) }, [search])
  useEffect(() => setPage(1), [debounced, severity, status, mitigation, osType, exploitOnly, sort])

  const summary = useQuery({ queryKey: ['application-vulnerability-summary'], queryFn: fetchVulnerabilitySummary, refetchInterval: 60_000 })
  const facets = useQuery({ queryKey: ['application-vulnerability-facets'], queryFn: fetchVulnerabilityFacets })
  const params: VulnerabilityParams = useMemo(() => ({
    search: debounced || undefined, severity: severity || undefined, status: status || undefined,
    mitigation: mitigation || undefined, os_type: osType || undefined,
    exploit: exploitOnly ? true : undefined, sort, order: 'desc', limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE,
  }), [debounced, severity, status, mitigation, osType, exploitOnly, sort, page])
  const findings = useQuery({ queryKey: ['application-vulnerabilities', params], queryFn: () => fetchApplicationVulnerabilities(params) })
  const totalPages = Math.max(1, Math.ceil((findings.data?.total || 0) / PAGE_SIZE))
  const maxSeverity = Math.max(1, summary.data?.severity.critical || 0, summary.data?.severity.high || 0, summary.data?.severity.medium || 0, summary.data?.severity.low || 0)
  const activeFilters = [severity, status, mitigation, osType, exploitOnly].filter(Boolean).length

  async function exportCsv() {
    setExporting(true)
    try { await exportApplicationVulnerabilities({ ...params, limit: undefined, offset: undefined }) } finally { setExporting(false) }
  }
  function clearFilters() { setSearch(''); setSeverity(''); setStatus(''); setMitigation(''); setOsType(''); setExploitOnly(false) }

  const failed = summary.isError || findings.isError
  return <div className="h-full overflow-y-auto"><div className="mx-auto max-w-[1550px] px-4 py-6 sm:px-6 lg:px-8">
    <header className="flex flex-col justify-between gap-5 pb-6 lg:flex-row lg:items-end"><div className="max-w-2xl"><div className="mb-3 flex items-center gap-2"><span className="status-pulse" data-status={(summary.data?.severity.critical || 0) > 0 ? 'error' : 'healthy'} /><p className="ui-eyebrow">SentinelOne application risk</p></div><h1 className="text-[clamp(1.8rem,4vw,3rem)] font-semibold leading-[.98] tracking-[-.055em]" style={{ color: 'var(--text-1)' }}>Software exposure,<br /><span style={{ color: 'var(--text-3)' }}>down to the endpoint.</span></h1><p className="mt-4 max-w-xl text-[12px] leading-5" style={{ color: 'var(--text-3)' }}>A source-faithful view of vulnerable applications, CVEs, exploit maturity, affected devices, and remediation status.</p></div><div className="flex items-center gap-3"><span className="text-[10px]" style={{ color: 'var(--text-4)' }}>Synced {relative(summary.data?.last_sync || null)}</span><button onClick={exportCsv} disabled={exporting || !findings.data?.total} className="ui-primary-button disabled:opacity-40">{exporting ? <RefreshCw size={13} className="animate-spin" /> : <Download size={13} />} Export CSV</button></div></header>

    {failed ? <section className="ui-command-surface flex items-start gap-3 p-5"><AlertCircle size={18} className="mt-0.5 text-red-400" /><div><p className="text-[12px] font-semibold text-red-300">SentinelOne vulnerability data is unavailable</p><p className="mt-1 text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>Confirm the token has Applications: View and View Risks permissions, then run Sync Now from Integrations.</p></div></section> : <>
      <section className="ui-command-surface grid grid-cols-2 divide-x divide-y overflow-hidden sm:grid-cols-3 xl:grid-cols-6 xl:divide-y-0" style={{ borderColor: 'var(--border)' }}><Metric label="Critical findings" value={summary.data?.severity.critical || 0} detail="Immediate remediation" color="#fb7185" /><Metric label="High findings" value={summary.data?.severity.high || 0} detail="Prioritize this cycle" color="#fb923c" /><Metric label="Unique CVEs" value={summary.data?.unique_cves || 0} detail={`${summary.data?.total || 0} finding instances`} /><Metric label="Exposed endpoints" value={summary.data?.endpoints || 0} detail="Distinct S1 devices" /><Metric label="Applications" value={summary.data?.applications || 0} detail="Vulnerable software titles" /><Metric label="Exploit evidence" value={summary.data?.exploit_available || 0} detail="Known maturity reported" color="#facc15" /></section>

      <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_300px]">
        <section className="ui-command-surface min-w-0 overflow-hidden">
          <div className="border-b px-4 py-4 sm:px-5" style={{ borderColor: 'var(--border)' }}><div className="flex flex-col gap-3"><div className="flex items-center justify-between"><div><p className="ui-eyebrow">Finding inventory</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>{findings.data?.total.toLocaleString() || 0} matching records{activeFilters ? ` · ${activeFilters} filters` : ''}</p></div>{findings.isFetching && <RefreshCw size={13} className="animate-spin" style={{ color: 'var(--accent)' }} />}</div><div className="grid gap-2 md:grid-cols-2 xl:grid-cols-[minmax(180px,1fr)_110px_125px_135px_105px_125px]">
            <label className="flex h-9 items-center gap-2 rounded-lg border px-3" style={{ background: 'var(--input-bg)', borderColor: 'var(--input-border)' }}><Search size={13} style={{ color: 'var(--text-4)' }} /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Application, CVE, endpoint…" className="min-w-0 flex-1 bg-transparent text-[11px] outline-none" style={{ color: 'var(--input-text)' }} /></label>
            <select value={severity} onChange={event => setSeverity(event.target.value)} className="focus-accent rounded-lg border px-2 text-[10px] outline-none" style={{ background: 'var(--input-bg)', borderColor: 'var(--input-border)', color: 'var(--input-text)' }}><option value="">All severity</option>{(facets.data?.severities || []).map(value => <option key={value}>{value}</option>)}</select>
            <select value={mitigation} onChange={event => setMitigation(event.target.value)} className="focus-accent rounded-lg border px-2 text-[10px] outline-none" style={{ background: 'var(--input-bg)', borderColor: 'var(--input-border)', color: 'var(--input-text)' }}><option value="">All mitigation</option>{(facets.data?.mitigations || []).map(value => <option key={value}>{value}</option>)}</select>
            <select value={status} onChange={event => setStatus(event.target.value)} className="focus-accent rounded-lg border px-2 text-[10px] outline-none" style={{ background: 'var(--input-bg)', borderColor: 'var(--input-border)', color: 'var(--input-text)' }}><option value="">All status</option>{(facets.data?.statuses || []).map(value => <option key={value}>{value}</option>)}</select>
            <select value={osType} onChange={event => setOsType(event.target.value)} className="focus-accent rounded-lg border px-2 text-[10px] outline-none" style={{ background: 'var(--input-bg)', borderColor: 'var(--input-border)', color: 'var(--input-text)' }}><option value="">All OS</option>{(facets.data?.os_types || []).map(value => <option key={value}>{value}</option>)}</select>
            <button onClick={() => setExploitOnly(value => !value)} className="pressable flex h-9 items-center justify-center gap-2 rounded-lg border px-3 text-[10px] font-semibold" style={{ color: exploitOnly ? '#fb7185' : 'var(--text-3)', borderColor: exploitOnly ? 'rgba(251,113,133,.35)' : 'var(--border)', background: exploitOnly ? 'rgba(251,113,133,.08)' : 'var(--surface-inset)' }}><Flame size={12} /> Exploit evidence</button>
          </div>{activeFilters > 0 && <button onClick={clearFilters} className="mt-3 text-[10px] font-semibold" style={{ color: 'var(--accent)' }}>Clear all filters</button>}</div></div>

          <div className="hidden grid-cols-[minmax(210px,1.4fr)_130px_minmax(160px,1fr)_95px_120px_25px] gap-4 border-b px-5 py-2.5 text-[9px] font-semibold uppercase tracking-[.09em] lg:grid" style={{ color: 'var(--text-4)', background: 'var(--table-header)', borderColor: 'var(--border)' }}><button onClick={() => setSort('application')} className="text-left">Application</button><span>CVE / severity</span><button onClick={() => setSort('endpoint')} className="text-left">Endpoint</button><button onClick={() => setSort('cvss')} className="text-left">CVSS</button><button onClick={() => setSort('detected')} className="text-left">Detected</button><span /></div>
          <div>{(findings.data?.items || []).map(item => <button key={item.id} onClick={() => setSelected(item)} className="ui-data-row grid w-full gap-3 border-b px-4 py-4 text-left last:border-b-0 sm:px-5 lg:grid-cols-[minmax(210px,1.4fr)_130px_minmax(160px,1fr)_95px_120px_25px] lg:items-center" style={{ borderColor: 'var(--border)' }}><div className="min-w-0"><div className="flex items-center gap-2"><PackageSearch size={13} style={{ color: 'var(--text-4)' }} /><span className="truncate text-[12px] font-semibold" style={{ color: 'var(--text-1)' }}>{item.application_name}</span></div><p className="mt-1 truncate pl-[21px] text-[10px]" style={{ color: 'var(--text-4)' }}>{item.application_version || 'Unknown version'} · {item.application_vendor || 'Unknown vendor'}</p></div><div><p className="font-mono text-[10px]" style={{ color: 'var(--text-2)' }}>{item.cve_id}</p><div className="mt-1.5"><SeverityBadge severity={item.severity} /></div></div><div className="min-w-0"><p className="truncate font-mono text-[11px]" style={{ color: 'var(--text-2)' }}>{item.endpoint_name}</p><p className="mt-1 truncate text-[9px]" style={{ color: 'var(--text-4)' }}>{item.os_type || 'Unknown OS'}{item.endpoint?.owner_email ? ` · ${item.endpoint.owner_email}` : ''}</p></div><div><p className="font-mono text-[15px] font-semibold" style={{ color: severityColor[item.severity || 'UNKNOWN'] }}>{item.nvd_base_score?.toFixed(1) ?? '—'}</p><p className="text-[8px]" style={{ color: 'var(--text-4)' }}>NVD base</p></div><div><p className="text-[10px]" style={{ color: 'var(--text-3)' }}>{relative(item.detection_date)}</p>{item.exploit_code_maturity && item.exploit_code_maturity.toLowerCase() !== 'unknown' && <p className="mt-1 flex items-center gap-1 text-[8px] text-rose-400"><Flame size={9} /> {item.exploit_code_maturity}</p>}</div><ArrowRight size={13} style={{ color: 'var(--text-4)' }} /></button>)}</div>
          {findings.isLoading && <div className="space-y-1 p-4">{[0,1,2,3,4,5].map(index => <div key={index} className="grid grid-cols-5 gap-4 py-3"><div className="shimmer h-4 rounded" /><div className="shimmer h-4 rounded" /><div className="shimmer h-4 rounded" /><div className="shimmer h-4 rounded" /><div className="shimmer h-4 rounded" /></div>)}</div>}
          {!findings.isLoading && !findings.data?.items.length && <div className="px-5 py-16 text-center"><CheckCircle2 size={25} className="mx-auto" style={{ color: 'var(--accent)' }} /><p className="mt-3 text-[12px] font-semibold" style={{ color: 'var(--text-2)' }}>{summary.data?.total ? 'No findings match these filters' : 'No vulnerability snapshot yet'}</p><p className="mx-auto mt-1 max-w-sm text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>{summary.data?.total ? 'Clear filters to return to the full SentinelOne inventory.' : 'Grant Applications: View and View Risks to the SentinelOne token, then run Sync Now.'}</p></div>}
          {(findings.data?.total || 0) > PAGE_SIZE && <footer className="flex items-center justify-between border-t px-5 py-3" style={{ borderColor: 'var(--border)' }}><p className="font-mono text-[9px]" style={{ color: 'var(--text-4)' }}>Page {page} / {totalPages}</p><div className="flex gap-1"><button onClick={() => setPage(value => Math.max(1, value - 1))} disabled={page === 1} className="rounded-md border p-2 disabled:opacity-30" style={{ borderColor: 'var(--border)', color: 'var(--text-3)' }}><ChevronLeft size={13} /></button><button onClick={() => setPage(value => Math.min(totalPages, value + 1))} disabled={page === totalPages} className="rounded-md border p-2 disabled:opacity-30" style={{ borderColor: 'var(--border)', color: 'var(--text-3)' }}><ChevronRight size={13} /></button></div></footer>}
        </section>

        <aside className="space-y-5">
          <section className="ui-command-surface p-4"><div className="flex items-center justify-between"><p className="ui-eyebrow">Severity pressure</p><ShieldAlert size={13} style={{ color: 'var(--text-4)' }} /></div><div className="mt-5 space-y-4">{Object.entries(summary.data?.severity || {}).map(([label, value]) => <button key={label} onClick={() => setSeverity(label.toUpperCase())} className="w-full text-left"><div className="mb-1.5 flex items-center justify-between"><span className="text-[10px] capitalize" style={{ color: 'var(--text-3)' }}>{label}</span><span className="font-mono text-[10px]" style={{ color: severityColor[label.toUpperCase()] }}>{value.toLocaleString()}</span></div><div className="h-1 overflow-hidden rounded-full" style={{ background: 'var(--surface-inset)' }}><div className="h-full rounded-full transition-[width] duration-500" style={{ width: `${Math.max(2, value / maxSeverity * 100)}%`, background: severityColor[label.toUpperCase()] }} /></div></button>)}</div></section>
          <section className="ui-command-surface overflow-hidden"><div className="border-b px-4 py-3.5" style={{ borderColor: 'var(--border)' }}><p className="ui-eyebrow">Highest-pressure apps</p></div>{(summary.data?.top_applications || []).map((app, index) => <button key={app.name} onClick={() => setSearch(app.name)} className="ui-data-row flex w-full items-center gap-3 border-b px-4 py-3 text-left last:border-b-0" style={{ borderColor: 'var(--border)' }}><span className="font-mono text-[9px]" style={{ color: 'var(--text-4)' }}>{String(index + 1).padStart(2, '0')}</span><div className="min-w-0 flex-1"><p className="truncate text-[10px] font-semibold" style={{ color: 'var(--text-2)' }}>{app.name}</p><p className="mt-0.5 text-[8px]" style={{ color: 'var(--text-4)' }}>{app.cves} CVEs · max {app.max_cvss?.toFixed(1) || '—'}</p></div><span className="font-mono text-[10px]" style={{ color: 'var(--text-3)' }}>{app.findings}</span></button>)}</section>
          <section className="rounded-xl border p-4" style={{ borderColor: 'rgba(16,185,129,.18)', background: 'rgba(16,185,129,.05)' }}><div className="flex items-start gap-3"><Sparkles size={14} className="mt-0.5 text-emerald-400" /><div><p className="text-[10px] font-semibold text-emerald-300">Exact SentinelOne evidence</p><p className="mt-1 text-[9px] leading-4" style={{ color: 'var(--text-4)' }}>Every finding keeps the original API object alongside normalized searchable fields.</p></div></div></section>
        </aside>
      </div>
    </>}
  </div>{selected && <FindingDrawer item={selected} onClose={() => setSelected(null)} />}</div>
}
