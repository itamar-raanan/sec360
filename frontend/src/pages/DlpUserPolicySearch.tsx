import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  RefreshCw,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  CheckCircle,
  Database,
  Download,
  FileSearch,
  Filter,
  Search,
  ShieldCheck,
  UserSearch,
  AlertCircle,
  X,
} from 'lucide-react'
import type { AxiosError } from 'axios'
import {
  fetchDlpPolicyExclusions,
  type DlpPolicyExclusion,
} from '../api/dlpPolicySearch'

const PAGE_SIZE = 50

const csvColumns: Array<[keyof DlpPolicyExclusion, string]> = [
  ['object_id', 'OBJECT_ID'],
  ['object_name', 'OBJECT_NAME'],
  ['object_description', 'OBJECT_DESCRIPTION'],
  ['object_status', 'OBJECT_STATUS'],
  ['rule_type', 'RULE_TYPE'],
  ['used_as', 'USED_AS'],
  ['policy_id', 'POLICY_ID'],
  ['policy_name', 'POLICY_NAME'],
  ['policy_active_status', 'POLICY_ACTIVE_STATUS'],
  ['policy_record_status', 'POLICY_RECORD_STATUS'],
  ['user_patterns', 'USER_PATTERNS'],
  ['ip_addresses', 'IP_ADDRESSES'],
  ['url_domains', 'URL_DOMAINS'],
  ['personal_email_breadth', 'PERSONAL_EMAIL_BREADTH'],
  ['personal_email_excluded_domains', 'PERSONAL_EMAIL_EXCLUDED_DOMAINS'],
  ['personal_email_max_recipients', 'PERSONAL_EMAIL_MAX_RECIPIENTS'],
  ['modified_date', 'MODIFIED_DATE'],
  ['modified_by_id', 'MODIFIED_BY_ID'],
  ['object_uuid', 'OBJECT_UUID'],
]

function normalize(value: unknown) {
  return String(value ?? '').trim().toLowerCase()
}

function parsePatterns(value: string | null) {
  if (!value) return []
  return value
    .split(/[\r\n;,]+/)
    .map(item => item.trim())
    .filter(Boolean)
}

function formatDate(value: string | null) {
  if (!value) return 'Unknown'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

function csvEscape(value: unknown) {
  const text = String(value ?? '')
  return `"${text.replace(/"/g, '""')}"`
}

function StatusPill({ value }: { value: string | null }) {
  const active = normalize(value) === 'active'
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.08em]"
      style={{
        color: active ? '#34d399' : '#f87171',
        background: active ? 'rgba(16,185,129,0.10)' : 'rgba(239,68,68,0.10)',
        border: `1px solid ${active ? 'rgba(16,185,129,0.18)' : 'rgba(239,68,68,0.18)'}`,
      }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: active ? '#34d399' : '#f87171' }} />
      {value || 'Unknown'}
    </span>
  )
}

function UsagePill({ value }: { value: string }) {
  const styles: Record<string, { color: string; background: string; border: string }> = {
    SENDER: { color: '#60a5fa', background: 'rgba(59,130,246,0.10)', border: 'rgba(59,130,246,0.18)' },
    RECIPIENT: { color: '#c084fc', background: 'rgba(168,85,247,0.10)', border: 'rgba(168,85,247,0.18)' },
    UNUSED: { color: 'var(--text-3)', background: 'var(--surface-3)', border: 'var(--border-mid)' },
  }
  const style = styles[value] || styles.UNUSED
  return (
    <span className="inline-flex rounded-md border px-2 py-1 text-[10px] font-semibold tracking-[0.08em]" style={style}>
      {value}
    </span>
  )
}

function DetailField({ label, value, mono = false }: { label: string; value: unknown; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--text-4)' }}>{label}</div>
      <div className={`break-words text-[12px] leading-5 ${mono ? 'font-mono' : ''}`} style={{ color: value ? 'var(--text-2)' : 'var(--text-4)' }}>
        {String(value ?? 'Not set')}
      </div>
    </div>
  )
}

function LoadingState() {
  return (
    <div className="space-y-3 px-5 py-5" aria-label="Loading DLP policy exclusions">
      {[0, 1, 2, 3, 4, 5].map(index => (
        <div key={index} className="grid grid-cols-[34px_1.2fr_1.5fr_100px_1fr_90px] items-center gap-4 py-3">
          <div className="shimmer h-7 w-7 rounded-md" />
          <div className="space-y-2"><div className="shimmer h-3 w-3/4 rounded" /><div className="shimmer h-2.5 w-1/2 rounded" /></div>
          <div className="shimmer h-6 w-4/5 rounded-md" />
          <div className="shimmer h-6 w-20 rounded-md" />
          <div className="shimmer h-3 w-3/4 rounded" />
          <div className="shimmer h-3 w-16 rounded" />
        </div>
      ))}
    </div>
  )
}

export default function DlpUserPolicySearch() {
  const searchRef = useRef<HTMLInputElement>(null)
  const [search, setSearch] = useState('')
  const [usage, setUsage] = useState('ALL')
  const [objectStatus, setObjectStatus] = useState('ACTIVE')
  const [policyStatus, setPolicyStatus] = useState('ALL')
  const [policy, setPolicy] = useState('ALL')
  const [page, setPage] = useState(1)
  const [expanded, setExpanded] = useState<string | null>(null)

  const query = useQuery({
    queryKey: ['dlp-policy-exclusions'],
    queryFn: fetchDlpPolicyExclusions,
    staleTime: 5 * 60 * 1000,
    refetchOnWindowFocus: false,
    retry: 1,
  })

  const items = useMemo(() => query.data?.items ?? [], [query.data?.items])
  const policyOptions = useMemo(() => Array.from(new Set(
    items.map(item => item.policy_name).filter((name): name is string => Boolean(name)),
  )).sort((a, b) => a.localeCompare(b)), [items])

  const filtered = useMemo(() => {
    const needle = normalize(search)
    return items.filter(item => {
      if (usage !== 'ALL' && item.used_as !== usage) return false
      if (objectStatus !== 'ALL' && normalize(item.object_status) !== normalize(objectStatus)) return false
      if (policyStatus !== 'ALL' && normalize(item.policy_record_status) !== normalize(policyStatus)) return false
      if (policy !== 'ALL' && item.policy_name !== policy) return false
      if (!needle) return true
      return [
        item.object_name,
        item.object_description,
        item.user_patterns,
        item.policy_name,
        item.ip_addresses,
        item.url_domains,
        item.personal_email_excluded_domains,
        item.object_uuid,
      ].some(value => normalize(value).includes(needle))
    })
  }, [items, search, usage, objectStatus, policyStatus, policy])

  useEffect(() => {
    setPage(1)
    setExpanded(null)
  }, [search, usage, objectStatus, policyStatus, policy])

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === '/' && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'SELECT') {
        event.preventDefault()
        searchRef.current?.focus()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  const stats = useMemo(() => ({
    objects: new Set(filtered.map(item => String(item.object_id))).size,
    policies: new Set(filtered.filter(item => item.policy_id != null).map(item => String(item.policy_id))).size,
    mapped: filtered.filter(item => item.used_as !== 'UNUSED').length,
    unused: new Set(filtered.filter(item => item.used_as === 'UNUSED').map(item => String(item.object_id))).size,
  }), [filtered])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const pageItems = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
  const activeFilters = [usage !== 'ALL', objectStatus !== 'ACTIVE', policyStatus !== 'ALL', policy !== 'ALL'].filter(Boolean).length

  const clearFilters = () => {
    setSearch('')
    setUsage('ALL')
    setObjectStatus('ACTIVE')
    setPolicyStatus('ALL')
    setPolicy('ALL')
  }

  const exportCsv = () => {
    const lines = [
      csvColumns.map(([, label]) => csvEscape(label)).join(','),
      ...filtered.map(item => csvColumns.map(([key]) => csvEscape(item[key])).join(',')),
    ]
    const blob = new Blob([`\uFEFF${lines.join('\r\n')}`], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `dlp-user-policy-search-${new Date().toISOString().slice(0, 10)}.csv`
    link.click()
    URL.revokeObjectURL(url)
  }

  const error = query.error as AxiosError<{ detail?: string }> | null
  const errorMessage = error?.response?.data?.detail || 'Could not reach the Symantec DLP database.'

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-[1700px] px-4 py-5 sm:px-6 lg:px-8">
        <section className="mb-5 flex flex-col gap-4 border-b pb-5 lg:flex-row lg:items-end lg:justify-between" style={{ borderColor: 'var(--border)' }}>
          <div className="max-w-3xl">
            <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-emerald-400">
              <Database size={14} /> Live Symantec DLP intelligence
            </div>
            <h2 className="text-2xl font-semibold tracking-[-0.035em] sm:text-3xl" style={{ color: 'var(--text-1)' }}>DLP User Policy Search</h2>
            <p className="mt-2 max-w-2xl text-[13px] leading-5" style={{ color: 'var(--text-3)' }}>
              Find user, sender, and recipient exclusions across nested DLP policy conditions. Results come directly from the configured Oracle database.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {query.data && (
              <span className="mr-1 text-[11px]" style={{ color: 'var(--text-4)' }}>
                Refreshed {formatDate(query.data.source_refreshed_at)} · {query.data.query_duration_ms.toLocaleString()} ms
              </span>
            )}
            <button
              type="button"
              onClick={() => query.refetch()}
              disabled={query.isFetching}
              className="focus-accent pressable inline-flex h-9 items-center gap-2 rounded-lg border px-3 text-[12px] font-medium disabled:cursor-wait disabled:opacity-60"
              style={{ background: 'var(--surface-2)', borderColor: 'var(--border-mid)', color: 'var(--text-2)' }}
            >
              <RefreshCw size={15} className={query.isFetching ? 'animate-spin' : ''} /> Refresh source
            </button>
            <button
              type="button"
              onClick={exportCsv}
              disabled={!filtered.length}
              className="focus-accent pressable inline-flex h-9 items-center gap-2 rounded-lg bg-emerald-600 px-3 text-[12px] font-semibold text-white hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Download size={15} /> Export {filtered.length.toLocaleString()} rows
            </button>
          </div>
        </section>

        {query.data?.truncated && (
          <div className="mb-4 flex items-start gap-3 rounded-lg border border-amber-500/20 bg-amber-500/[0.07] px-4 py-3 text-[12px] text-amber-300">
            <AlertCircle size={17} className="mt-0.5 shrink-0" />
            The Oracle result exceeded {query.data.max_rows.toLocaleString()} rows. This view shows the first {query.data.max_rows.toLocaleString()}; refine the source query if the complete set is required.
          </div>
        )}

        <section className="mb-4 grid grid-cols-2 border lg:grid-cols-4" style={{ background: 'var(--surface-2)', borderColor: 'var(--border)' }}>
          {[
            { label: 'Exclusion objects', value: stats.objects, icon: UserSearch, note: 'Unique pattern objects' },
            { label: 'Policies', value: stats.policies, icon: ShieldCheck, note: 'Unique policy matches' },
            { label: 'Policy mappings', value: stats.mapped, icon: CheckCircle, note: 'Sender + recipient links' },
            { label: 'Unused objects', value: stats.unused, icon: FileSearch, note: 'Not linked to a policy' },
          ].map(({ label, value, icon: Icon, note }, index) => (
            <div key={label} className={`min-w-0 px-4 py-4 sm:px-5 ${index % 2 ? '' : 'border-r'} ${index < 2 ? 'border-b lg:border-b-0' : ''} ${index === 1 ? 'lg:border-r' : ''} ${index === 2 ? 'lg:border-r' : ''}`} style={{ borderColor: 'var(--border)' }}>
              <div className="mb-2 flex items-center justify-between">
                <span className="text-[10px] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--text-4)' }}>{label}</span>
                <Icon size={16} className="text-emerald-400" />
              </div>
              <div className="text-2xl font-semibold tabular-nums tracking-tight" style={{ color: 'var(--text-1)' }}>{value.toLocaleString()}</div>
              <div className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>{note}</div>
            </div>
          ))}
        </section>

        <section className="overflow-hidden rounded-xl border" style={{ background: 'var(--surface-2)', borderColor: 'var(--border)' }}>
          <div className="border-b px-4 py-4" style={{ borderColor: 'var(--border)' }}>
            <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
              <div className="relative min-w-0 flex-1">
                <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-4)' }} />
                <input
                  ref={searchRef}
                  value={search}
                  onChange={event => setSearch(event.target.value)}
                  placeholder="Search user, email, object, policy, IP, or domain…"
                  className="focus-accent h-10 w-full rounded-lg border bg-transparent pl-10 pr-20 text-[13px] outline-none"
                  style={{ background: 'var(--input-bg)', borderColor: 'var(--input-border)', color: 'var(--input-text)' }}
                />
                {search ? (
                  <button type="button" onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1" style={{ color: 'var(--text-4)' }} aria-label="Clear search"><X size={14} /></button>
                ) : (
                  <kbd className="absolute right-3 top-1/2 -translate-y-1/2 rounded border px-1.5 py-0.5 font-mono text-[10px]" style={{ borderColor: 'var(--border)', color: 'var(--text-4)' }}>/</kbd>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <FilterSelect label="Usage" value={usage} onChange={setUsage} options={['ALL', 'SENDER', 'RECIPIENT', 'UNUSED']} />
                <FilterSelect label="Object" value={objectStatus} onChange={setObjectStatus} options={['ALL', 'ACTIVE', 'DELETED']} />
                <FilterSelect label="Policy" value={policyStatus} onChange={setPolicyStatus} options={['ALL', 'ACTIVE', 'DELETED']} />
                <div className="relative">
                  <select value={policy} onChange={event => setPolicy(event.target.value)} className="focus-accent h-9 max-w-[220px] appearance-none truncate rounded-lg border pl-3 pr-8 text-[11px] outline-none" style={{ background: 'var(--surface-3)', borderColor: 'var(--border)', color: 'var(--text-2)' }} aria-label="Filter by policy name">
                    <option value="ALL">All policy names</option>
                    {policyOptions.map(name => <option key={name} value={name}>{name}</option>)}
                  </select>
                  <ChevronDown size={11} className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-4)' }} />
                </div>
                {(activeFilters > 0 || search) && (
                  <button type="button" onClick={clearFilters} className="inline-flex h-9 items-center gap-1.5 rounded-lg px-2.5 text-[11px]" style={{ color: 'var(--text-3)' }}><Filter size={13} /> Clear</button>
                )}
              </div>
            </div>
          </div>

          {query.isLoading ? <LoadingState /> : query.isError ? (
            <div className="flex min-h-[340px] flex-col items-center justify-center px-6 py-12 text-center">
              <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-xl border border-red-500/20 bg-red-500/10 text-red-400"><AlertCircle size={23} /></div>
              <h3 className="text-[15px] font-semibold" style={{ color: 'var(--text-1)' }}>DLP query unavailable</h3>
              <p className="mt-2 max-w-md text-[12px] leading-5" style={{ color: 'var(--text-3)' }}>{errorMessage}</p>
              <button type="button" onClick={() => query.refetch()} className="pressable mt-5 inline-flex h-9 items-center gap-2 rounded-lg bg-emerald-600 px-4 text-[12px] font-semibold text-white hover:bg-emerald-500"><RefreshCw size={14} /> Try again</button>
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex min-h-[340px] flex-col items-center justify-center px-6 py-12 text-center">
              <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-xl border text-emerald-400" style={{ background: 'var(--accent-dim)', borderColor: 'rgba(16,185,129,0.18)' }}><FileSearch size={23} /></div>
              <h3 className="text-[15px] font-semibold" style={{ color: 'var(--text-1)' }}>{items.length ? 'No matching exclusions' : 'No DLP exclusions found'}</h3>
              <p className="mt-2 max-w-md text-[12px] leading-5" style={{ color: 'var(--text-3)' }}>{items.length ? 'Try a different user, policy name, or filter combination.' : 'The query completed successfully but returned no sender or recipient pattern objects.'}</p>
              {items.length > 0 && <button type="button" onClick={clearFilters} className="mt-4 text-[12px] font-medium text-emerald-400 hover:text-emerald-300">Reset all filters</button>}
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[1040px] border-collapse text-left">
                  <thead>
                    <tr className="border-b" style={{ borderColor: 'var(--border)', background: 'var(--surface-1)' }}>
                      <th className="w-10 px-3 py-3" />
                      {['Exclusion object', 'User patterns', 'Used as', 'Policy', 'Object status', 'Modified'].map(label => (
                        <th key={label} className="px-3 py-3 text-[10px] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--text-4)' }}>{label}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {pageItems.map((item, index) => {
                      const rowKey = `${item.object_id}-${item.policy_id ?? 'none'}-${item.used_as}-${index}`
                      const isExpanded = expanded === rowKey
                      const patterns = parsePatterns(item.user_patterns)
                      return (
                        <React.Fragment key={rowKey}>
                          <tr className="group cursor-pointer border-b hover:bg-white/[0.025]" style={{ borderColor: 'var(--border)' }} onClick={() => setExpanded(isExpanded ? null : rowKey)} aria-expanded={isExpanded}>
                            <td className="px-3 py-3.5"><button type="button" className="flex h-7 w-7 items-center justify-center rounded-md" style={{ color: 'var(--text-4)', background: isExpanded ? 'var(--accent-dim)' : 'transparent' }} aria-label={isExpanded ? 'Collapse details' : 'Expand details'}>{isExpanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}</button></td>
                            <td className="max-w-[250px] px-3 py-3.5 align-top">
                              <div className="truncate text-[13px] font-medium" style={{ color: 'var(--text-1)' }}>{item.object_name || 'Unnamed object'}</div>
                              <div className="mt-1 truncate font-mono text-[10px]" style={{ color: 'var(--text-4)' }}>ID {String(item.object_id ?? '—')} · Rule {String(item.rule_type ?? '—')}</div>
                            </td>
                            <td className="max-w-[330px] px-3 py-3.5 align-top">
                              {patterns.length ? <div className="flex flex-wrap gap-1.5">{patterns.slice(0, 2).map(pattern => <span key={pattern} className="max-w-[220px] truncate rounded-md border px-2 py-1 font-mono text-[10px]" style={{ background: 'var(--surface-3)', borderColor: 'var(--border)', color: 'var(--text-2)' }}>{pattern}</span>)}{patterns.length > 2 && <span className="px-1 py-1 text-[10px]" style={{ color: 'var(--text-4)' }}>+{patterns.length - 2}</span>}</div> : <span className="text-[11px]" style={{ color: 'var(--text-4)' }}>No user pattern</span>}
                            </td>
                            <td className="px-3 py-3.5 align-top"><UsagePill value={item.used_as} /></td>
                            <td className="max-w-[260px] px-3 py-3.5 align-top">
                              <div className="truncate text-[12px]" style={{ color: item.policy_name ? 'var(--text-2)' : 'var(--text-4)' }}>{item.policy_name || 'Not linked to a policy'}</div>
                              {item.policy_id != null && <div className="mt-1 font-mono text-[10px]" style={{ color: 'var(--text-4)' }}>Policy {String(item.policy_id)}</div>}
                            </td>
                            <td className="px-3 py-3.5 align-top"><StatusPill value={item.object_status} /></td>
                            <td className="whitespace-nowrap px-3 py-3.5 align-top text-[11px]" style={{ color: 'var(--text-3)' }}>{formatDate(item.modified_date)}</td>
                          </tr>
                          {isExpanded && (
                            <tr className="border-b" style={{ borderColor: 'var(--border)', background: 'color-mix(in srgb, var(--surface-3) 62%, transparent)' }}>
                              <td />
                              <td colSpan={6} className="px-3 py-5">
                                <div className="mb-5 grid gap-5 lg:grid-cols-[1.2fr_1fr_1fr]">
                                  <DetailField label="Description" value={item.object_description} />
                                  <DetailField label="Policy record" value={`${item.policy_record_status ?? 'Unknown'} · Active status ${String(item.policy_active_status ?? 'Unknown')}`} />
                                  <DetailField label="Object UUID" value={item.object_uuid} mono />
                                </div>
                                <div className="grid gap-5 border-t pt-5 sm:grid-cols-2 lg:grid-cols-4" style={{ borderColor: 'var(--border)' }}>
                                  <DetailField label="All user patterns" value={item.user_patterns} mono />
                                  <DetailField label="IP addresses" value={item.ip_addresses} mono />
                                  <DetailField label="URL domains" value={item.url_domains} mono />
                                  <DetailField label="Personal email excluded domains" value={item.personal_email_excluded_domains} mono />
                                  <DetailField label="Personal email breadth" value={item.personal_email_breadth} />
                                  <DetailField label="Max personal email recipients" value={item.personal_email_max_recipients} />
                                  <DetailField label="Modified by ID" value={item.modified_by_id} mono />
                                  <DetailField label="Usage" value={item.used_as} />
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      )
                    })}
                  </tbody>
                </table>
              </div>
              <div className="flex flex-col gap-3 border-t px-4 py-3 sm:flex-row sm:items-center sm:justify-between" style={{ borderColor: 'var(--border)' }}>
                <div className="text-[11px]" style={{ color: 'var(--text-4)' }}>Showing {((page - 1) * PAGE_SIZE + 1).toLocaleString()}–{Math.min(page * PAGE_SIZE, filtered.length).toLocaleString()} of {filtered.length.toLocaleString()} matching rows</div>
                <div className="flex items-center gap-2">
                  <button type="button" disabled={page === 1} onClick={() => setPage(value => Math.max(1, value - 1))} className="focus-accent flex h-8 w-8 items-center justify-center rounded-lg border disabled:opacity-30" style={{ borderColor: 'var(--border)', color: 'var(--text-3)' }} aria-label="Previous page"><ChevronLeft size={13} /></button>
                  <span className="min-w-[92px] text-center text-[11px] tabular-nums" style={{ color: 'var(--text-3)' }}>Page {page} of {totalPages}</span>
                  <button type="button" disabled={page === totalPages} onClick={() => setPage(value => Math.min(totalPages, value + 1))} className="focus-accent flex h-8 w-8 items-center justify-center rounded-lg border disabled:opacity-30" style={{ borderColor: 'var(--border)', color: 'var(--text-3)' }} aria-label="Next page"><ChevronRight size={13} /></button>
                </div>
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  )
}

function FilterSelect({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: string[] }) {
  return (
    <div className="relative">
      <select value={value} onChange={event => onChange(event.target.value)} className="focus-accent h-9 appearance-none rounded-lg border pl-3 pr-8 text-[11px] outline-none" style={{ background: 'var(--surface-3)', borderColor: 'var(--border)', color: 'var(--text-2)' }} aria-label={`Filter by ${label.toLowerCase()}`}>
        {options.map(option => <option key={option} value={option}>{label}: {option === 'ALL' ? 'All' : option.charAt(0) + option.slice(1).toLowerCase()}</option>)}
      </select>
      <ChevronDown size={11} className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-4)' }} />
    </div>
  )
}
