import React, { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import {
  AlertCircle, Archive, ArrowRight, Check, CheckCircle2, Copy, Database,
  Fingerprint, GitMerge, History, RefreshCw, Search, ShieldCheck, UserX, X,
} from 'lucide-react'
import {
  fetchDuplicateCandidates, fetchQualityEndpoints, fetchQualitySummary,
  updateEndpointLifecycle, type ConfidenceTier, type LifecycleState,
  type QualityEndpoint,
} from '../api/dataQuality'
import { useAuthStore } from '../store/auth'

const stateLabels: Record<LifecycleState, string> = {
  active: 'Active', stale: 'Stale', ignored: 'Ignored', decommissioned: 'Decommissioned',
}

const confidenceColor: Record<ConfidenceTier, string> = {
  high: '#34d399', medium: '#fbbf24', low: '#f87171',
}

function relativeDate(value: string | null) {
  if (!value) return 'Never observed'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Unknown'
  return formatDistanceToNow(date, { addSuffix: true })
}

function Metric({ label, value, note, tone = 'var(--text-1)' }: { label: string; value: number; note: string; tone?: string }) {
  return (
    <div className="ui-metric min-w-0 py-4">
      <p className="ui-eyebrow">{label}</p>
      <p className="mt-2 font-mono text-[26px] font-semibold tracking-[-0.05em]" style={{ color: tone }}>{value.toLocaleString()}</p>
      <p className="mt-1 truncate text-[11px]" style={{ color: 'var(--text-4)' }}>{note}</p>
    </div>
  )
}

function ConfidenceBadge({ tier, score }: { tier: ConfidenceTier; score: number }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-md border px-2 py-1 font-mono text-[10px] font-semibold"
      style={{ color: confidenceColor[tier], borderColor: `${confidenceColor[tier]}33`, background: `${confidenceColor[tier]}12` }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: confidenceColor[tier] }} />
      {score} · {tier.toUpperCase()}
    </span>
  )
}

function LifecycleBadge({ state }: { state: LifecycleState }) {
  const tones: Record<LifecycleState, string> = {
    active: '#34d399', stale: '#fbbf24', ignored: '#94a3b8', decommissioned: '#f87171',
  }
  return (
    <span className="rounded-md border px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.07em]"
      style={{ color: tones[state], borderColor: `${tones[state]}30`, background: `${tones[state]}0d` }}>
      {stateLabels[state]}
    </span>
  )
}

function LifecycleDialog({ endpoint, onClose }: { endpoint: QualityEndpoint; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [state, setState] = useState<LifecycleState>(endpoint.lifecycle_state)
  const [reason, setReason] = useState(endpoint.lifecycle_reason || '')
  const requiresReason = state === 'ignored' || state === 'decommissioned'
  const mutation = useMutation({
    mutationFn: () => updateEndpointLifecycle(endpoint.id, state, reason.trim() || null),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['data-quality-summary'] }),
        queryClient.invalidateQueries({ queryKey: ['data-quality-endpoints'] }),
        queryClient.invalidateQueries({ queryKey: ['data-quality-duplicates'] }),
        queryClient.invalidateQueries({ queryKey: ['compliance'] }),
      ])
      onClose()
    },
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" onMouseDown={onClose}>
      <section className="ui-float-surface w-full max-w-[520px] overflow-hidden" role="dialog" aria-modal="true" aria-labelledby="lifecycle-title" onMouseDown={event => event.stopPropagation()}>
        <div className="flex items-start justify-between border-b px-5 py-4" style={{ borderColor: 'var(--border)' }}>
          <div>
            <p className="ui-eyebrow">Analyst disposition</p>
            <h2 id="lifecycle-title" className="mt-2 text-[17px] font-semibold" style={{ color: 'var(--text-1)' }}>{endpoint.hostname}</h2>
          </div>
          <button className="rounded-md p-1.5 hover:bg-white/[0.05]" style={{ color: 'var(--text-3)' }} onClick={onClose} aria-label="Close"><X size={16} /></button>
        </div>
        <div className="space-y-5 p-5">
          <div>
            <label className="mb-2 block text-[11px] font-semibold" style={{ color: 'var(--text-3)' }}>Lifecycle state</label>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {(['active', 'stale', 'ignored', 'decommissioned'] as LifecycleState[]).map(option => (
                <button key={option} onClick={() => setState(option)} className="pressable rounded-lg border px-2 py-2.5 text-[11px] font-medium"
                  style={{ color: state === option ? 'var(--accent)' : 'var(--text-3)', borderColor: state === option ? 'var(--accent)' : 'var(--border)', background: state === option ? 'var(--accent-dim)' : 'var(--surface-inset)' }}>
                  {stateLabels[option]}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label htmlFor="lifecycle-reason" className="mb-2 block text-[11px] font-semibold" style={{ color: 'var(--text-3)' }}>
              Decision reason {requiresReason ? <span style={{ color: '#f87171' }}>*</span> : <span style={{ color: 'var(--text-4)' }}>(optional)</span>}
            </label>
            <textarea id="lifecycle-reason" rows={3} value={reason} onChange={event => setReason(event.target.value)}
              placeholder="Give the next analyst enough context to trust this decision…"
              className="focus-accent w-full resize-none rounded-lg border px-3 py-2.5 text-[12px] outline-none"
              style={{ background: 'var(--input-bg)', borderColor: 'var(--input-border)', color: 'var(--input-text)' }} />
          </div>
          <div className="rounded-lg border px-3 py-2.5 text-[11px] leading-5" style={{ borderColor: 'var(--border)', background: 'var(--surface-inset)', color: 'var(--text-3)' }}>
            {state === 'active' ? 'This endpoint returns to current inventory when its source observation is fresh.' : 'This endpoint will be excluded from compliance coverage. The action and reason are written to the audit log.'}
          </div>
          {mutation.isError && <p className="text-[11px] text-red-400">The lifecycle decision could not be saved. Please try again.</p>}
        </div>
        <div className="flex justify-end gap-2 border-t px-5 py-3.5" style={{ borderColor: 'var(--border)' }}>
          <button onClick={onClose} className="rounded-lg px-3 py-2 text-[11px] font-semibold" style={{ color: 'var(--text-3)' }}>Cancel</button>
          <button onClick={() => mutation.mutate()} disabled={mutation.isPending || (requiresReason && !reason.trim())}
            className="ui-primary-button disabled:cursor-not-allowed disabled:opacity-40">
            {mutation.isPending ? <RefreshCw size={13} className="animate-spin" /> : <Check size={13} />}
            Save disposition
          </button>
        </div>
      </section>
    </div>
  )
}

export default function DataQuality() {
  const { user } = useAuthStore()
  const canEdit = user?.role === 'analyst' || user?.role === 'admin'
  const [search, setSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [confidence, setConfidence] = useState('')
  const [lifecycle, setLifecycle] = useState('')
  const [issue, setIssue] = useState('')
  const [tab, setTab] = useState<'review' | 'duplicates'>('review')
  const [selected, setSelected] = useState<QualityEndpoint | null>(null)

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedSearch(search.trim()), 250)
    return () => window.clearTimeout(timer)
  }, [search])

  const summaryQuery = useQuery({ queryKey: ['data-quality-summary'], queryFn: fetchQualitySummary, refetchInterval: 60_000 })
  const endpointsQuery = useQuery({
    queryKey: ['data-quality-endpoints', debouncedSearch, confidence, lifecycle, issue],
    queryFn: () => fetchQualityEndpoints({
      search: debouncedSearch || undefined, confidence: confidence || undefined,
      lifecycle: lifecycle || undefined, issue: issue || undefined,
    }),
  })
  const duplicatesQuery = useQuery({
    queryKey: ['data-quality-duplicates'], queryFn: fetchDuplicateCandidates,
    enabled: tab === 'duplicates',
  })

  const summary = summaryQuery.data
  const enabledSources = useMemo(() => summary?.source_freshness.filter(source => source.is_enabled) ?? [], [summary])
  const isLoading = summaryQuery.isLoading || endpointsQuery.isLoading
  const hasError = summaryQuery.isError || endpointsQuery.isError

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-[1500px] px-4 py-6 sm:px-6 lg:px-8">
        <header className="flex flex-col justify-between gap-5 pb-6 lg:flex-row lg:items-end">
          <div className="max-w-2xl">
            <div className="mb-3 flex items-center gap-2">
              <span className="status-pulse" data-status={summary?.confidence.low ? 'warning' : 'healthy'} />
              <p className="ui-eyebrow">Identity control plane</p>
            </div>
            <h1 className="text-[clamp(1.8rem,4vw,3rem)] font-semibold leading-[0.98] tracking-[-0.055em]" style={{ color: 'var(--text-1)' }}>
              Asset confidence,<br /><span style={{ color: 'var(--text-3)' }}>made explainable.</span>
            </h1>
            <p className="mt-4 max-w-xl text-[12px] leading-5" style={{ color: 'var(--text-3)' }}>
              See why endpoint identities were trusted, which records affect compliance, and where analyst decisions are needed.
            </p>
          </div>
          <div className="flex items-center gap-2 text-[10px]" style={{ color: 'var(--text-4)' }}>
            <History size={12} /> Generated {summary ? relativeDate(summary.generated_at) : 'now'}
          </div>
        </header>

        {hasError ? (
          <div className="ui-command-surface flex items-center gap-3 p-5 text-[12px] text-red-400"><AlertCircle size={17} /> Data quality analysis is unavailable. Refresh the page to retry.</div>
        ) : (
          <>
            <section className="ui-command-surface grid grid-cols-2 divide-x divide-y overflow-hidden sm:grid-cols-3 xl:grid-cols-6 xl:divide-y-0" style={{ borderColor: 'var(--border)' }} aria-label="Data quality summary">
              <Metric label="Current inventory" value={summary?.current_inventory ?? 0} note={`${summary?.total ?? 0} records observed`} tone="#34d399" />
              <Metric label="High confidence" value={summary?.confidence.high ?? 0} note="Strong identity evidence" />
              <Metric label="Needs review" value={(summary?.confidence.low ?? 0) + (summary?.confidence.medium ?? 0)} note="Low or partial evidence" tone="#fbbf24" />
              <Metric label="Unassigned" value={summary?.unassigned ?? 0} note="No directory owner" />
              <Metric label="Duplicates" value={summary?.duplicate_candidates ?? 0} note="Candidates, not auto-merged" tone="#f87171" />
              <Metric label="Excluded" value={(summary?.lifecycle.ignored ?? 0) + (summary?.lifecycle.decommissioned ?? 0)} note="Audited dispositions" />
            </section>

            <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_310px]">
              <section className="ui-command-surface min-w-0 overflow-hidden">
                <div className="flex flex-col gap-3 border-b px-4 py-4 sm:px-5" style={{ borderColor: 'var(--border)' }}>
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-1 rounded-lg p-1" style={{ background: 'var(--surface-inset)' }}>
                      <button onClick={() => setTab('review')} className="rounded-md px-3 py-1.5 text-[11px] font-semibold"
                        style={{ background: tab === 'review' ? 'var(--surface-2)' : 'transparent', color: tab === 'review' ? 'var(--text-1)' : 'var(--text-4)', boxShadow: tab === 'review' ? 'var(--shadow-card)' : 'none' }}>
                        Review queue <span className="ml-1 font-mono">{endpointsQuery.data?.total ?? 0}</span>
                      </button>
                      <button onClick={() => setTab('duplicates')} className="rounded-md px-3 py-1.5 text-[11px] font-semibold"
                        style={{ background: tab === 'duplicates' ? 'var(--surface-2)' : 'transparent', color: tab === 'duplicates' ? 'var(--text-1)' : 'var(--text-4)', boxShadow: tab === 'duplicates' ? 'var(--shadow-card)' : 'none' }}>
                        Duplicate candidates <span className="ml-1 font-mono">{summary?.duplicate_candidates ?? 0}</span>
                      </button>
                    </div>
                    {isLoading && <RefreshCw size={13} className="animate-spin" style={{ color: 'var(--accent)' }} />}
                  </div>
                  {tab === 'review' && (
                    <div className="grid gap-2 md:grid-cols-[minmax(180px,1fr)_145px_145px_165px]">
                      <label className="flex items-center gap-2 rounded-lg border px-3" style={{ background: 'var(--input-bg)', borderColor: 'var(--input-border)' }}>
                        <Search size={13} style={{ color: 'var(--text-4)' }} />
                        <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Hostname, serial or user…" className="h-9 min-w-0 flex-1 bg-transparent text-[11px] outline-none" style={{ color: 'var(--input-text)' }} />
                      </label>
                      <select value={confidence} onChange={event => setConfidence(event.target.value)} className="focus-accent h-9 rounded-lg border px-2 text-[11px] outline-none" style={{ background: 'var(--input-bg)', borderColor: 'var(--input-border)', color: 'var(--input-text)' }}>
                        <option value="">All confidence</option><option value="low">Low confidence</option><option value="medium">Medium confidence</option><option value="high">High confidence</option>
                      </select>
                      <select value={lifecycle} onChange={event => setLifecycle(event.target.value)} className="focus-accent h-9 rounded-lg border px-2 text-[11px] outline-none" style={{ background: 'var(--input-bg)', borderColor: 'var(--input-border)', color: 'var(--input-text)' }}>
                        <option value="">All lifecycle</option>{Object.entries(stateLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                      </select>
                      <select value={issue} onChange={event => setIssue(event.target.value)} className="focus-accent h-9 rounded-lg border px-2 text-[11px] outline-none" style={{ background: 'var(--input-bg)', borderColor: 'var(--input-border)', color: 'var(--input-text)' }}>
                        <option value="">All quality issues</option><option value="unassigned">Unassigned owner</option><option value="missing_serial">Missing serial</option><option value="low_confidence">Low confidence</option><option value="not_in_compliance">Outside compliance</option>
                      </select>
                    </div>
                  )}
                </div>

                {tab === 'review' ? (
                  <div>
                    {(endpointsQuery.data?.items ?? []).map(endpoint => (
                      <article key={endpoint.id} className="ui-data-row grid gap-3 border-b px-4 py-4 last:border-b-0 sm:px-5 lg:grid-cols-[minmax(190px,1.2fr)_150px_minmax(190px,1fr)_140px] lg:items-center" style={{ borderColor: 'var(--border)' }}>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2"><Fingerprint size={13} style={{ color: 'var(--text-4)' }} /><h3 className="truncate font-mono text-[12px] font-semibold" style={{ color: 'var(--text-1)' }}>{endpoint.hostname}</h3></div>
                          <p className="mt-1 truncate pl-[21px] font-mono text-[10px]" style={{ color: 'var(--text-4)' }}>{endpoint.serial_number || 'No hardware serial'}</p>
                        </div>
                        <div><ConfidenceBadge tier={endpoint.confidence.tier} score={endpoint.confidence.score} /><p className="mt-1.5 text-[10px] capitalize" style={{ color: 'var(--text-4)' }}>{endpoint.confidence.method.replace(/_/g, ' ')}</p></div>
                        <div className="min-w-0">
                          <p className="truncate text-[11px]" style={{ color: 'var(--text-2)' }}>{endpoint.confidence.explanation}</p>
                          <div className="mt-1.5 flex flex-wrap gap-1">{endpoint.confidence.sources.map(source => <span key={source} className="rounded px-1.5 py-0.5 text-[9px]" style={{ background: 'var(--surface-inset)', color: 'var(--text-4)' }}>{source}</span>)}</div>
                        </div>
                        <div className="flex items-center justify-between gap-2 lg:justify-end">
                          <div className="text-right"><LifecycleBadge state={endpoint.lifecycle_state} /><p className="mt-1.5 text-[9px]" style={{ color: endpoint.included_in_compliance ? '#34d399' : 'var(--text-4)' }}>{endpoint.included_in_compliance ? 'In compliance scope' : 'Excluded from scope'}</p></div>
                          {canEdit && <button onClick={() => setSelected(endpoint)} className="rounded-md border p-2 hover:bg-white/[0.04]" style={{ borderColor: 'var(--border)', color: 'var(--text-3)' }} title="Review lifecycle"><ArrowRight size={13} /></button>}
                        </div>
                      </article>
                    ))}
                    {!isLoading && !endpointsQuery.data?.items.length && <div className="px-5 py-16 text-center"><CheckCircle2 className="mx-auto" size={24} style={{ color: 'var(--accent)' }} /><p className="mt-3 text-[12px] font-semibold" style={{ color: 'var(--text-2)' }}>No endpoints match this review view</p><p className="mt-1 text-[10px]" style={{ color: 'var(--text-4)' }}>Try clearing one or more filters.</p></div>}
                  </div>
                ) : (
                  <div>
                    {(duplicatesQuery.data?.items ?? []).map(candidate => (
                      <article key={candidate.candidate_id} className="border-b px-5 py-5 last:border-b-0" style={{ borderColor: 'var(--border)' }}>
                        <div className="flex items-start justify-between gap-4"><div><p className="ui-eyebrow">{candidate.score}% match</p><p className="mt-2 text-[11px]" style={{ color: 'var(--text-3)' }}>{candidate.reasons.join(' · ')}</p></div><GitMerge size={16} style={{ color: candidate.score > 90 ? '#f87171' : '#fbbf24' }} /></div>
                        <div className="mt-4 grid gap-px overflow-hidden rounded-lg border sm:grid-cols-2" style={{ background: 'var(--border)', borderColor: 'var(--border)' }}>
                          {[candidate.left, candidate.right].map(endpoint => <div key={endpoint.id} className="p-3" style={{ background: 'var(--surface-inset)' }}><div className="flex items-center justify-between gap-2"><span className="truncate font-mono text-[11px] font-semibold" style={{ color: 'var(--text-1)' }}>{endpoint.hostname}</span><Copy size={11} style={{ color: 'var(--text-4)' }} /></div><p className="mt-1 font-mono text-[9px]" style={{ color: 'var(--text-4)' }}>{endpoint.serial_number || 'No serial'} · {endpoint.source || 'Unknown source'}</p></div>)}
                        </div>
                        <p className="mt-3 text-[10px]" style={{ color: 'var(--text-4)' }}>Review only — no endpoint records are changed from this screen.</p>
                      </article>
                    ))}
                    {duplicatesQuery.isLoading && <div className="flex justify-center py-14"><RefreshCw size={18} className="animate-spin" style={{ color: 'var(--accent)' }} /></div>}
                    {!duplicatesQuery.isLoading && !duplicatesQuery.data?.items.length && <div className="px-5 py-16 text-center"><ShieldCheck className="mx-auto" size={24} style={{ color: 'var(--accent)' }} /><p className="mt-3 text-[12px] font-semibold" style={{ color: 'var(--text-2)' }}>No duplicate candidates detected</p></div>}
                  </div>
                )}
              </section>

              <aside className="space-y-5">
                <section className="ui-command-surface overflow-hidden">
                  <div className="border-b px-4 py-3.5" style={{ borderColor: 'var(--border)' }}><p className="ui-eyebrow">Source freshness</p></div>
                  <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {enabledSources.map(source => {
                      const stale = source.age_hours == null || source.age_hours > 24 || source.status === 'error'
                      return <div key={source.integration_type} className="flex items-center gap-3 px-4 py-3.5"><span className="h-2 w-2 rounded-full" style={{ background: stale ? '#f87171' : '#34d399' }} /><div className="min-w-0 flex-1"><p className="truncate text-[11px] font-semibold" style={{ color: 'var(--text-2)' }}>{source.display_name}</p><p className="mt-0.5 text-[9px]" style={{ color: 'var(--text-4)' }}>{relativeDate(source.last_sync)}{source.records_synced ? ` · ${source.records_synced} records` : ''}</p></div><Database size={12} style={{ color: 'var(--text-4)' }} /></div>
                    })}
                    {!enabledSources.length && <p className="px-4 py-6 text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>No enabled integration sources were found.</p>}
                  </div>
                </section>

                <section className="ui-command-surface p-4">
                  <p className="ui-eyebrow">Confidence model</p>
                  <div className="mt-4 space-y-3">
                    {[['Hardware serial', '+35', Fingerprint], ['Directory identity', '+20', UserX], ['Cross-source evidence', '+15', GitMerge], ['Fresh observation', '+10', RefreshCw]].map(([label, weight, Icon]) => (
                      <div key={String(label)} className="flex items-center gap-3"><div className="flex h-7 w-7 items-center justify-center rounded-md" style={{ background: 'var(--surface-inset)' }}><Icon size={12} style={{ color: 'var(--text-3)' }} /></div><span className="flex-1 text-[10px]" style={{ color: 'var(--text-3)' }}>{label as string}</span><span className="font-mono text-[10px]" style={{ color: 'var(--accent)' }}>{weight as string}</span></div>
                    ))}
                  </div>
                  <p className="mt-4 border-t pt-4 text-[10px] leading-4" style={{ borderColor: 'var(--border)', color: 'var(--text-4)' }}>Every score is recomputed from visible evidence. Lifecycle exclusions do not inflate compliance coverage.</p>
                </section>

                <section className="rounded-xl border p-4" style={{ borderColor: 'rgba(251,191,36,0.18)', background: 'rgba(251,191,36,0.055)' }}>
                  <div className="flex items-start gap-3"><Archive size={15} className="mt-0.5 text-amber-400" /><div><p className="text-[11px] font-semibold text-amber-300">Safe by design</p><p className="mt-1 text-[10px] leading-4" style={{ color: 'var(--text-3)' }}>Duplicate detection is advisory. Lifecycle changes require analyst access and are fully audited.</p></div></div>
                </section>
              </aside>
            </div>
          </>
        )}
      </div>
      {selected && <LifecycleDialog endpoint={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
