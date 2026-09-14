import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Braces,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Database,
  Download,
  RefreshCw,
  Search,
  Server,
  Tags,
  X,
} from 'lucide-react'

import {
  exportPuppetFacts,
  fetchPuppetFactFacets,
  fetchPuppetFacts,
  fetchPuppetFactSummary,
  type PuppetFact,
} from '../api/puppetFacts'

const PAGE_SIZE = 50

function displayValue(value: unknown, expanded = false) {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'string') return value
  const rendered = JSON.stringify(value, null, expanded ? 2 : 0)
  return rendered ?? String(value)
}

function formatTimestamp(value: string | null) {
  if (!value) return 'Never'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

const TYPE_COLORS: Record<string, string> = {
  string: '#60a5fa',
  number: '#c084fc',
  boolean: '#34d399',
  object: '#fbbf24',
  array: '#fb923c',
  null: '#71717a',
}

function FactRow({ fact }: { fact: PuppetFact }) {
  const [expanded, setExpanded] = useState(false)
  const structured = fact.value_type === 'object' || fact.value_type === 'array'
  return (
    <button
      type="button"
      onClick={() => structured && setExpanded(value => !value)}
      className="grid w-full grid-cols-[minmax(170px,1fr)_minmax(180px,1fr)_minmax(260px,2fr)_110px_32px] items-start gap-4 px-5 py-3 text-left transition-colors hover:bg-white/[0.025]"
    >
      <div className="min-w-0">
        <div className="truncate font-mono text-[12px] font-medium" style={{ color: 'var(--text-1)' }}>{fact.certname}</div>
        <div className="mt-1 truncate text-[10px]" style={{ color: 'var(--text-4)' }}>{fact.environment || 'No environment'}</div>
      </div>
      <div className="min-w-0">
        <div className="truncate font-mono text-[12px]" style={{ color: 'var(--text-2)' }}>{fact.name}</div>
        <span
          className="mt-1 inline-flex rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide"
          style={{ color: TYPE_COLORS[fact.value_type], borderColor: `${TYPE_COLORS[fact.value_type]}40`, background: `${TYPE_COLORS[fact.value_type]}12` }}
        >
          {fact.value_type}
        </span>
      </div>
      <pre className={`min-w-0 whitespace-pre-wrap break-all font-mono text-[11px] leading-5 ${expanded ? '' : 'line-clamp-2'}`} style={{ color: 'var(--text-3)' }}>
        {displayValue(fact.value, expanded)}
      </pre>
      <div className="text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>{formatTimestamp(fact.synced_at)}</div>
      <div className="pt-1" style={{ color: structured ? 'var(--text-4)' : 'transparent' }}>
        <ChevronDown size={14} className={`transition-transform ${expanded ? 'rotate-180' : ''}`} />
      </div>
    </button>
  )
}

export default function PuppetFacts() {
  const [input, setInput] = useState('')
  const [search, setSearch] = useState('')
  const [factName, setFactName] = useState('')
  const [environment, setEnvironment] = useState('')
  const [page, setPage] = useState(1)
  const [exporting, setExporting] = useState(false)

  useEffect(() => {
    const timeout = window.setTimeout(() => setSearch(input.trim()), 250)
    return () => window.clearTimeout(timeout)
  }, [input])

  useEffect(() => setPage(1), [search, factName, environment])

  const params = useMemo(() => ({
    search: search || undefined,
    name: factName || undefined,
    environment: environment || undefined,
  }), [search, factName, environment])

  const summary = useQuery({
    queryKey: ['puppet-facts-summary'],
    queryFn: fetchPuppetFactSummary,
  })
  const facets = useQuery({
    queryKey: ['puppet-facts-facets'],
    queryFn: fetchPuppetFactFacets,
  })
  const facts = useQuery({
    queryKey: ['puppet-facts', params, page],
    queryFn: () => fetchPuppetFacts({ ...params, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }),
  })

  const total = facts.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const hasFilters = Boolean(input || factName || environment)

  const refresh = () => {
    void Promise.all([summary.refetch(), facets.refetch(), facts.refetch()])
  }

  const runExport = async () => {
    setExporting(true)
    try {
      await exportPuppetFacts(params)
    } finally {
      setExporting(false)
    }
  }

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-[1700px] px-4 py-5 sm:px-6 lg:px-8">
        <section className="mb-5 flex flex-col gap-4 border-b pb-5 lg:flex-row lg:items-end lg:justify-between" style={{ borderColor: 'var(--border)' }}>
          <div>
            <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-amber-400">
              <Database size={14} /> PuppetDB inventory
            </div>
            <h2 className="text-[22px] font-semibold tracking-[-0.035em] sm:text-[26px]" style={{ color: 'var(--text-1)' }}>Puppet Facts</h2>
            <p className="mt-2 max-w-2xl text-[13px] leading-5" style={{ color: 'var(--text-3)' }}>
              Search every synchronized Puppet fact across managed nodes, including structured objects and custom facts.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button type="button" onClick={refresh} className="focus-accent pressable inline-flex h-9 items-center gap-2 rounded-lg border px-3 text-[12px]" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-2)', background: 'var(--surface-2)' }}>
              <RefreshCw size={14} className={facts.isFetching ? 'animate-spin' : ''} /> Refresh
            </button>
            <button type="button" onClick={runExport} disabled={exporting} className="focus-accent pressable inline-flex h-9 items-center gap-2 rounded-lg bg-amber-400 px-3 text-[12px] font-semibold text-black disabled:opacity-60">
              <Download size={14} /> {exporting ? 'Exporting…' : 'Export CSV'}
            </button>
          </div>
        </section>

        <section className="mb-4 grid gap-px overflow-hidden rounded-xl border sm:grid-cols-2 xl:grid-cols-4" style={{ borderColor: 'var(--border)', background: 'var(--border)' }}>
          {[
            { label: 'Facts', value: summary.data?.facts ?? 0, icon: Braces },
            { label: 'Managed nodes', value: summary.data?.nodes ?? 0, icon: Server },
            { label: 'Unique fact names', value: summary.data?.fact_names ?? 0, icon: Tags },
            { label: 'Last synchronized', value: formatTimestamp(summary.data?.last_sync ?? null), icon: RefreshCw, text: true },
          ].map(item => {
            const Icon = item.icon
            return (
              <div key={item.label} className="bg-[var(--surface-1)] px-4 py-4">
                <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--text-4)' }}><Icon size={13} /> {item.label}</div>
                <div className={`mt-2 font-semibold ${item.text ? 'text-[13px]' : 'text-[24px]'}`} style={{ color: 'var(--text-1)' }}>
                  {typeof item.value === 'number' ? item.value.toLocaleString() : item.value}
                </div>
              </div>
            )
          })}
        </section>

        <section className="overflow-hidden rounded-xl border" style={{ borderColor: 'var(--border)', background: 'var(--surface-1)' }}>
          <div className="flex flex-col gap-3 border-b p-4 lg:flex-row lg:items-center" style={{ borderColor: 'var(--border)' }}>
            <label className="relative min-w-0 flex-1">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-4)' }} />
              <input value={input} onChange={event => setInput(event.target.value)} placeholder="Search node, fact name, or value…" className="focus-accent h-10 w-full rounded-lg border bg-[var(--surface-inset)] pl-9 pr-9 text-[12px] outline-none" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-1)' }} />
              {input && <button type="button" onClick={() => setInput('')} className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-4)' }}><X size={14} /></button>}
            </label>
            <select value={factName} onChange={event => setFactName(event.target.value)} className="focus-accent h-10 max-w-[280px] rounded-lg border bg-[var(--surface-inset)] px-3 text-[12px]" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-2)' }}>
              <option value="">All fact names</option>
              {(facets.data?.names ?? []).map(name => <option key={name} value={name}>{name}</option>)}
            </select>
            <select value={environment} onChange={event => setEnvironment(event.target.value)} className="focus-accent h-10 rounded-lg border bg-[var(--surface-inset)] px-3 text-[12px]" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-2)' }}>
              <option value="">All environments</option>
              {(facets.data?.environments ?? []).map(value => <option key={value} value={value}>{value}</option>)}
            </select>
          </div>

          <div className="overflow-x-auto">
            <div className="min-w-[900px]">
              <div className="grid grid-cols-[minmax(170px,1fr)_minmax(180px,1fr)_minmax(260px,2fr)_110px_32px] gap-4 border-b px-5 py-2 text-[9px] font-semibold uppercase tracking-[0.1em]" style={{ borderColor: 'var(--border)', color: 'var(--text-4)', background: 'var(--table-header)' }}>
                <span>Node</span><span>Fact</span><span>Value</span><span>Synced</span><span />
              </div>

              <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {facts.isLoading && Array.from({ length: 8 }, (_, index) => <div key={index} className="shimmer mx-5 my-3 h-12 rounded-lg" />)}
                {facts.isError && (
                  <div className="px-6 py-12 text-center text-sm text-red-400">
                    Puppet facts could not be loaded. Check the integration status and try again.
                  </div>
                )}
                {!facts.isLoading && !facts.isError && facts.data?.items.map(fact => <FactRow key={fact.id} fact={fact} />)}
                {!facts.isLoading && !facts.isError && total === 0 && (
                  <div className="px-6 py-16 text-center">
                    <Braces size={28} className="mx-auto text-zinc-600" />
                    <p className="mt-3 text-sm font-medium" style={{ color: 'var(--text-2)' }}>{hasFilters ? 'No facts match these filters' : 'No Puppet facts synchronized yet'}</p>
                    <p className="mt-1 text-xs" style={{ color: 'var(--text-4)' }}>{hasFilters ? 'Try a broader query.' : 'Run Sync Now from the Puppet integration.'}</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between border-t px-4 py-3" style={{ borderColor: 'var(--border)' }}>
            <span className="text-[11px]" style={{ color: 'var(--text-4)' }}>{total.toLocaleString()} facts · Page {page} of {totalPages}</span>
            <div className="flex gap-1.5">
              <button type="button" disabled={page === 1} onClick={() => setPage(value => value - 1)} className="rounded-lg border p-2 disabled:opacity-30" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-3)' }}><ChevronLeft size={14} /></button>
              <button type="button" disabled={page >= totalPages} onClick={() => setPage(value => value + 1)} className="rounded-lg border p-2 disabled:opacity-30" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-3)' }}><ChevronRight size={14} /></button>
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}
