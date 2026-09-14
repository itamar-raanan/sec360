import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowDownAZ,
  ArrowUpAZ,
  Bookmark,
  Braces,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Database,
  Download,
  Filter,
  RefreshCw,
  Save,
  Search,
  Server,
  SlidersHorizontal,
  Star,
  Tags,
  Trash2,
  X,
} from 'lucide-react'

import {
  createPuppetFactFavorite,
  createPuppetFactSavedView,
  deletePuppetFactFavorite,
  deletePuppetFactSavedView,
  exportPuppetFacts,
  fetchPuppetFactFacets,
  fetchPuppetFactFavorites,
  fetchPuppetFacts,
  fetchPuppetFactSavedViews,
  fetchPuppetFactSummary,
  updatePuppetFactSavedView,
  type PuppetFact,
  type PuppetFactParams,
  type PuppetFactSavedView,
  type PuppetFactSort,
  type PuppetFactValueType,
  type PuppetFactViewDefinition,
  type SortOrder,
} from '../api/puppetFacts'

const VALUE_TYPES: PuppetFactValueType[] = ['string', 'number', 'boolean', 'array', 'object', 'null']
const DEFAULT_VIEW: PuppetFactViewDefinition = {
  search: '', certname: '', names: [], environment: '', value_types: [],
  favorites_only: false, page_size: 50, sort: 'certname', order: 'asc',
}

const TYPE_COLORS: Record<PuppetFactValueType, string> = {
  string: '#60a5fa', number: '#c084fc', boolean: '#34d399',
  object: '#fbbf24', array: '#fb923c', null: '#71717a',
}

function displayValue(value: unknown, expanded = false) {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'string') return value
  return JSON.stringify(value, null, expanded ? 2 : 0) ?? String(value)
}

function formatTimestamp(value: string | null) {
  if (!value) return 'Never'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : 'The request could not be completed.'
}

function FactRow({ fact, favorite, onToggleFavorite }: {
  fact: PuppetFact
  favorite: boolean
  onToggleFavorite: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const structured = fact.value_type === 'object' || fact.value_type === 'array'
  return (
    <div className="grid w-full grid-cols-[34px_minmax(170px,1fr)_minmax(180px,1fr)_minmax(260px,2fr)_110px_28px] items-start gap-4 px-5 py-3 transition-colors hover:bg-white/[0.025]">
      <button
        type="button"
        onClick={onToggleFavorite}
        aria-label={favorite ? `Remove ${fact.name} from favourites` : `Add ${fact.name} to favourites`}
        className="focus-accent mt-0.5 rounded-md p-1.5 transition-colors hover:bg-amber-400/10"
        style={{ color: favorite ? '#fbbf24' : 'var(--text-4)' }}
      >
        <Star size={15} fill={favorite ? 'currentColor' : 'none'} />
      </button>
      <div className="min-w-0">
        <div className="truncate font-mono text-[12px] font-medium" style={{ color: 'var(--text-1)' }}>{fact.certname}</div>
        <div className="mt-1 truncate text-[10px]" style={{ color: 'var(--text-4)' }}>{fact.environment || 'No environment'}</div>
      </div>
      <div className="min-w-0">
        <div className="truncate font-mono text-[12px]" style={{ color: 'var(--text-2)' }}>{fact.name}</div>
        <span className="mt-1 inline-flex rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide" style={{ color: TYPE_COLORS[fact.value_type], borderColor: `${TYPE_COLORS[fact.value_type]}40`, background: `${TYPE_COLORS[fact.value_type]}12` }}>
          {fact.value_type}
        </span>
      </div>
      <button type="button" onClick={() => structured && setExpanded(value => !value)} className="min-w-0 text-left" aria-expanded={expanded}>
        <pre className={`whitespace-pre-wrap break-all font-mono text-[11px] leading-5 ${expanded ? '' : 'line-clamp-2'}`} style={{ color: 'var(--text-3)' }}>{displayValue(fact.value, expanded)}</pre>
      </button>
      <div className="text-[10px] leading-4" style={{ color: 'var(--text-4)' }}>{formatTimestamp(fact.synced_at)}</div>
      <button type="button" onClick={() => structured && setExpanded(value => !value)} disabled={!structured} aria-label={expanded ? 'Collapse value' : 'Expand value'} className="focus-accent rounded p-1 disabled:opacity-0" style={{ color: 'var(--text-4)' }}>
        <ChevronDown size={14} className={`transition-transform ${expanded ? 'rotate-180' : ''}`} />
      </button>
    </div>
  )
}

function SaveViewDialog({ view, definition, onClose, onSave, saving, error }: {
  view: PuppetFactSavedView | null
  definition: PuppetFactViewDefinition
  onClose: () => void
  onSave: (name: string, isDefault: boolean) => void
  saving: boolean
  error: string
}) {
  const [name, setName] = useState(view?.name ?? '')
  const [isDefault, setIsDefault] = useState(view?.is_default ?? false)
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm" onMouseDown={onClose}>
      <form onSubmit={event => { event.preventDefault(); if (name.trim()) onSave(name.trim(), isDefault) }} onMouseDown={event => event.stopPropagation()} className="w-full max-w-md rounded-xl border p-5 shadow-2xl" style={{ borderColor: 'var(--border-mid)', background: 'var(--surface-1)' }}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-base font-semibold" style={{ color: 'var(--text-1)' }}>{view ? 'Update saved view' : 'Save this view'}</h3>
            <p className="mt-1 text-xs leading-5" style={{ color: 'var(--text-4)' }}>Stores selected facts, every filter, sorting, and page size.</p>
          </div>
          <button type="button" onClick={onClose} className="focus-accent rounded-md p-1" style={{ color: 'var(--text-4)' }}><X size={16} /></button>
        </div>
        <label className="mt-5 block text-[11px] font-semibold uppercase tracking-[0.08em]" style={{ color: 'var(--text-3)' }}>
          View name
          <input autoFocus value={name} onChange={event => setName(event.target.value)} maxLength={120} placeholder="Production Linux overview" className="focus-accent mt-2 h-10 w-full rounded-lg border bg-[var(--surface-inset)] px-3 text-[12px] font-normal normal-case tracking-normal outline-none" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-1)' }} />
        </label>
        <label className="mt-4 flex cursor-pointer items-start gap-3 rounded-lg border p-3" style={{ borderColor: 'var(--border)' }}>
          <input type="checkbox" checked={isDefault} onChange={event => setIsDefault(event.target.checked)} className="mt-0.5 accent-amber-400" />
          <span><span className="block text-xs font-medium" style={{ color: 'var(--text-2)' }}>Open this view by default</span><span className="mt-0.5 block text-[11px]" style={{ color: 'var(--text-4)' }}>Only one Puppet Facts view can be the default.</span></span>
        </label>
        <div className="mt-3 rounded-lg border px-3 py-2 text-[11px]" style={{ borderColor: 'var(--border)', color: 'var(--text-4)', background: 'var(--surface-inset)' }}>
          {definition.names.length || 'All'} facts · {definition.value_types.length || 'All'} types · {definition.page_size} rows
        </div>
        {error && <p className="mt-3 text-xs text-red-400">{error}</p>}
        <div className="mt-5 flex justify-end gap-2">
          <button type="button" onClick={onClose} className="focus-accent h-9 rounded-lg border px-4 text-xs" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-3)' }}>Cancel</button>
          <button type="submit" disabled={!name.trim() || saving} className="focus-accent inline-flex h-9 items-center gap-2 rounded-lg bg-amber-400 px-4 text-xs font-semibold text-black disabled:opacity-50"><Save size={14} /> {saving ? 'Saving…' : view ? 'Update view' : 'Save view'}</button>
        </div>
      </form>
    </div>
  )
}

export default function PuppetFacts() {
  const queryClient = useQueryClient()
  const initializedDefault = useRef(false)
  const [input, setInput] = useState('')
  const [search, setSearch] = useState('')
  const [certname, setCertname] = useState('')
  const [selectedFacts, setSelectedFacts] = useState<string[]>([])
  const [environment, setEnvironment] = useState('')
  const [valueTypes, setValueTypes] = useState<PuppetFactValueType[]>([])
  const [favoritesOnly, setFavoritesOnly] = useState(false)
  const [pageSize, setPageSize] = useState<25 | 50 | 100>(50)
  const [sort, setSort] = useState<PuppetFactSort>('certname')
  const [order, setOrder] = useState<SortOrder>('asc')
  const [page, setPage] = useState(1)
  const [exporting, setExporting] = useState(false)
  const [pickerOpen, setPickerOpen] = useState(false)
  const [pickerSearch, setPickerSearch] = useState('')
  const [activeViewId, setActiveViewId] = useState('')
  const [saveDialogOpen, setSaveDialogOpen] = useState(false)
  const [saveError, setSaveError] = useState('')

  useEffect(() => {
    const timeout = window.setTimeout(() => setSearch(input.trim()), 250)
    return () => window.clearTimeout(timeout)
  }, [input])

  useEffect(() => setPage(1), [search, certname, selectedFacts, environment, valueTypes, favoritesOnly, pageSize, sort, order])

  const definition = useMemo<PuppetFactViewDefinition>(() => ({
    search, certname, names: selectedFacts, environment, value_types: valueTypes,
    favorites_only: favoritesOnly, page_size: pageSize, sort, order,
  }), [search, certname, selectedFacts, environment, valueTypes, favoritesOnly, pageSize, sort, order])

  const params = useMemo<PuppetFactParams>(() => ({
    search: search || undefined,
    certname: certname || undefined,
    names: selectedFacts.length ? selectedFacts.join(',') : undefined,
    environment: environment || undefined,
    value_types: valueTypes.length ? valueTypes.join(',') : undefined,
    favorites_only: favoritesOnly || undefined,
    sort,
    order,
  }), [search, certname, selectedFacts, environment, valueTypes, favoritesOnly, sort, order])

  const summary = useQuery({ queryKey: ['puppet-facts-summary', params], queryFn: () => fetchPuppetFactSummary(params) })
  const facets = useQuery({ queryKey: ['puppet-facts-facets'], queryFn: fetchPuppetFactFacets })
  const favorites = useQuery({ queryKey: ['puppet-facts-favorites'], queryFn: fetchPuppetFactFavorites })
  const savedViews = useQuery({ queryKey: ['puppet-facts-saved-views'], queryFn: fetchPuppetFactSavedViews })
  const facts = useQuery({
    queryKey: ['puppet-facts', params, page, pageSize],
    queryFn: () => fetchPuppetFacts({ ...params, limit: pageSize, offset: (page - 1) * pageSize }),
  })

  const favoriteByName = useMemo(() => new Map((favorites.data ?? []).map(item => [item.fact_name, item])), [favorites.data])
  const activeView = (savedViews.data ?? []).find(view => view.id === activeViewId) ?? null
  const isModified = activeView ? JSON.stringify(definition) !== JSON.stringify(activeView.definition) : false
  const visiblePickerFacts = useMemo(() => {
    const term = pickerSearch.trim().toLowerCase()
    return (facets.data?.names ?? []).filter(name => !term || name.toLowerCase().includes(term))
  }, [facets.data?.names, pickerSearch])
  const total = facts.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const filterCount = Number(Boolean(search)) + Number(Boolean(certname)) + selectedFacts.length + Number(Boolean(environment)) + valueTypes.length + Number(favoritesOnly)

  const applyDefinition = useCallback((next: PuppetFactViewDefinition) => {
    setInput(next.search); setSearch(next.search); setCertname(next.certname)
    setSelectedFacts(next.names); setEnvironment(next.environment); setValueTypes(next.value_types)
    setFavoritesOnly(next.favorites_only); setPageSize(next.page_size); setSort(next.sort); setOrder(next.order); setPage(1)
  }, [])

  useEffect(() => {
    if (initializedDefault.current || !savedViews.data) return
    initializedDefault.current = true
    const defaultView = savedViews.data.find(view => view.is_default)
    if (defaultView) { setActiveViewId(defaultView.id); applyDefinition(defaultView.definition) }
  }, [applyDefinition, savedViews.data])

  const favoriteMutation = useMutation({
    mutationFn: async (factName: string) => {
      const existing = favoriteByName.get(factName)
      return existing ? deletePuppetFactFavorite(existing.id) : createPuppetFactFavorite(factName)
    },
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['puppet-facts-favorites'] }); if (favoritesOnly) { void queryClient.invalidateQueries({ queryKey: ['puppet-facts'] }); void queryClient.invalidateQueries({ queryKey: ['puppet-facts-summary'] }) } },
  })

  const saveMutation = useMutation({
    mutationFn: ({ name, isDefault }: { name: string; isDefault: boolean }) => activeView
      ? updatePuppetFactSavedView(activeView.id, { name, definition, is_default: isDefault })
      : createPuppetFactSavedView({ name, definition, is_default: isDefault }),
    onSuccess: view => { setSaveDialogOpen(false); setSaveError(''); setActiveViewId(view.id); void queryClient.invalidateQueries({ queryKey: ['puppet-facts-saved-views'] }) },
    onError: error => setSaveError(errorMessage(error)),
  })

  const deleteViewMutation = useMutation({
    mutationFn: deletePuppetFactSavedView,
    onSuccess: () => { setActiveViewId(''); void queryClient.invalidateQueries({ queryKey: ['puppet-facts-saved-views'] }) },
  })

  const clearFilters = () => { applyDefinition(DEFAULT_VIEW); setActiveViewId('') }
  const refresh = () => { void Promise.all([summary.refetch(), facets.refetch(), favorites.refetch(), savedViews.refetch(), facts.refetch()]) }
  const runExport = async () => { setExporting(true); try { await exportPuppetFacts(params) } finally { setExporting(false) } }

  return (
    <div className="h-full overflow-y-auto">
      {saveDialogOpen && <SaveViewDialog view={activeView} definition={definition} onClose={() => { setSaveDialogOpen(false); setSaveError('') }} onSave={(name, isDefault) => saveMutation.mutate({ name, isDefault })} saving={saveMutation.isPending} error={saveError} />}
      <div className="mx-auto max-w-[1700px] px-4 py-5 sm:px-6 lg:px-8">
        <section className="mb-5 flex flex-col gap-4 border-b pb-5 lg:flex-row lg:items-end lg:justify-between" style={{ borderColor: 'var(--border)' }}>
          <div>
            <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.12em] text-amber-400"><Database size={14} /> PuppetDB inventory</div>
            <h2 className="text-[22px] font-semibold tracking-[-0.035em] sm:text-[26px]" style={{ color: 'var(--text-1)' }}>Puppet Facts</h2>
            <p className="mt-2 max-w-2xl text-[13px] leading-5" style={{ color: 'var(--text-3)' }}>Build reusable fact dashboards across managed nodes, then save the exact facts and filters your team uses.</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={refresh} className="focus-accent pressable inline-flex h-9 items-center gap-2 rounded-lg border px-3 text-[12px]" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-2)', background: 'var(--surface-2)' }}><RefreshCw size={14} className={facts.isFetching ? 'animate-spin' : ''} /> Refresh</button>
            <button type="button" onClick={runExport} disabled={exporting} className="focus-accent pressable inline-flex h-9 items-center gap-2 rounded-lg bg-amber-400 px-3 text-[12px] font-semibold text-black disabled:opacity-60"><Download size={14} /> {exporting ? 'Exporting…' : 'Export CSV'}</button>
          </div>
        </section>

        <section className="mb-4 flex flex-col gap-3 rounded-xl border p-3 sm:flex-row sm:items-center" style={{ borderColor: 'var(--border)', background: 'var(--surface-1)' }}>
          <div className="flex min-w-0 flex-1 items-center gap-2">
            <Bookmark size={15} className="shrink-0 text-amber-400" />
            <select value={activeViewId} onChange={event => { const id = event.target.value; setActiveViewId(id); const view = (savedViews.data ?? []).find(item => item.id === id); if (view) applyDefinition(view.definition) }} className="focus-accent h-9 min-w-0 flex-1 rounded-lg border bg-[var(--surface-inset)] px-3 text-xs" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-2)' }}>
              <option value="">Unsaved view</option>
              {(savedViews.data ?? []).map(view => <option key={view.id} value={view.id}>{view.name}{view.is_default ? ' — Default' : ''}</option>)}
            </select>
            {isModified && <span className="hidden text-[10px] uppercase tracking-wide text-amber-400 sm:inline">Modified</span>}
          </div>
          <div className="flex items-center gap-2">
            <button type="button" onClick={() => { setSaveError(''); setSaveDialogOpen(true) }} className="focus-accent inline-flex h-9 items-center gap-2 rounded-lg border px-3 text-xs" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-2)' }}><Save size={14} /> {activeView ? 'Update view' : 'Save view'}</button>
            {activeView && <button type="button" onClick={() => { if (window.confirm(`Delete saved view “${activeView.name}”?`)) deleteViewMutation.mutate(activeView.id) }} disabled={deleteViewMutation.isPending} aria-label="Delete saved view" className="focus-accent h-9 rounded-lg border px-2.5 text-red-400" style={{ borderColor: 'var(--border-mid)' }}><Trash2 size={14} /></button>}
          </div>
        </section>

        <section className="mb-4 grid gap-px overflow-hidden rounded-xl border sm:grid-cols-2 xl:grid-cols-4" style={{ borderColor: 'var(--border)', background: 'var(--border)' }}>
          {[
            { label: 'Matching facts', value: summary.data?.facts ?? 0, icon: Braces },
            { label: 'Matching nodes', value: summary.data?.nodes ?? 0, icon: Server },
            { label: 'Fact names in view', value: summary.data?.fact_names ?? 0, icon: Tags },
            { label: 'Latest synchronized', value: formatTimestamp(summary.data?.last_sync ?? null), icon: RefreshCw, text: true },
          ].map(item => { const Icon = item.icon; return <div key={item.label} className="bg-[var(--surface-1)] px-4 py-4"><div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.1em]" style={{ color: 'var(--text-4)' }}><Icon size={13} /> {item.label}</div><div className={`mt-2 font-semibold ${item.text ? 'text-[13px]' : 'text-[24px]'}`} style={{ color: 'var(--text-1)' }}>{typeof item.value === 'number' ? item.value.toLocaleString() : item.value}</div></div> })}
        </section>

        <section className="overflow-hidden rounded-xl border" style={{ borderColor: 'var(--border)', background: 'var(--surface-1)' }}>
          <div className="border-b p-4" style={{ borderColor: 'var(--border)' }}>
            <div className="mb-3 flex items-center justify-between"><div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.09em]" style={{ color: 'var(--text-3)' }}><SlidersHorizontal size={14} /> Filters {filterCount > 0 && <span className="rounded-full bg-amber-400 px-1.5 py-0.5 text-[9px] text-black">{filterCount}</span>}</div>{filterCount > 0 && <button type="button" onClick={clearFilters} className="text-[11px] font-medium text-amber-400">Clear all</button>}</div>
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-[minmax(240px,1.4fr)_minmax(170px,1fr)_minmax(190px,1fr)_170px]">
              <label className="relative min-w-0"><Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-4)' }} /><input value={input} onChange={event => setInput(event.target.value)} placeholder="Search fact name or value…" className="focus-accent h-10 w-full rounded-lg border bg-[var(--surface-inset)] pl-9 pr-9 text-[12px] outline-none" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-1)' }} />{input && <button type="button" onClick={() => setInput('')} className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-4)' }}><X size={14} /></button>}</label>
              <input value={certname} onChange={event => setCertname(event.target.value)} placeholder="Filter by node…" className="focus-accent h-10 min-w-0 rounded-lg border bg-[var(--surface-inset)] px-3 text-[12px] outline-none" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-1)' }} />
              <div className="relative">
                <button type="button" onClick={() => setPickerOpen(value => !value)} className="focus-accent flex h-10 w-full items-center justify-between rounded-lg border bg-[var(--surface-inset)] px-3 text-left text-[12px]" style={{ borderColor: pickerOpen ? '#fbbf24' : 'var(--border-mid)', color: 'var(--text-2)' }}><span className="truncate">{selectedFacts.length ? `${selectedFacts.length} facts selected` : 'Choose facts'}</span><ChevronDown size={14} /></button>
                {pickerOpen && <div className="absolute left-0 top-12 z-30 w-full min-w-[300px] overflow-hidden rounded-xl border shadow-2xl" style={{ borderColor: 'var(--border-mid)', background: 'var(--surface-1)' }}>
                  <div className="border-b p-3" style={{ borderColor: 'var(--border)' }}><div className="relative"><Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--text-4)' }} /><input autoFocus value={pickerSearch} onChange={event => setPickerSearch(event.target.value)} placeholder="Find a fact…" className="focus-accent h-9 w-full rounded-lg border bg-[var(--surface-inset)] pl-8 pr-3 text-xs outline-none" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-1)' }} /></div></div>
                  <div className="flex items-center justify-between border-b px-3 py-2 text-[10px]" style={{ borderColor: 'var(--border)', color: 'var(--text-4)' }}><span>{visiblePickerFacts.length.toLocaleString()} fact names</span><button type="button" onClick={() => setSelectedFacts([])} className="text-amber-400">Clear selection</button></div>
                  <div className="max-h-72 overflow-y-auto">{visiblePickerFacts.map(name => { const selected = selectedFacts.includes(name); const favorite = favoriteByName.has(name); return <div key={name} className="flex items-center gap-1 px-2 py-0.5 hover:bg-white/[0.03]"><button type="button" onClick={() => setSelectedFacts(current => selected ? current.filter(item => item !== name) : [...current, name])} className="flex min-w-0 flex-1 items-center gap-2 rounded px-1 py-2 text-left"><span className={`flex h-4 w-4 shrink-0 items-center justify-center rounded border ${selected ? 'border-amber-400 bg-amber-400 text-black' : ''}`} style={selected ? undefined : { borderColor: 'var(--border-mid)' }}>{selected && <Check size={11} />}</span><span className="truncate font-mono text-[11px]" style={{ color: 'var(--text-2)' }}>{name}</span></button><button type="button" onClick={() => favoriteMutation.mutate(name)} aria-label={favorite ? `Remove ${name} from favourites` : `Add ${name} to favourites`} className="rounded p-2" style={{ color: favorite ? '#fbbf24' : 'var(--text-4)' }}><Star size={13} fill={favorite ? 'currentColor' : 'none'} /></button></div> })}{visiblePickerFacts.length === 0 && <div className="px-4 py-8 text-center text-xs" style={{ color: 'var(--text-4)' }}>No fact names match.</div>}</div>
                  <div className="border-t p-2 text-right" style={{ borderColor: 'var(--border)' }}><button type="button" onClick={() => setPickerOpen(false)} className="rounded-md bg-amber-400 px-3 py-1.5 text-[11px] font-semibold text-black">Done</button></div>
                </div>}
              </div>
              <select value={environment} onChange={event => setEnvironment(event.target.value)} className="focus-accent h-10 min-w-0 rounded-lg border bg-[var(--surface-inset)] px-3 text-[12px]" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-2)' }}><option value="">All environments</option>{(facets.data?.environments ?? []).map(value => <option key={value} value={value}>{value}</option>)}</select>
            </div>

            <div className="mt-3 flex flex-col gap-3 border-t pt-3 xl:flex-row xl:items-center xl:justify-between" style={{ borderColor: 'var(--border)' }}>
              <div className="flex flex-wrap items-center gap-1.5"><span className="mr-1 text-[10px] font-semibold uppercase tracking-wide" style={{ color: 'var(--text-4)' }}>Value type</span>{VALUE_TYPES.map(type => { const active = valueTypes.includes(type); return <button key={type} type="button" onClick={() => setValueTypes(current => active ? current.filter(item => item !== type) : [...current, type])} className="focus-accent rounded-md border px-2 py-1 text-[10px] font-medium capitalize" style={{ borderColor: active ? `${TYPE_COLORS[type]}80` : 'var(--border-mid)', color: active ? TYPE_COLORS[type] : 'var(--text-4)', background: active ? `${TYPE_COLORS[type]}12` : 'transparent' }}>{type}</button> })}<button type="button" onClick={() => setFavoritesOnly(value => !value)} className="focus-accent ml-1 inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[10px] font-medium" style={{ borderColor: favoritesOnly ? '#fbbf2480' : 'var(--border-mid)', color: favoritesOnly ? '#fbbf24' : 'var(--text-4)', background: favoritesOnly ? '#fbbf2412' : 'transparent' }}><Star size={11} fill={favoritesOnly ? 'currentColor' : 'none'} /> Favourites only</button></div>
              <div className="flex flex-wrap items-center gap-2">
                <label className="flex items-center gap-2 text-[10px]" style={{ color: 'var(--text-4)' }}>Sort<select value={sort} onChange={event => setSort(event.target.value as PuppetFactSort)} className="focus-accent h-8 rounded-md border bg-[var(--surface-inset)] px-2 text-[11px]" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-2)' }}><option value="certname">Node</option><option value="name">Fact name</option><option value="value_type">Value type</option><option value="environment">Environment</option><option value="synced_at">Synced time</option></select></label>
                <button type="button" onClick={() => setOrder(value => value === 'asc' ? 'desc' : 'asc')} aria-label={`Sort ${order === 'asc' ? 'descending' : 'ascending'}`} className="focus-accent h-8 rounded-md border px-2" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-3)' }}>{order === 'asc' ? <ArrowDownAZ size={14} /> : <ArrowUpAZ size={14} />}</button>
                <label className="flex items-center gap-2 text-[10px]" style={{ color: 'var(--text-4)' }}>Rows<select value={pageSize} onChange={event => setPageSize(Number(event.target.value) as 25 | 50 | 100)} className="focus-accent h-8 rounded-md border bg-[var(--surface-inset)] px-2 text-[11px]" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-2)' }}><option value={25}>25</option><option value={50}>50</option><option value={100}>100</option></select></label>
              </div>
            </div>
            {selectedFacts.length > 0 && <div className="mt-3 flex flex-wrap gap-1.5">{selectedFacts.map(name => <button key={name} type="button" onClick={() => setSelectedFacts(current => current.filter(item => item !== name))} className="inline-flex max-w-[260px] items-center gap-1 rounded-md border px-2 py-1 font-mono text-[10px]" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-3)', background: 'var(--surface-inset)' }}><span className="truncate">{name}</span><X size={10} /></button>)}</div>}
          </div>

          <div className="overflow-x-auto"><div className="min-w-[960px]">
            <div className="grid grid-cols-[34px_minmax(170px,1fr)_minmax(180px,1fr)_minmax(260px,2fr)_110px_28px] gap-4 border-b px-5 py-2 text-[9px] font-semibold uppercase tracking-[0.1em]" style={{ borderColor: 'var(--border)', color: 'var(--text-4)', background: 'var(--table-header)' }}><Star size={11} /><span>Node</span><span>Fact</span><span>Value</span><span>Synced</span><span /></div>
            <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {facts.isLoading && Array.from({ length: 8 }, (_, index) => <div key={index} className="shimmer mx-5 my-3 h-12 rounded-lg" />)}
              {facts.isError && <div className="px-6 py-12 text-center text-sm text-red-400">Puppet facts could not be loaded. Check the integration status and try again.</div>}
              {!facts.isLoading && !facts.isError && facts.data?.items.map(fact => <FactRow key={fact.id} fact={fact} favorite={favoriteByName.has(fact.name)} onToggleFavorite={() => favoriteMutation.mutate(fact.name)} />)}
              {!facts.isLoading && !facts.isError && total === 0 && <div className="px-6 py-16 text-center"><Filter size={28} className="mx-auto text-zinc-600" /><p className="mt-3 text-sm font-medium" style={{ color: 'var(--text-2)' }}>{filterCount ? 'No facts match this view' : 'No Puppet facts synchronized yet'}</p><p className="mt-1 text-xs" style={{ color: 'var(--text-4)' }}>{filterCount ? 'Remove a filter or select additional fact names.' : 'Run Sync Now from the Puppet integration.'}</p>{filterCount > 0 && <button type="button" onClick={clearFilters} className="mt-4 rounded-lg border px-3 py-2 text-xs text-amber-400" style={{ borderColor: 'var(--border-mid)' }}>Clear filters</button>}</div>}
            </div>
          </div></div>

          <div className="flex flex-col gap-3 border-t px-4 py-3 sm:flex-row sm:items-center sm:justify-between" style={{ borderColor: 'var(--border)' }}><span className="text-[11px]" style={{ color: 'var(--text-4)' }}>{total.toLocaleString()} matching facts · Page {page} of {totalPages}</span><div className="flex gap-1.5"><button type="button" disabled={page === 1} onClick={() => setPage(value => value - 1)} className="rounded-lg border p-2 disabled:opacity-30" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-3)' }}><ChevronLeft size={14} /></button><button type="button" disabled={page >= totalPages} onClick={() => setPage(value => value + 1)} className="rounded-lg border p-2 disabled:opacity-30" style={{ borderColor: 'var(--border-mid)', color: 'var(--text-3)' }}><ChevronRight size={14} /></button></div></div>
        </section>
      </div>
    </div>
  )
}
