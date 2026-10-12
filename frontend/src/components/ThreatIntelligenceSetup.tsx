import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertCircle, Check, ChevronDown, ChevronRight, KeyRound, Loader2,
  Save, ShieldCheck, Trash2, XCircle,
} from 'lucide-react'
import {
  deleteIntegrationCredentials,
  fetchIntegrations,
  saveIntegrationCredentials,
  setIntegrationEnabled,
  testIntegration,
} from '../api/integrations'
import { useAuthStore } from '../store/auth'
import type { IntegrationConfig } from '../types'

type Field = {
  name: string
  label: string
  type: 'text' | 'password' | 'number'
  defaultValue?: string
  placeholder?: string
}

type ProviderDefinition = {
  type: string
  label: string
  description: string
  fields: Field[]
  help: string
  automated: boolean
}

const PROVIDERS: ProviderDefinition[] = [
  {
    type: 'virustotal',
    label: 'VirusTotal',
    description: 'URL and domain reputation',
    fields: [
      { name: 'api_key', label: 'API key', type: 'password', placeholder: 'VirusTotal API v3 key' },
      { name: 'timeout_seconds', label: 'Timeout (seconds)', type: 'number', defaultValue: '15' },
      { name: 'cache_ttl_minutes', label: 'Cache (minutes)', type: 'number', defaultValue: '60' },
      { name: 'rate_limit_per_minute', label: 'Requests per minute', type: 'number', defaultValue: '4' },
      { name: 'fresh_days', label: 'Freshness (days)', type: 'number', defaultValue: '30' },
    ],
    help: 'Queries disclose the indicator to VirusTotal and use your account quota.',
    automated: true,
  },
  {
    type: 'abuseipdb',
    label: 'AbuseIPDB',
    description: 'Resolved-IP reputation context',
    fields: [
      { name: 'api_key', label: 'API key', type: 'password', placeholder: 'AbuseIPDB API key' },
      { name: 'max_ips', label: 'Maximum IPs', type: 'number', defaultValue: '5' },
      { name: 'max_age_days', label: 'Lookback (days)', type: 'number', defaultValue: '90' },
      { name: 'timeout_seconds', label: 'Timeout (seconds)', type: 'number', defaultValue: '15' },
      { name: 'cache_ttl_minutes', label: 'Cache (minutes)', type: 'number', defaultValue: '60' },
      { name: 'rate_limit_per_minute', label: 'Requests per minute', type: 'number', defaultValue: '10' },
    ],
    help: 'Infrastructure context only; shared hosting addresses may serve unrelated domains.',
    automated: true,
  },
  {
    type: 'cloudflare_url_scanner',
    label: 'Cloudflare URL Scanner',
    description: 'Existing scans and explicit unlisted submissions',
    fields: [
      { name: 'account_id', label: 'Account ID', type: 'text' },
      { name: 'api_token', label: 'API token', type: 'password' },
      { name: 'timeout_seconds', label: 'Timeout (seconds)', type: 'number', defaultValue: '20' },
      { name: 'cache_ttl_minutes', label: 'Cache (minutes)', type: 'number', defaultValue: '60' },
      { name: 'rate_limit_per_minute', label: 'Requests per minute', type: 'number', defaultValue: '10' },
      { name: 'fresh_days', label: 'Freshness (days)', type: 'number', defaultValue: '30' },
    ],
    help: 'Requires URL Scanner Read; explicit scans also require URL Scanner Write.',
    automated: true,
  },
  {
    type: 'site_shot',
    label: 'Site-Shot',
    description: 'Explicit screenshot evidence',
    fields: [
      { name: 'api_key', label: 'API key', type: 'password', placeholder: 'Site-Shot user key' },
      { name: 'timeout_seconds', label: 'Timeout (seconds)', type: 'number', defaultValue: '30' },
      { name: 'rate_limit_per_minute', label: 'Requests per minute', type: 'number', defaultValue: '5' },
    ],
    help: 'Screenshot capture may consume paid quota and never contributes to the risk score.',
    automated: false,
  },
  {
    type: 'cisco_talos',
    label: 'Cisco Talos',
    description: 'Manual reputation lookup',
    fields: [],
    help: 'Manual link only. No supported generic Talos reputation API is assumed.',
    automated: false,
  },
]

function errorMessage(error: unknown): string {
  return (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail
    ?? (error as Error)?.message
    ?? 'The request failed.'
}

function statusLabel(config?: IntegrationConfig): { label: string; tone: string } {
  if (!config?.credentials_configured) return { label: 'Not configured', tone: 'text-zinc-500' }
  if (!config.is_enabled) return { label: 'Disabled', tone: 'text-zinc-500' }
  if (config.status === 'connected') return { label: 'Connected', tone: 'text-emerald-400' }
  if (config.status === 'error') return { label: 'Connection error', tone: 'text-red-400' }
  return { label: 'Saved · test required', tone: 'text-amber-300' }
}

function ProviderConfiguration({ definition, config }: { definition: ProviderDefinition; config?: IntegrationConfig }) {
  const queryClient = useQueryClient()
  const [values, setValues] = useState<Record<string, string>>({})
  const [feedback, setFeedback] = useState<{ success: boolean; message: string } | null>(null)

  useEffect(() => {
    setValues(Object.fromEntries(definition.fields.map(field => [field.name, field.defaultValue ?? ''])))
    setFeedback(null)
  }, [definition])

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['integrations'] })
  const save = useMutation({
    mutationFn: () => {
      const credentials: Record<string, unknown> = definition.type === 'cisco_talos' ? { mode: 'manual' } : {}
      definition.fields.forEach(field => {
        const value = values[field.name]?.trim()
        if (value) credentials[field.name] = field.type === 'number' ? Number(value) : value
      })
      return saveIntegrationCredentials(definition.type, credentials, true)
    },
    onSuccess: async () => {
      await refresh()
      setFeedback({ success: true, message: 'Saved and enabled. Test the connection before investigating.' })
    },
    onError: error => setFeedback({ success: false, message: errorMessage(error) }),
  })
  const test = useMutation({
    mutationFn: () => testIntegration(definition.type),
    onSuccess: async data => {
      await refresh()
      setFeedback(data)
    },
    onError: error => setFeedback({ success: false, message: errorMessage(error) }),
  })
  const toggle = useMutation({
    mutationFn: () => setIntegrationEnabled(definition.type, !config?.is_enabled),
    onSuccess: async () => {
      await refresh()
      setFeedback({ success: true, message: config?.is_enabled ? 'Provider disabled.' : 'Provider enabled.' })
    },
    onError: error => setFeedback({ success: false, message: errorMessage(error) }),
  })
  const remove = useMutation({
    mutationFn: () => deleteIntegrationCredentials(definition.type),
    onSuccess: async () => {
      await refresh()
      setFeedback({ success: true, message: 'Credentials removed.' })
    },
    onError: error => setFeedback({ success: false, message: errorMessage(error) }),
  })
  const pending = save.isPending || test.isPending || toggle.isPending || remove.isPending

  return <div className="space-y-4 border-t border-[var(--border)] px-4 py-4 sm:px-5">
    <div className="flex items-start gap-2 text-[11px] leading-5 text-zinc-500"><AlertCircle size={13} className="mt-1 shrink-0" />{definition.help}</div>
    {config?.credentials_configured && definition.fields.length > 0 && <p className="rounded-lg border border-amber-500/15 bg-amber-500/[0.06] px-3 py-2 text-[11px] text-amber-200/80">Credentials are stored securely and cannot be displayed. Enter all fields to replace them.</p>}
    {definition.fields.length > 0 && <div className="grid gap-3 sm:grid-cols-2">
      {definition.fields.map(field => <label key={field.name} className="space-y-1.5">
        <span className="block text-[10px] font-semibold uppercase tracking-[0.1em] text-zinc-500">{field.label}</span>
        <input
          type={field.type}
          value={values[field.name] ?? ''}
          onChange={event => setValues(current => ({ ...current, [field.name]: event.target.value }))}
          placeholder={field.placeholder}
          min={field.type === 'number' ? 0 : undefined}
          className="w-full rounded-lg border border-[var(--input-border)] bg-[var(--input-bg)] px-3 py-2 text-xs text-[var(--input-text)] outline-none"
        />
      </label>)}
    </div>}
    <div className="flex flex-wrap gap-2">
      <button onClick={() => save.mutate()} disabled={pending} className="pressable inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-3 py-2 text-xs font-semibold text-zinc-950 disabled:opacity-40"><Save size={13} />{definition.type === 'cisco_talos' ? 'Enable manual lookup' : 'Save & enable'}</button>
      {config?.credentials_configured && <button onClick={() => test.mutate()} disabled={pending} className="pressable inline-flex items-center gap-2 rounded-lg border border-white/[0.09] px-3 py-2 text-xs text-zinc-300 disabled:opacity-40"><ShieldCheck size={13} />Test</button>}
      {config?.credentials_configured && <button onClick={() => toggle.mutate()} disabled={pending} className="pressable inline-flex items-center gap-2 rounded-lg border border-white/[0.09] px-3 py-2 text-xs text-zinc-300 disabled:opacity-40">{config.is_enabled ? <XCircle size={13} /> : <Check size={13} />}{config.is_enabled ? 'Disable' : 'Enable'}</button>}
      {config?.credentials_configured && <button onClick={() => { if (window.confirm(`Remove saved ${definition.label} credentials?`)) remove.mutate() }} disabled={pending} className="pressable ml-auto inline-flex items-center gap-2 rounded-lg border border-red-500/20 px-3 py-2 text-xs text-red-400 disabled:opacity-40"><Trash2 size={13} />Remove</button>}
      {pending && <Loader2 size={14} className="my-auto animate-spin text-zinc-500" />}
    </div>
    {feedback && <div role="status" className={`rounded-lg border px-3 py-2 text-xs ${feedback.success ? 'border-emerald-500/20 bg-emerald-500/[0.07] text-emerald-300' : 'border-red-500/20 bg-red-500/[0.07] text-red-300'}`}>{feedback.message}</div>}
  </div>
}

export default function ThreatIntelligenceSetup() {
  const user = useAuthStore(state => state.user)
  const [open, setOpen] = useState(false)
  const [selected, setSelected] = useState<string | null>(null)
  const query = useQuery({ queryKey: ['integrations'], queryFn: fetchIntegrations })
  const configurations = useMemo(() => new Map(query.data?.map(item => [item.integration_type, item]) ?? []), [query.data])
  const automatedConnected = PROVIDERS.filter(item => item.automated && configurations.get(item.type)?.is_enabled && configurations.get(item.type)?.status === 'connected').length

  return <section className="overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface-1)]">
    <button type="button" onClick={() => setOpen(value => !value)} className="flex w-full items-center gap-3 px-4 py-3.5 text-left sm:px-5">
      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-emerald-500/20 bg-emerald-500/[0.07] text-emerald-400"><KeyRound size={15} /></span>
      <span className="min-w-0 flex-1"><span className="block text-sm font-semibold text-zinc-100">Intelligence providers</span><span className="mt-0.5 block text-[11px] text-zinc-500">{query.isLoading ? 'Loading configuration…' : `${automatedConnected} automated sources connected · Cisco Talos is manual`}</span></span>
      {open ? <ChevronDown size={15} className="text-zinc-500" /> : <ChevronRight size={15} className="text-zinc-500" />}
    </button>
    {open && <div className="border-t border-[var(--border)]">
      {query.isError && <div className="m-4 rounded-lg border border-red-500/20 bg-red-500/[0.07] p-3 text-xs text-red-300">Could not load integration status.</div>}
      {PROVIDERS.map(definition => {
        const config = configurations.get(definition.type)
        const status = statusLabel(config)
        const expanded = selected === definition.type
        return <div key={definition.type} className="border-b border-[var(--border)] last:border-b-0">
          <button type="button" onClick={() => user?.role === 'admin' && setSelected(expanded ? null : definition.type)} className={`flex w-full items-center gap-3 px-4 py-3 text-left sm:px-5 ${user?.role === 'admin' ? 'hover:bg-white/[0.02]' : ''}`}>
            <span className={`h-2 w-2 shrink-0 rounded-full ${config?.is_enabled && config.status === 'connected' ? 'bg-emerald-400' : config?.status === 'error' ? 'bg-red-400' : 'bg-zinc-700'}`} />
            <span className="min-w-0 flex-1"><span className="block text-xs font-semibold text-zinc-200">{definition.label}</span><span className="block truncate text-[10px] text-zinc-600">{definition.description}</span></span>
            <span className={`text-[10px] font-medium ${status.tone}`}>{status.label}</span>
            {user?.role === 'admin' && (expanded ? <ChevronDown size={13} className="text-zinc-600" /> : <ChevronRight size={13} className="text-zinc-600" />)}
          </button>
          {expanded && user?.role === 'admin' && <ProviderConfiguration definition={definition} config={config} />}
        </div>
      })}
      {user?.role !== 'admin' && <p className="border-t border-[var(--border)] px-5 py-3 text-[10px] text-zinc-600">An administrator manages provider credentials. Analysts can run investigations using connected sources.</p>}
    </div>}
  </section>
}
