import React, { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { LucideIcon } from 'lucide-react'
import {
  Server,
  Shield,
  Lock,
  GitBranch,
  Building2,
  Globe,
  Users,
  CheckCircle2,
  XCircle,
  Clock,
  Plug,
  Loader2,
  AlertCircle,
  LayoutGrid,
  KeyRound,
  ShieldCheck,
  Puzzle,
  RefreshCw,
  Trash2,
  X,
  Eye,
  EyeOff,
  Database,
  Plus,
  Settings2,
  Activity,
  Package,
  ChevronRight,
  Cloud,
} from 'lucide-react'
import {
  fetchIntegrations,
  saveIntegrationCredentials,
  testIntegration,
  syncIntegration,
  deleteIntegrationCredentials,
  createCustomIntegration,
  deleteIntegration,
} from '../api/integrations'
import type { IntegrationConfig } from '../types'

// ─── Types ───────────────────────────────────────────────────────────────────

type FieldDef = {
  name: string
  label: string
  type: 'text' | 'password' | 'number' | 'url' | 'email' | 'textarea' | 'select'
  placeholder?: string
  hint?: string
  required?: boolean
  options?: { value: string; label: string }[]
  defaultValue?: string
  group?: string
}

type CatalogEntry = {
  label: string
  category: string
  description: string
  color: string
  icon: LucideIcon
  dataProduces: string[]
  fields: FieldDef[]
  docsHint?: string
}

// ─── Catalog ─────────────────────────────────────────────────────────────────

const INTEGRATION_CATALOG: Record<string, CatalogEntry> = {
  jumpcloud: {
    label: 'JumpCloud',
    category: 'directory',
    description: 'Directory service, SSO, and device management platform',
    color: '#2563eb',
    icon: Server,
    dataProduces: ['Users', 'Endpoints', 'MFA Status'],
    docsHint: 'Admin Console → API Settings → API Key',
    fields: [
      {
        name: 'api_key',
        label: 'Admin API Key',
        type: 'password',
        placeholder: 'JumpCloud Admin API key',
        hint: 'Found in Admin Console → API Settings',
        required: true,
      },
    ],
  },
  sentinelone: {
    label: 'SentinelOne',
    category: 'security',
    description: 'Endpoint detection and response (EDR) platform',
    color: '#7c3aed',
    icon: Shield,
    dataProduces: ['Endpoints', 'Agents', 'Threats'],
    docsHint: 'Management Console → Settings → Users → API Token',
    fields: [
      {
        name: 'console_url',
        label: 'Console URL',
        type: 'url',
        placeholder: 'https://usea1.sentinelone.net',
        required: true,
        group: 'connection',
      },
      {
        name: 'api_key',
        label: 'API Token',
        type: 'password',
        placeholder: 'SentinelOne API token',
        required: true,
        group: 'connection',
      },
    ],
  },
  symantec_dlp: {
    label: 'Symantec DLP',
    category: 'dlp',
    description: 'Data Loss Prevention — agent status via direct DB connection',
    color: '#d97706',
    icon: Lock,
    dataProduces: ['DLP Agents', 'Policy Violations'],
    docsHint: 'Requires direct database access to the Symantec DLP Enforce DB',
    fields: [
      {
        name: 'db_type',
        label: 'Database Type',
        type: 'select',
        defaultValue: 'postgresql',
        options: [
          { value: 'postgresql', label: 'PostgreSQL' },
          { value: 'mssql', label: 'MSSQL' },
          { value: 'oracle', label: 'Oracle' },
        ],
      },
      {
        name: 'db_host',
        label: 'Host',
        type: 'text',
        placeholder: 'db.example.com',
        required: true,
        group: 'host',
      },
      {
        name: 'db_port',
        label: 'Port',
        type: 'number',
        placeholder: '5432',
        group: 'host',
      },
      {
        name: 'db_name',
        label: 'Database Name',
        type: 'text',
        placeholder: 'symantec_dlp',
        required: true,
      },
      {
        name: 'db_user',
        label: 'Username',
        type: 'text',
        placeholder: 'dlp_readonly',
        required: true,
        group: 'creds',
      },
      {
        name: 'db_password',
        label: 'Password',
        type: 'password',
        placeholder: 'Database password',
        required: true,
        group: 'creds',
      },
    ],
  },
  puppet: {
    label: 'Puppet',
    category: 'config',
    description: 'Infrastructure configuration management via PuppetDB REST API',
    color: '#f59e0b',
    icon: GitBranch,
    dataProduces: ['Endpoints', 'OS Info', 'Last Seen'],
    docsHint: 'Requires PuppetDB API access (v4). Token auth is optional.',
    fields: [
      {
        name: 'base_url',
        label: 'PuppetDB URL',
        type: 'url',
        placeholder: 'http://puppetdb.example.com:8080',
        hint: 'Include port if non-standard (default: 8080)',
        required: true,
      },
      {
        name: 'api_token',
        label: 'API Token',
        type: 'password',
        placeholder: 'Optional — leave blank for unauthenticated',
        hint: 'Token is sent as X-Authentication header',
      },
      {
        name: 'verify_ssl',
        label: 'Verify SSL',
        type: 'select',
        defaultValue: 'true',
        options: [
          { value: 'true', label: 'Yes (recommended)' },
          { value: 'false', label: 'No (skip verification)' },
        ],
      },
    ],
  },
  active_directory: {
    label: 'Active Directory',
    category: 'directory',
    description: 'Microsoft Active Directory — sync users and computers via LDAP',
    color: '#0ea5e9',
    icon: Building2,
    dataProduces: ['Users', 'Endpoints', 'Departments'],
    docsHint: 'Requires a service account with read access to your AD tree',
    fields: [
      {
        name: 'ldap_host',
        label: 'LDAP Host',
        type: 'text',
        placeholder: 'dc01.corp.example.com',
        required: true,
        group: 'server',
      },
      {
        name: 'ldap_port',
        label: 'Port',
        type: 'number',
        placeholder: '389',
        defaultValue: '389',
        group: 'server',
      },
      {
        name: 'use_ssl',
        label: 'Use LDAPS',
        type: 'select',
        defaultValue: 'false',
        options: [
          { value: 'false', label: 'No (LDAP port 389)' },
          { value: 'true', label: 'Yes (LDAPS port 636)' },
        ],
      },
      {
        name: 'base_dn',
        label: 'Base DN',
        type: 'text',
        placeholder: 'DC=corp,DC=example,DC=com',
        hint: 'Root distinguished name for searches',
        required: true,
      },
      {
        name: 'bind_dn',
        label: 'Bind DN',
        type: 'text',
        placeholder: 'CN=svc-sec360,OU=ServiceAccounts,DC=corp,DC=example,DC=com',
        hint: 'Service account distinguished name',
        required: true,
      },
      {
        name: 'bind_password',
        label: 'Bind Password',
        type: 'password',
        placeholder: 'Service account password',
        required: true,
      },
    ],
  },
  google_workspace: {
    label: 'Google Workspace',
    category: 'productivity',
    description: 'Google Workspace login events and application usage data',
    color: '#16a34a',
    icon: Globe,
    dataProduces: ['Login Events', 'App Usage', 'Users'],
    docsHint: 'Requires a Service Account with domain-wide delegation',
    fields: [
      {
        name: 'admin_email',
        label: 'Admin Email',
        type: 'email',
        placeholder: 'admin@yourdomain.com',
        hint: 'Super Admin account to impersonate',
        required: true,
      },
      {
        name: 'service_account_json',
        label: 'Service Account JSON',
        type: 'textarea',
        placeholder: 'Paste your service account JSON here...',
        hint: 'Download from GCP Console → IAM → Service Accounts → Keys',
        required: true,
      },
    ],
  },
  hibob: {
    label: 'HiBob',
    category: 'hr',
    description: 'HR system — user identity, org structure, and employment data',
    color: '#ec4899',
    icon: Users,
    dataProduces: ['Employees', 'Departments', 'Employment Status'],
    docsHint: 'HiBob Settings → Integrations → Service Users',
    fields: [
      {
        name: 'service_user_id',
        label: 'Service User ID',
        type: 'text',
        placeholder: 'service-user@company.com',
        required: true,
        group: 'auth',
      },
      {
        name: 'service_user_token',
        label: 'Service User Token',
        type: 'password',
        placeholder: 'HiBob service token',
        required: true,
        group: 'auth',
      },
    ],
  },
  cloudsoc: {
    label: 'Symantec CloudSOC',
    category: 'casb',
    description: 'Cloud Access Security Broker — shadow IT, cloud app activity, and threat detection',
    color: '#f59e0b',
    icon: Cloud,
    dataProduces: ['Cloud Activity Logs', 'Threat Incidents', 'Policy Violations'],
    docsHint: 'CloudSOC Console → Settings (⚙) → API Keys → Add New API Key',
    fields: [
      {
        name: 'tenant_id',
        label: 'Tenant ID',
        type: 'text',
        placeholder: 'your-tenant-id',
        hint: 'Found in the CloudSOC console URL or API key download',
        required: true,
        group: 'connection',
      },
      {
        name: 'key_id',
        label: 'Key ID',
        type: 'text',
        placeholder: 'API Key ID (username)',
        hint: 'The Key-ID from your downloaded API key file',
        required: true,
        group: 'auth',
      },
      {
        name: 'key_secret',
        label: 'Key Secret',
        type: 'password',
        placeholder: 'API Key Secret (password)',
        hint: 'The Key-Secret from your downloaded API key file',
        required: true,
        group: 'auth',
      },
      {
        name: 'base_url',
        label: 'Base URL',
        type: 'url',
        placeholder: 'https://api-vip.elastica.net',
        hint: 'US: https://api-vip.elastica.net  ·  EU: https://api.eu.elastica.net',
        required: false,
        group: 'connection',
      },
    ],
  },
}

// ─── Category definitions ─────────────────────────────────────────────────────

type CategoryDef = {
  id: string
  label: string
  icon: LucideIcon
}

const CATEGORIES: CategoryDef[] = [
  { id: 'all', label: 'All Integrations', icon: LayoutGrid },
  { id: 'connected', label: 'Connected', icon: CheckCircle2 },
  { id: 'directory', label: 'Directory & IAM', icon: KeyRound },
  { id: 'security', label: 'Endpoint Security', icon: ShieldCheck },
  { id: 'dlp', label: 'Data Protection', icon: Lock },
  { id: 'config', label: 'Config Management', icon: GitBranch },
  { id: 'hr', label: 'HR & Identity', icon: Users },
  { id: 'productivity', label: 'Productivity', icon: Globe },
  { id: 'custom', label: 'Custom', icon: Puzzle },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatRelativeTime(isoString: string | null): string | null {
  if (!isoString) return null
  const date = new Date(isoString)
  const diff = Math.floor((Date.now() - date.getTime()) / 1000)
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}

function getCatalogEntry(type: string): CatalogEntry | null {
  return INTEGRATION_CATALOG[type] || null
}

// ─── DynamicForm ─────────────────────────────────────────────────────────────

function DynamicForm({
  fields,
  values,
  onChange,
}: {
  fields: FieldDef[]
  values: Record<string, string>
  onChange: (name: string, value: string) => void
}) {
  const [showPass, setShowPass] = useState<Record<string, boolean>>({})

  const inputClass =
    'w-full bg-[var(--surface-0)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-[var(--accent)] transition-colors'
  const labelClass = 'block text-xs font-medium text-zinc-400 mb-1.5'

  // Group fields
  const rendered: React.ReactNode[] = []
  const seen = new Set<string>()

  for (const field of fields) {
    if (seen.has(field.name)) continue
    seen.add(field.name)

    const groupId = field.group
    if (groupId) {
      const groupFields = fields.filter((f) => f.group === groupId)
      // Only render the group once
      const allGroupSeen = groupFields.every((f) => seen.has(f.name))
      if (!allGroupSeen) {
        groupFields.forEach((f) => seen.add(f.name))
        rendered.push(
          <div key={`group-${groupId}`} className={`grid gap-3`} style={{ gridTemplateColumns: `repeat(${groupFields.length}, 1fr)` }}>
            {groupFields.map((gf) => (
              <div key={gf.name}>
                <label className={labelClass}>{gf.label}</label>
                {renderField(gf)}
              </div>
            ))}
          </div>
        )
        continue
      }
    }

    rendered.push(
      <div key={field.name}>
        <label className={labelClass}>{field.label}</label>
        {field.hint && <p className="text-xs text-zinc-500 mb-1.5">{field.hint}</p>}
        {renderField(field)}
      </div>
    )
  }

  function renderField(f: FieldDef) {
    const val = values[f.name] ?? f.defaultValue ?? ''

    if (f.type === 'select') {
      return (
        <select
          value={val}
          onChange={(e) => onChange(f.name, e.target.value)}
          className={inputClass}
        >
          {f.options?.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      )
    }

    if (f.type === 'textarea') {
      return (
        <textarea
          value={val}
          onChange={(e) => onChange(f.name, e.target.value)}
          placeholder={f.placeholder}
          rows={5}
          className={`${inputClass} font-mono resize-none`}
        />
      )
    }

    if (f.type === 'password') {
      const visible = showPass[f.name] || false
      return (
        <div className="relative">
          <input
            type={visible ? 'text' : 'password'}
            value={val}
            onChange={(e) => onChange(f.name, e.target.value)}
            placeholder={f.placeholder}
            className={`${inputClass} pr-9`}
          />
          <button
            type="button"
            onClick={() => setShowPass((p) => ({ ...p, [f.name]: !visible }))}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
          >
            {visible ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        </div>
      )
    }

    return (
      <input
        type={f.type}
        value={val}
        onChange={(e) => onChange(f.name, e.target.value)}
        placeholder={f.placeholder}
        className={inputClass}
      />
    )
  }

  return <div className="space-y-4">{rendered}</div>
}

// ─── Status dot ───────────────────────────────────────────────────────────────

function StatusDot({ status }: { status: string }) {
  if (status === 'connected') {
    return (
      <span className="inline-flex items-center gap-1.5">
        <span
          className="w-2 h-2 rounded-full bg-emerald-400"
          style={{ animation: 'pulse-dot 2s ease-in-out infinite' }}
        />
        <span className="text-xs font-medium text-emerald-400">Connected</span>
      </span>
    )
  }
  if (status === 'error') {
    return (
      <span className="inline-flex items-center gap-1.5">
        <span className="w-2 h-2 rounded-full bg-red-400" />
        <span className="text-xs font-medium text-red-400">Error</span>
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="w-2 h-2 rounded-full bg-zinc-600" />
      <span className="text-xs font-medium text-zinc-500">Not Configured</span>
    </span>
  )
}

// ─── IntegrationCard ──────────────────────────────────────────────────────────

function IntegrationCard({
  config,
  selected,
  onClick,
}: {
  config: IntegrationConfig
  selected: boolean
  onClick: () => void
}) {
  const catalog = getCatalogEntry(config.integration_type)
  const isCustomApi = config.integration_type.startsWith('custom_api')

  const Icon = catalog?.icon ?? (isCustomApi ? Activity : Database)
  const color = catalog?.color ?? '#6366f1'
  const description = catalog?.description ?? config.display_name
  const produces = catalog?.dataProduces ?? []
  const category = catalog?.category ?? 'custom'

  const categoryLabel = CATEGORIES.find((c) => c.id === category)?.label ?? category
  const relativeSync = formatRelativeTime(config.last_sync)

  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-xl card card-interactive p-4 transition-all ${
        selected
          ? 'border-[var(--accent)] shadow-[0_0_0_1px_var(--accent)]'
          : ''
      }`}
    >
      <div className="flex items-start gap-3">
        {/* Icon box */}
        <div
          className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ background: `${color}22`, border: `1px solid ${color}44` }}
        >
          <Icon size={18} style={{ color }} />
        </div>

        {/* Body */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-white font-semibold text-sm">{config.display_name}</span>
            <span className="text-[10px] font-medium px-1.5 py-0.5 rounded-full bg-zinc-800 text-zinc-400 border border-white/[0.06]">
              {categoryLabel}
            </span>
          </div>
          <p className="text-zinc-500 text-xs mt-0.5 leading-relaxed truncate">{description}</p>

          {/* Data produces chips */}
          {produces.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {produces.map((p) => (
                <span
                  key={p}
                  className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800/80 text-zinc-400"
                >
                  {p}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Right: status + sync time */}
        <div className="flex flex-col items-end gap-1 flex-shrink-0">
          <StatusDot status={config.status} />
          {relativeSync && (
            <span className="text-[10px] text-zinc-600 flex items-center gap-1">
              <Clock size={9} />
              {relativeSync}
            </span>
          )}
        </div>
      </div>

      {/* Subtle right arrow */}
      <div className="flex justify-end mt-2">
        <ChevronRight size={14} className={`transition-colors ${selected ? 'text-[var(--accent)]' : 'text-zinc-700'}`} />
      </div>
    </button>
  )
}

// ─── IntegrationPanel ─────────────────────────────────────────────────────────

function IntegrationPanel({
  config,
  onClose,
}: {
  config: IntegrationConfig | null
  onClose: () => void
}) {
  const queryClient = useQueryClient()
  const [formValues, setFormValues] = useState<Record<string, string>>({})
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [view, setView] = useState<'status' | 'config'>('status')

  const configType = config?.integration_type
  const initialView = config?.credentials_configured ? 'status' : 'config'

  useEffect(() => {
    if (configType) {
      setFormValues({})
      setTestResult(null)
      setView(initialView)
    }
  }, [configType, initialView])

  const catalog = config ? getCatalogEntry(config.integration_type) : null
  const isCustom = config?.integration_type.startsWith('custom_') ?? false
  const isCustomApi = config?.integration_type.startsWith('custom_api') ?? false

  const Icon = catalog?.icon ?? (isCustomApi ? Activity : Database)
  const color = catalog?.color ?? '#6366f1'
  const description = catalog?.description ?? config?.display_name ?? ''
  const produces = catalog?.dataProduces ?? []
  const category = catalog?.category ?? 'custom'
  const categoryLabel = CATEGORIES.find((c) => c.id === category)?.label ?? category
  const fields = catalog?.fields ?? []

  const saveMutation = useMutation({
    mutationFn: (creds: Record<string, unknown>) =>
      saveIntegrationCredentials(config!.integration_type, creds, true),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] })
      setView('status')
    },
  })

  const testMutation = useMutation({
    mutationFn: () => testIntegration(config!.integration_type),
    onSuccess: (data) => setTestResult(data),
    onError: (err: Error) => setTestResult({ success: false, message: err.message }),
  })

  const syncMutation = useMutation({
    mutationFn: () => syncIntegration(config!.integration_type),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['integrations'] }),
  })

  const removeCreditsMutation = useMutation({
    mutationFn: () => deleteIntegrationCredentials(config!.integration_type),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] })
      setTestResult(null)
    },
  })

  const deleteIntegrationMutation = useMutation({
    mutationFn: () => deleteIntegration(config!.integration_type),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] })
      onClose()
    },
  })

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault()
    const creds: Record<string, unknown> = {}
    // Merge defaults with form values
    fields.forEach((f) => {
      const val = formValues[f.name] ?? f.defaultValue ?? ''
      if (val !== '') {
        if (f.type === 'number') {
          creds[f.name] = parseInt(val, 10) || undefined
        } else {
          creds[f.name] = val
        }
      }
    })
    saveMutation.mutate(creds)
  }

  const visible = config !== null
  const relativeSync = formatRelativeTime(config?.last_sync ?? null)

  return (
    <>
      {/* Backdrop */}
      {visible && (
        <div
          className="fixed inset-0 bg-black/50 z-40 fade-in"
          onClick={onClose}
        />
      )}

      {/* Panel */}
      <div
        className={`fixed top-0 right-0 h-full w-[520px] z-50 flex flex-col bg-[var(--surface-1)] border-l border-[var(--border)] shadow-2xl transition-transform duration-300 ease-out ${
          visible ? 'translate-x-0' : 'translate-x-full'
        }`}
      >
        {!config ? null : (
          <>
            {/* Header */}
            <div className="flex items-start gap-4 p-6 border-b border-[var(--border)] flex-shrink-0">
              <div
                className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0"
                style={{ background: `${color}22`, border: `1px solid ${color}55` }}
              >
                <Icon size={22} style={{ color }} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="text-white font-bold text-base">{config.display_name}</h2>
                  <span className="text-[10px] font-medium px-1.5 py-0.5 rounded-full bg-zinc-800 text-zinc-400 border border-white/[0.06]">
                    {categoryLabel}
                  </span>
                </div>
                <p className="text-zinc-500 text-xs mt-0.5 leading-relaxed">{description}</p>
              </div>
              <button
                onClick={onClose}
                className="text-zinc-500 hover:text-white p-1 rounded-lg hover:bg-white/[0.06] flex-shrink-0"
              >
                <X size={18} />
              </button>
            </div>

            {/* Tab switcher */}
            <div className="flex border-b border-[var(--border)] flex-shrink-0">
              {(['status', 'config'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setView(tab)}
                  className={`flex-1 py-3 text-xs font-medium transition-colors ${
                    view === tab
                      ? 'text-white border-b-2 border-[var(--accent)]'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  {tab === 'status' ? 'Status & Actions' : 'Configure'}
                </button>
              ))}
            </div>

            {/* Scrollable body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {view === 'status' && (
                <>
                  {/* Status card */}
                  <div className="rounded-xl bg-[var(--surface-2)] border border-[var(--border)] p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-zinc-500 font-medium uppercase tracking-wide">Status</span>
                      <StatusDot status={config.status} />
                    </div>
                    {relativeSync && (
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-zinc-500">Last synced</span>
                        <span className="text-zinc-300 flex items-center gap-1">
                          <Clock size={11} />
                          {relativeSync}
                        </span>
                      </div>
                    )}
                    {config.records_synced && (
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-zinc-500">Records synced</span>
                        <span className="text-zinc-300">{config.records_synced}</span>
                      </div>
                    )}
                    {config.last_error && (
                      <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-xs text-red-400 flex items-start gap-2">
                        <AlertCircle size={13} className="flex-shrink-0 mt-0.5" />
                        <span>{config.last_error}</span>
                      </div>
                    )}
                  </div>

                  {/* Data produced */}
                  {produces.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-zinc-500 uppercase tracking-wide mb-2">
                        Data Synced
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {produces.map((p) => (
                          <span
                            key={p}
                            className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] text-zinc-300"
                          >
                            <Package size={11} className="text-zinc-500" />
                            {p}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  {config.credentials_configured && (
                    <div className="space-y-2">
                      <p className="text-xs font-medium text-zinc-500 uppercase tracking-wide mb-2">Actions</p>

                      <button
                        onClick={() => testMutation.mutate()}
                        disabled={testMutation.isPending}
                        className="w-full flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[var(--surface-2)] border border-[var(--border)] hover:border-[var(--accent)]/50 text-sm text-zinc-300 hover:text-white transition-colors disabled:opacity-50"
                      >
                        {testMutation.isPending ? (
                          <Loader2 size={14} className="animate-spin text-zinc-400" />
                        ) : (
                          <Settings2 size={14} className="text-zinc-400" />
                        )}
                        Test Connection
                      </button>

                      <button
                        onClick={() => syncMutation.mutate()}
                        disabled={syncMutation.isPending}
                        className="w-full flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[var(--accent)]/10 border border-[var(--accent)]/30 hover:bg-[var(--accent)]/20 text-sm text-emerald-400 hover:text-emerald-300 transition-colors disabled:opacity-50"
                      >
                        {syncMutation.isPending ? (
                          <Loader2 size={14} className="animate-spin" />
                        ) : (
                          <RefreshCw size={14} />
                        )}
                        {syncMutation.isPending ? 'Syncing...' : 'Sync Now'}
                      </button>

                      <button
                        onClick={() => {
                          if (window.confirm('Remove credentials for this integration?')) {
                            removeCreditsMutation.mutate()
                          }
                        }}
                        disabled={removeCreditsMutation.isPending}
                        className="w-full flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-500/5 border border-red-500/20 hover:bg-red-500/10 text-sm text-red-400 hover:text-red-300 transition-colors disabled:opacity-50"
                      >
                        <Trash2 size={14} />
                        Remove Credentials
                      </button>

                      {isCustom && (
                        <button
                          onClick={() => {
                            if (window.confirm(`Delete the "${config.display_name}" integration entirely?`)) {
                              deleteIntegrationMutation.mutate()
                            }
                          }}
                          disabled={deleteIntegrationMutation.isPending}
                          className="w-full flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-500/10 border border-red-500/30 hover:bg-red-500/15 text-sm text-red-400 transition-colors disabled:opacity-50"
                        >
                          <Trash2 size={14} />
                          Delete Integration
                        </button>
                      )}
                    </div>
                  )}

                  {!config.credentials_configured && (
                    <div className="rounded-xl bg-[var(--surface-2)] border border-[var(--border)] p-4 text-center">
                      <Plug size={28} className="text-zinc-600 mx-auto mb-2" />
                      <p className="text-zinc-400 text-sm font-medium">Not configured yet</p>
                      <p className="text-zinc-600 text-xs mt-1 mb-3">Add credentials to start syncing data</p>
                      <button
                        onClick={() => setView('config')}
                        className="inline-flex items-center gap-2 px-4 py-2 bg-[var(--accent)]/10 border border-[var(--accent)]/30 text-emerald-400 text-sm rounded-lg hover:bg-[var(--accent)]/20"
                      >
                        <Settings2 size={14} />
                        Configure Now
                      </button>
                    </div>
                  )}

                  {/* Test / sync results */}
                  {testResult && (
                    <div
                      className={`rounded-lg p-3 text-xs flex items-start gap-2 ${
                        testResult.success
                          ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-300'
                          : 'bg-red-500/10 border border-red-500/20 text-red-400'
                      }`}
                    >
                      {testResult.success ? <CheckCircle2 size={13} className="flex-shrink-0 mt-0.5" /> : <XCircle size={13} className="flex-shrink-0 mt-0.5" />}
                      <span>{testResult.message}</span>
                    </div>
                  )}
                </>
              )}

              {view === 'config' && (
                <form onSubmit={handleSave} className="space-y-4">
                  {catalog?.docsHint && (
                    <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3 text-xs text-blue-300 flex items-start gap-2">
                      <AlertCircle size={13} className="flex-shrink-0 mt-0.5" />
                      <span>{catalog.docsHint}</span>
                    </div>
                  )}

                  {config.credentials_configured && (
                    <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3 text-xs text-amber-300">
                      Credentials are already configured. Re-enter all fields to update them.
                    </div>
                  )}

                  {fields.length > 0 ? (
                    <DynamicForm
                      fields={fields}
                      values={formValues}
                      onChange={(name, value) => setFormValues((p) => ({ ...p, [name]: value }))}
                    />
                  ) : (
                    <p className="text-zinc-500 text-sm">No configurable fields for this integration.</p>
                  )}

                  <div className="flex items-center gap-3 pt-2">
                    <button
                      type="submit"
                      disabled={saveMutation.isPending}
                      className="flex items-center gap-2 px-4 py-2.5 bg-[var(--accent)] hover:bg-emerald-400 disabled:bg-emerald-900 disabled:cursor-not-allowed text-black text-sm font-semibold rounded-lg pressable transition-colors"
                    >
                      {saveMutation.isPending && <Loader2 size={14} className="animate-spin" />}
                      Save & Enable
                    </button>
                    <button
                      type="button"
                      onClick={() => setView('status')}
                      className="px-4 py-2.5 text-zinc-400 hover:text-white text-sm font-medium transition-colors"
                    >
                      Cancel
                    </button>
                  </div>

                  {saveMutation.isError && (
                    <p className="text-red-400 text-xs">{(saveMutation.error as Error).message}</p>
                  )}
                </form>
              )}
            </div>
          </>
        )}
      </div>
    </>
  )
}

// ─── AddCustomModal ───────────────────────────────────────────────────────────

function AddCustomModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<'api' | 'db'>('api')
  const [displayName, setDisplayName] = useState('')
  const [apiValues, setApiValues] = useState<Record<string, string>>({
    auth_type: 'none',
    entity_type: 'endpoint',
  })
  const [dbValues, setDbValues] = useState<Record<string, string>>({
    db_type: 'postgresql',
    entity_type: 'endpoint',
  })

  const createMutation = useMutation({
    mutationFn: createCustomIntegration,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] })
      onClose()
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!displayName.trim()) return
    const slug = slugify(displayName)

    if (tab === 'api') {
      const creds: Record<string, unknown> = { custom_name: displayName, ...apiValues }
      createMutation.mutate({
        integration_type: `custom_api_${slug}`,
        display_name: displayName,
        credentials: creds,
        is_enabled: true,
      })
    } else {
      const creds: Record<string, unknown> = { custom_name: displayName, ...dbValues }
      if (dbValues.db_port) creds.db_port = parseInt(dbValues.db_port, 10)
      createMutation.mutate({
        integration_type: `custom_db_${slug}`,
        display_name: displayName,
        credentials: creds,
        is_enabled: true,
      })
    }
  }

  const inputClass =
    'w-full bg-[var(--surface-0)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-[var(--accent)] transition-colors'
  const labelClass = 'block text-xs font-medium text-zinc-400 mb-1.5'

  const showAuthValue = apiValues.auth_type !== 'none'
  const showAuthHeader = apiValues.auth_type === 'api_key'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 fade-in">
      <div className="w-full max-w-lg bg-[var(--surface-1)] rounded-2xl border border-[var(--border)] shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-[var(--border)]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-[var(--accent)]/10 rounded-lg flex items-center justify-center">
              <Plus size={16} className="text-emerald-400" />
            </div>
            <h2 className="text-white font-bold text-base">Add Custom Integration</h2>
          </div>
          <button onClick={onClose} className="text-zinc-500 hover:text-white p-1 rounded-lg hover:bg-white/[0.06]">
            <X size={18} />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-[var(--border)]">
          {(['api', 'db'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`flex-1 py-3 text-xs font-medium flex items-center justify-center gap-2 transition-colors ${
                tab === t
                  ? 'text-white border-b-2 border-[var(--accent)]'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {t === 'api' ? <Activity size={13} /> : <Database size={13} />}
              {t === 'api' ? 'REST API' : 'Database'}
            </button>
          ))}
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4 max-h-[60vh] overflow-y-auto">
          {/* Name — shared */}
          <div>
            <label className={labelClass}>Integration Name</label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder={tab === 'api' ? 'e.g. My Salesforce API' : 'e.g. Internal Asset DB'}
              className={inputClass}
              required
            />
          </div>

          {tab === 'api' && (
            <>
              <div>
                <label className={labelClass}>Base URL</label>
                <input
                  type="url"
                  value={apiValues.base_url ?? ''}
                  onChange={(e) => setApiValues((p) => ({ ...p, base_url: e.target.value }))}
                  placeholder="https://api.example.com"
                  className={inputClass}
                  required
                />
              </div>
              <div>
                <label className={labelClass}>Endpoint Path</label>
                <input
                  type="text"
                  value={apiValues.endpoint_path ?? ''}
                  onChange={(e) => setApiValues((p) => ({ ...p, endpoint_path: e.target.value }))}
                  placeholder="/api/v1/devices"
                  className={inputClass}
                />
              </div>
              <div>
                <label className={labelClass}>Authentication Type</label>
                <select
                  value={apiValues.auth_type ?? 'none'}
                  onChange={(e) => setApiValues((p) => ({ ...p, auth_type: e.target.value }))}
                  className={inputClass}
                >
                  <option value="none">None</option>
                  <option value="api_key">API Key</option>
                  <option value="bearer">Bearer Token</option>
                  <option value="basic">Basic Auth (Base64)</option>
                </select>
              </div>
              {showAuthHeader && (
                <div>
                  <label className={labelClass}>Auth Header Name</label>
                  <input
                    type="text"
                    value={apiValues.auth_header ?? 'Authorization'}
                    onChange={(e) => setApiValues((p) => ({ ...p, auth_header: e.target.value }))}
                    placeholder="Authorization"
                    className={inputClass}
                  />
                </div>
              )}
              {showAuthValue && (
                <div>
                  <label className={labelClass}>
                    {apiValues.auth_type === 'bearer' ? 'Bearer Token' : apiValues.auth_type === 'basic' ? 'Base64 Credentials' : 'API Key Value'}
                  </label>
                  <input
                    type="password"
                    value={apiValues.auth_value ?? ''}
                    onChange={(e) => setApiValues((p) => ({ ...p, auth_value: e.target.value }))}
                    placeholder="Credential value"
                    className={inputClass}
                  />
                </div>
              )}
              <div>
                <label className={labelClass}>JSON Path to Array</label>
                <input
                  type="text"
                  value={apiValues.data_field ?? ''}
                  onChange={(e) => setApiValues((p) => ({ ...p, data_field: e.target.value }))}
                  placeholder='e.g. "data" or "data.items" (leave blank for root array)'
                  className={inputClass}
                />
              </div>
              <div>
                <label className={labelClass}>Entity Type</label>
                <select
                  value={apiValues.entity_type ?? 'endpoint'}
                  onChange={(e) => setApiValues((p) => ({ ...p, entity_type: e.target.value }))}
                  className={inputClass}
                >
                  <option value="endpoint">Endpoint</option>
                  <option value="user">User</option>
                  <option value="raw">Raw Only</option>
                </select>
              </div>
            </>
          )}

          {tab === 'db' && (
            <>
              <div>
                <label className={labelClass}>Database Type</label>
                <select
                  value={dbValues.db_type ?? 'postgresql'}
                  onChange={(e) => setDbValues((p) => ({ ...p, db_type: e.target.value }))}
                  className={inputClass}
                >
                  <option value="postgresql">PostgreSQL</option>
                  <option value="mssql">MSSQL / SQL Server</option>
                  <option value="mysql">MySQL</option>
                </select>
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label className={labelClass}>Host</label>
                  <input
                    type="text"
                    value={dbValues.db_host ?? ''}
                    onChange={(e) => setDbValues((p) => ({ ...p, db_host: e.target.value }))}
                    placeholder="db.example.com"
                    className={inputClass}
                    required
                  />
                </div>
                <div>
                  <label className={labelClass}>Port</label>
                  <input
                    type="number"
                    value={dbValues.db_port ?? ''}
                    onChange={(e) => setDbValues((p) => ({ ...p, db_port: e.target.value }))}
                    placeholder={dbValues.db_type === 'mssql' ? '1433' : '5432'}
                    className={inputClass}
                  />
                </div>
              </div>
              <div>
                <label className={labelClass}>Database Name</label>
                <input
                  type="text"
                  value={dbValues.db_name ?? ''}
                  onChange={(e) => setDbValues((p) => ({ ...p, db_name: e.target.value }))}
                  placeholder="assets_db"
                  className={inputClass}
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={labelClass}>Username</label>
                  <input
                    type="text"
                    value={dbValues.db_user ?? ''}
                    onChange={(e) => setDbValues((p) => ({ ...p, db_user: e.target.value }))}
                    placeholder="readonly_user"
                    className={inputClass}
                    required
                  />
                </div>
                <div>
                  <label className={labelClass}>Password</label>
                  <input
                    type="password"
                    value={dbValues.db_password ?? ''}
                    onChange={(e) => setDbValues((p) => ({ ...p, db_password: e.target.value }))}
                    placeholder="Password"
                    className={inputClass}
                    required
                  />
                </div>
              </div>
              <div>
                <label className={labelClass}>SQL Query</label>
                <textarea
                  value={dbValues.query ?? ''}
                  onChange={(e) => setDbValues((p) => ({ ...p, query: e.target.value }))}
                  placeholder="SELECT hostname, os_version, last_seen FROM assets"
                  rows={4}
                  className={`${inputClass} font-mono resize-none`}
                  required
                />
              </div>
              <div>
                <label className={labelClass}>Entity Type</label>
                <select
                  value={dbValues.entity_type ?? 'endpoint'}
                  onChange={(e) => setDbValues((p) => ({ ...p, entity_type: e.target.value }))}
                  className={inputClass}
                >
                  <option value="endpoint">Endpoint</option>
                  <option value="user">User</option>
                  <option value="raw">Raw Only</option>
                </select>
              </div>
            </>
          )}

          {createMutation.isError && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-xs text-red-400">
              {(createMutation.error as Error).message}
            </div>
          )}
        </form>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 p-5 border-t border-[var(--border)]">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-zinc-400 hover:text-white text-sm font-medium transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit as unknown as React.MouseEventHandler}
            disabled={createMutation.isPending || !displayName.trim()}
            className="flex items-center gap-2 px-5 py-2.5 bg-[var(--accent)] hover:bg-emerald-400 disabled:bg-emerald-900 disabled:cursor-not-allowed text-black text-sm font-semibold rounded-lg pressable transition-colors"
          >
            {createMutation.isPending && <Loader2 size={14} className="animate-spin" />}
            Create Integration
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function Integrations() {
  const queryClient = useQueryClient()
  const [category, setCategory] = useState('all')
  const [selectedType, setSelectedType] = useState<string | null>(null)
  const [showAddCustom, setShowAddCustom] = useState(false)
  const [correlateResult, setCorrelateResult] = useState<{ success: boolean; message: string } | null>(null)

  const { data: integrations = [], isLoading, isError, error } = useQuery({
    queryKey: ['integrations'],
    queryFn: fetchIntegrations,
    refetchInterval: 30000,
  })

  const correlateMutation = useMutation({
    mutationFn: async () => {
      const { data } = await import('../api/client').then((m) => m.default.post('/api/users/correlate'))
      return data
    },
    onSuccess: (data) => {
      setCorrelateResult({
        success: data.success,
        message: data.success
          ? `Correlation complete: ${data.endpoint_merges ?? 0} endpoints merged, ${data.user_endpoint_matches ?? 0} user-device links`
          : `Correlation failed: ${data.error}`,
      })
      queryClient.invalidateQueries({ queryKey: ['users'] })
      queryClient.invalidateQueries({ queryKey: ['user-identity'] })
      setTimeout(() => setCorrelateResult(null), 8000)
    },
  })

  // Category filtering
  const filtered = integrations.filter((config) => {
    if (category === 'all') return true
    if (category === 'connected') return config.status === 'connected'
    if (category === 'custom') return config.integration_type.startsWith('custom_')
    const cat = getCatalogEntry(config.integration_type)?.category
    return cat === category
  })

  const selectedConfig = integrations.find((c) => c.integration_type === selectedType) ?? null

  // Category counts
  const counts: Record<string, number> = {
    all: integrations.length,
    connected: integrations.filter((c) => c.status === 'connected').length,
    custom: integrations.filter((c) => c.integration_type.startsWith('custom_')).length,
  }

  return (
    <div className="absolute inset-0 flex overflow-hidden">
      {/* ── Left sidebar ── */}
      <aside className="w-[220px] flex-shrink-0 border-r border-[var(--border)] bg-[var(--surface-1)] flex flex-col overflow-y-auto">
        <div className="p-4 border-b border-[var(--border)]">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 bg-emerald-600/20 rounded-lg flex items-center justify-center">
              <Plug size={14} className="text-emerald-400" />
            </div>
            <span className="text-white font-bold text-sm">Integrations</span>
          </div>
        </div>

        <nav className="flex-1 p-3 space-y-0.5">
          {CATEGORIES.map((cat) => {
            const CatIcon = cat.icon
            const count = counts[cat.id] ?? integrations.filter((c) => {
              if (cat.id === 'custom') return c.integration_type.startsWith('custom_')
              return getCatalogEntry(c.integration_type)?.category === cat.id
            }).length
            return (
              <button
                key={cat.id}
                onClick={() => setCategory(cat.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                  category === cat.id
                    ? 'bg-[var(--accent)]/10 text-emerald-400 border border-[var(--accent)]/20'
                    : 'text-zinc-400 hover:text-white hover:bg-white/[0.04]'
                }`}
              >
                <CatIcon size={14} />
                <span className="flex-1 text-left">{cat.label}</span>
                {count > 0 && (
                  <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-medium ${
                    category === cat.id ? 'bg-emerald-500/20 text-emerald-400' : 'bg-zinc-800 text-zinc-500'
                  }`}>
                    {count}
                  </span>
                )}
              </button>
            )
          })}
        </nav>

        {/* Add Custom button */}
        <div className="p-3 border-t border-[var(--border)]">
          <button
            onClick={() => setShowAddCustom(true)}
            className="w-full flex items-center gap-2 px-3 py-2.5 rounded-lg bg-[var(--accent)]/10 border border-[var(--accent)]/20 hover:bg-[var(--accent)]/20 text-xs font-medium text-emerald-400 transition-colors"
          >
            <Plus size={13} />
            Add Custom
          </button>
        </div>
      </aside>

      {/* ── Main area ── */}
      <main className="flex-1 overflow-y-auto">
        <div className="p-6 max-w-3xl">
          {/* Header */}
          <div className="flex items-center justify-between mb-5">
            <div>
              <h1 className="text-white font-bold text-xl">
                {CATEGORIES.find((c) => c.id === category)?.label ?? 'Integrations'}
              </h1>
              <p className="text-zinc-500 text-xs mt-0.5">
                {filtered.length} integration{filtered.length !== 1 ? 's' : ''}
              </p>
            </div>
            <button
              onClick={() => correlateMutation.mutate()}
              disabled={correlateMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-[var(--accent)]/10 border border-[var(--accent)]/30 hover:bg-[var(--accent)]/20 disabled:opacity-60 text-emerald-400 text-xs font-medium rounded-lg pressable"
            >
              {correlateMutation.isPending ? (
                <Loader2 size={13} className="animate-spin" />
              ) : (
                <RefreshCw size={13} />
              )}
              {correlateMutation.isPending ? 'Correlating...' : 'Run Correlation'}
            </button>
          </div>

          {correlateResult && (
            <div
              className={`mb-4 flex items-start gap-2 text-xs px-4 py-2.5 rounded-lg border ${
                correlateResult.success
                  ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-300'
                  : 'bg-red-500/10 border-red-500/20 text-red-400'
              }`}
            >
              {correlateResult.success ? (
                <CheckCircle2 size={13} className="mt-0.5 flex-shrink-0" />
              ) : (
                <XCircle size={13} className="mt-0.5 flex-shrink-0" />
              )}
              {correlateResult.message}
            </div>
          )}

          {isError && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 mb-5 flex items-start gap-3">
              <AlertCircle size={16} className="text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <div className="text-red-400 font-medium text-sm">Failed to load integrations</div>
                <div className="text-red-400/70 text-xs mt-0.5">{(error as Error)?.message}</div>
              </div>
            </div>
          )}

          {/* Cards grid */}
          <div className="grid gap-3">
            {isLoading &&
              Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="rounded-xl card p-4 animate-pulse">
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 bg-zinc-800 rounded-lg flex-shrink-0" />
                    <div className="flex-1 space-y-2 pt-1">
                      <div className="h-4 bg-zinc-800 rounded w-32" />
                      <div className="h-3 bg-zinc-800 rounded w-56" />
                    </div>
                    <div className="h-5 w-20 bg-zinc-800 rounded-full" />
                  </div>
                </div>
              ))}

            {!isLoading && filtered.length === 0 && (
              <div className="rounded-xl card p-8 text-center">
                <Puzzle size={32} className="text-zinc-700 mx-auto mb-3" />
                <p className="text-zinc-400 text-sm font-medium">No integrations in this category</p>
                <p className="text-zinc-600 text-xs mt-1">
                  {category === 'connected'
                    ? 'Connect and sync an integration to see it here'
                    : 'Add a custom integration or select a different category'}
                </p>
              </div>
            )}

            {!isLoading &&
              filtered.map((config) => (
                <IntegrationCard
                  key={config.integration_type}
                  config={config}
                  selected={selectedType === config.integration_type}
                  onClick={() => {
                    setSelectedType(
                      selectedType === config.integration_type ? null : config.integration_type
                    )
                  }}
                />
              ))}
          </div>
        </div>
      </main>

      {/* ── Right slide-over panel ── */}
      <IntegrationPanel
        config={selectedConfig}
        onClose={() => setSelectedType(null)}
      />

      {/* ── Add Custom Modal ── */}
      {showAddCustom && <AddCustomModal onClose={() => setShowAddCustom(false)} />}
    </div>
  )
}
