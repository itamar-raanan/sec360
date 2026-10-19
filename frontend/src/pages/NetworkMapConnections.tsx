import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, CheckCircle2, Loader2, Plus, RadioTower, Router, Save, Server, Trash2, Wifi } from 'lucide-react'

import apiClient from '../api/client'
import { useConfirm } from '../components/shared/ConfirmDialog'

type ConnectionType = 'cisco_wlc' | 'fortigate' | 'mikrotik'

interface Connection {
  id: string
  connection_type: ConnectionType
  display_name: string
  enabled: boolean
  config: Record<string, string | number | boolean>
  credentials_configured: boolean
  status: string
  last_tested_at: string | null
  last_collected_at: string | null
  last_error: string | null
  records_synced: number
}

interface Floor { id: string; ordinal: number; label: string; managed: boolean }
interface Equipment { id: string; kind: 'ap' | 'switch'; name: string; floor_id: string | null; position_x: number; position_z: number; port_overrides: Record<string, { floor_id?: string; role?: string }>; last_seen: string | null }

const PRODUCTS: Record<ConnectionType, { label: string; note: string; icon: typeof Wifi }> = {
  cisco_wlc: { label: 'Cisco WLC', note: 'One SSH connection · wireless clients, APs, and SSIDs', icon: RadioTower },
  fortigate: { label: 'FortiGate', note: 'One HTTPS API connection · DHCP identity enrichment', icon: Router },
  mikrotik: { label: 'MikroTik SwOS', note: 'Multiple HTTP Digest connections · switch port and VLAN attachment', icon: Server },
}

const initialConfig = (type: ConnectionType): Record<string, string | number | boolean> => type === 'cisco_wlc'
  ? { host: '', port: 22, username: '', password: '', timeout_seconds: 15, allow_unknown_host_key: false }
  : type === 'fortigate'
    ? { base_url: '', api_token: '', vdom: '*', timeout_seconds: 10, verify_ssl: true }
    : { base_url: 'http://', username: 'admin', password: '', timeout_seconds: 10, verify_ssl: false }

function errorText(error: unknown) {
  return (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Request failed'
}

export default function NetworkMapConnections() {
  const queryClient = useQueryClient()
  const confirm = useConfirm()
  const { data: connections = [], isLoading } = useQuery<Connection[]>({
    queryKey: ['network-map-connections'],
    queryFn: () => apiClient.get('/network-map/connections').then(response => response.data),
  })
  const { data: floors = [] } = useQuery<Floor[]>({ queryKey: ['network-map-floors'], queryFn: () => apiClient.get('/network-map/floors').then(response => response.data) })
  const { data: equipment = [] } = useQuery<Equipment[]>({ queryKey: ['network-map-equipment'], queryFn: () => apiClient.get('/network-map/equipment').then(response => response.data) })
  const [editing, setEditing] = useState<Connection | null>(null)
  const [addingType, setAddingType] = useState<ConnectionType | null>(null)
  const [form, setForm] = useState<Record<string, string | number | boolean>>({})
  const [displayName, setDisplayName] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null)

  const singletonTypes = useMemo(() => new Set(connections.map(item => item.connection_type)), [connections])
  const currentType = editing?.connection_type || addingType
  const managedFloors = floors.filter(floor => floor.managed)

  const refresh = () => queryClient.invalidateQueries({ queryKey: ['network-map-connections'] })
  const refreshEquipment = () => queryClient.invalidateQueries({ queryKey: ['network-map-equipment'] })
  const saveMutation = useMutation({
    mutationFn: async () => {
      if (!currentType) return
      if (editing) {
        await apiClient.put(`/network-map/connections/${editing.id}`, { display_name: displayName, enabled, config: form })
      } else {
        await apiClient.post('/network-map/connections', { connection_type: currentType, display_name: displayName, enabled, config: form })
      }
    },
    onSuccess: async () => {
      await refresh()
      setEditing(null); setAddingType(null); setMessage({ ok: true, text: 'Connection saved. Run Test to validate it.' })
    },
    onError: error => setMessage({ ok: false, text: errorText(error) }),
  })
  const testMutation = useMutation({
    mutationFn: async () => {
      const response = editing
        ? await apiClient.post(`/network-map/connections/${editing.id}/test`, { config: form })
        : await apiClient.post('/network-map/connections/test', { connection_type: currentType, config: form })
      return response.data as { counts: Record<string, number> }
    },
    onSuccess: async data => {
      await refresh()
      const count = Object.values(data.counts).reduce((sum, value) => sum + value, 0)
      setMessage({ ok: true, text: `Connection succeeded · ${count} records visible` })
    },
    onError: error => setMessage({ ok: false, text: errorText(error) }),
  })

  const openNew = (type: ConnectionType) => {
    setEditing(null); setAddingType(type); setDisplayName(PRODUCTS[type].label); setEnabled(true); setForm(initialConfig(type)); setMessage(null)
  }
  const openEdit = (item: Connection) => {
    setAddingType(null); setEditing(item); setDisplayName(item.display_name); setEnabled(item.enabled)
    setForm({ ...initialConfig(item.connection_type), ...item.config, password: '', api_token: '' }); setMessage(null)
  }

  const remove = async (item: Connection) => {
    const approved = await confirm({ title: 'Delete connection?', message: `${item.display_name} and its retained Network Map observations will be removed.`, confirmLabel: 'Delete', tone: 'danger' })
    if (!approved) return
    await apiClient.delete(`/network-map/connections/${item.id}`)
    await refresh()
  }

  return (
    <div className="h-full overflow-y-auto px-5 py-6 lg:px-8">
      <div className="mx-auto max-w-6xl">
        <a href="/settings" className="mb-5 inline-flex items-center gap-1.5 text-xs font-medium text-zinc-500 hover:text-zinc-200"><ArrowLeft size={13} /> System Settings</a>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-emerald-500">Network Map</p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight text-white">Connections</h1>
            <p className="mt-1 max-w-2xl text-sm text-zinc-500">Feature-owned topology sources. Tests never save the form, and saved secrets are never returned to the browser.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {(Object.keys(PRODUCTS) as ConnectionType[]).map(type => {
              const disabled = type !== 'mikrotik' && singletonTypes.has(type)
              return <button key={type} disabled={disabled} onClick={() => openNew(type)} className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-2 text-xs font-medium text-zinc-300 hover:border-emerald-500/40 hover:text-white disabled:cursor-not-allowed disabled:opacity-35"><Plus size={13} /> {PRODUCTS[type].label}</button>
            })}
          </div>
        </div>

        <div className="mt-7 grid gap-3 lg:grid-cols-3">
          {(Object.keys(PRODUCTS) as ConnectionType[]).map(type => {
            const product = PRODUCTS[type]
            const rows = connections.filter(item => item.connection_type === type)
            const Icon = product.icon
            return <section key={type} className="min-h-52 rounded-xl border border-white/[0.07] bg-white/[0.025] p-4">
              <div className="flex items-start gap-3"><span className="rounded-lg bg-emerald-500/10 p-2 text-emerald-400"><Icon size={16} /></span><div><h2 className="text-sm font-semibold text-zinc-100">{product.label}</h2><p className="mt-0.5 text-[11px] leading-4 text-zinc-500">{product.note}</p></div></div>
              <div className="mt-4 space-y-2">
                {isLoading && <div className="h-16 animate-pulse rounded-lg bg-white/[0.03]" />}
                {!isLoading && rows.length === 0 && <p className="rounded-lg border border-dashed border-white/[0.08] px-3 py-5 text-center text-xs text-zinc-600">Not configured</p>}
                {rows.map(item => <button key={item.id} onClick={() => openEdit(item)} className="w-full rounded-lg border border-white/[0.06] bg-black/10 p-3 text-left hover:border-white/[0.14]">
                  <span className="flex items-center justify-between"><span className="text-xs font-medium text-zinc-200">{item.display_name}</span><span className={`h-2 w-2 rounded-full ${item.status === 'connected' ? 'bg-emerald-400' : item.status === 'error' ? 'bg-red-400' : 'bg-zinc-600'}`} /></span>
                  <span className="mt-1 block text-[10px] text-zinc-600">{item.status} · {item.records_synced} records</span>
                </button>)}
              </div>
            </section>
          })}
        </div>

        {currentType && <section className="mt-6 rounded-xl border border-emerald-500/20 bg-emerald-500/[0.025] p-5">
          <div className="flex items-start justify-between gap-4"><div><p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-emerald-500">{editing ? 'Edit' : 'New connection'}</p><h2 className="mt-1 text-base font-semibold text-white">{PRODUCTS[currentType].label}</h2></div>{editing && <button onClick={() => remove(editing)} className="rounded-lg p-2 text-zinc-600 hover:bg-red-500/10 hover:text-red-400" aria-label="Delete connection"><Trash2 size={15} /></button>}</div>
          <div className="mt-5 grid gap-4 md:grid-cols-2">
            <Field label="Display name"><input value={displayName} onChange={event => setDisplayName(event.target.value)} /></Field>
            {currentType === 'cisco_wlc' && <><Field label="Host"><input value={String(form.host || '')} onChange={event => setForm({ ...form, host: event.target.value })} /></Field><Field label="SSH port"><input type="number" value={Number(form.port || 22)} onChange={event => setForm({ ...form, port: Number(event.target.value) })} /></Field></>}
            {currentType !== 'cisco_wlc' && <Field label={currentType === 'fortigate' ? 'HTTPS base URL' : 'SwOS URL'}><input value={String(form.base_url || '')} onChange={event => setForm({ ...form, base_url: event.target.value })} placeholder={currentType === 'fortigate' ? 'https://firewall.example' : 'http://switch.local'} /></Field>}
            {currentType !== 'fortigate' && <Field label="Username"><input value={String(form.username || '')} onChange={event => setForm({ ...form, username: event.target.value })} /></Field>}
            <Field label={currentType === 'fortigate' ? 'API token' : 'Password'} hint={editing ? 'Leave blank to preserve the saved secret' : undefined}><input type="password" value={String(form[currentType === 'fortigate' ? 'api_token' : 'password'] || '')} onChange={event => setForm({ ...form, [currentType === 'fortigate' ? 'api_token' : 'password']: event.target.value })} autoComplete="new-password" /></Field>
            {currentType === 'fortigate' && <Field label="VDOM"><input value={String(form.vdom || '*')} onChange={event => setForm({ ...form, vdom: event.target.value })} /></Field>}
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-4 text-xs text-zinc-400">
            <label className="flex items-center gap-2"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} /> Enabled</label>
            {currentType === 'cisco_wlc' && <label className="flex items-center gap-2"><input type="checkbox" checked={Boolean(form.allow_unknown_host_key)} onChange={event => setForm({ ...form, allow_unknown_host_key: event.target.checked })} /> Allow unknown SSH host key</label>}
            {currentType !== 'cisco_wlc' && <label className="flex items-center gap-2"><input type="checkbox" checked={Boolean(form.verify_ssl)} onChange={event => setForm({ ...form, verify_ssl: event.target.checked })} /> Verify TLS certificate</label>}
          </div>
          {message && <div className={`mt-4 flex items-center gap-2 rounded-lg border px-3 py-2 text-xs ${message.ok ? 'border-emerald-500/20 bg-emerald-500/[0.06] text-emerald-300' : 'border-red-500/20 bg-red-500/[0.06] text-red-300'}`}>{message.ok && <CheckCircle2 size={13} />}{message.text}</div>}
          <div className="mt-5 flex gap-2"><button onClick={() => testMutation.mutate()} disabled={testMutation.isPending} className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.1] px-4 py-2 text-xs font-semibold text-zinc-200 hover:bg-white/[0.04] disabled:opacity-50">{testMutation.isPending ? <Loader2 size={13} className="animate-spin" /> : <Wifi size={13} />} Test connection</button><button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending} className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500 disabled:opacity-50">{saveMutation.isPending ? <Loader2 size={13} className="animate-spin" /> : <Save size={13} />} Save</button><button onClick={() => { setEditing(null); setAddingType(null); setMessage(null) }} className="px-3 py-2 text-xs text-zinc-500 hover:text-zinc-200">Cancel</button></div>
        </section>}

        <section className="mt-6 rounded-xl border border-white/[0.07] bg-white/[0.025] p-5">
          <div><p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-emerald-500">Placement</p><h2 className="mt-1 text-base font-semibold text-white">Floors &amp; infrastructure</h2><p className="mt-1 text-xs text-zinc-500">Assign discovered access points or switches to the floors selected in the 3D Network Map.</p></div>
          <div className="mt-5 grid gap-5 lg:grid-cols-[260px_1fr]">
            <div className="space-y-1.5">{managedFloors.length === 0 ? <a href="/network-map" className="block rounded-lg border border-dashed border-white/[0.08] px-3 py-5 text-center text-xs text-zinc-600 hover:border-emerald-500/30 hover:text-emerald-300">Choose managed floors in the map</a> : managedFloors.map(floor => <div key={floor.id} className="flex items-center gap-2 rounded-md border border-white/[0.06] bg-black/15 px-2.5 py-2"><span className="w-6 text-[10px] text-zinc-600">{floor.ordinal}</span><span className="truncate text-xs text-zinc-300">{floor.label}</span></div>)}</div>
            <div className="max-h-80 space-y-2 overflow-y-auto pr-1">
              {equipment.length === 0 && <div className="rounded-lg border border-dashed border-white/[0.08] px-4 py-8 text-center text-xs text-zinc-600">Discovered APs and switches appear here after the first successful collection.</div>}
              {equipment.map(item => <div key={item.id} className="rounded-lg border border-white/[0.06] bg-black/10 p-2.5">
                <div className="grid items-center gap-2 sm:grid-cols-[1fr_150px_72px_72px]">
                  <div className="min-w-0"><p className="truncate text-xs font-medium text-zinc-300">{item.name}</p><p className="text-[9px] uppercase tracking-wide text-zinc-600">{item.kind}</p></div>
                  <select value={item.floor_id || ''} onChange={async event => { await apiClient.put(`/network-map/equipment/${item.id}`, { floor_id: event.target.value || null }); await refreshEquipment() }} className="rounded-md border border-white/[0.07] bg-zinc-950 px-2 py-1.5 text-xs text-zinc-300"><option value="">Unassigned</option>{managedFloors.map(floor => <option key={floor.id} value={floor.id}>{floor.label}</option>)}</select>
                  <input type="number" step="0.25" defaultValue={item.position_x} title="X position" onBlur={async event => { await apiClient.put(`/network-map/equipment/${item.id}`, { position_x: Number(event.target.value) }); await refreshEquipment() }} className="rounded-md border border-white/[0.07] bg-zinc-950 px-2 py-1.5 text-xs text-zinc-300" />
                  <input type="number" step="0.25" defaultValue={item.position_z} title="Z position" onBlur={async event => { await apiClient.put(`/network-map/equipment/${item.id}`, { position_z: Number(event.target.value) }); await refreshEquipment() }} className="rounded-md border border-white/[0.07] bg-zinc-950 px-2 py-1.5 text-xs text-zinc-300" />
                </div>
                {item.kind === 'switch' && <PortOverrideEditor item={item} floors={managedFloors} onSaved={refreshEquipment} />}
              </div>)}
            </div>
          </div>
        </section>
      </div>
    </div>
  )
}

function PortOverrideEditor({ item, floors, onSaved }: { item: Equipment; floors: Floor[]; onSaved: () => Promise<unknown> }) {
  const [port, setPort] = useState('')
  const [floorId, setFloorId] = useState('')
  const [role, setRole] = useState('endpoint')
  const save = async () => {
    if (!port.trim()) return
    await apiClient.put(`/network-map/equipment/${item.id}`, {
      port_overrides: { ...item.port_overrides, [port.trim()]: { floor_id: floorId || undefined, role } },
    })
    setPort(''); setFloorId(''); setRole('endpoint'); await onSaved()
  }
  return <details className="mt-2 border-t border-white/[0.05] pt-2"><summary className="cursor-pointer text-[10px] font-medium text-zinc-500 hover:text-zinc-300">Port floor overrides · {Object.keys(item.port_overrides || {}).length}</summary><div className="mt-2 grid gap-2 sm:grid-cols-[80px_1fr_105px_auto]"><input value={port} onChange={event => setPort(event.target.value)} placeholder="Port" className="rounded-md border border-white/[0.07] bg-zinc-950 px-2 py-1.5 text-xs text-zinc-300" /><select value={floorId} onChange={event => setFloorId(event.target.value)} className="rounded-md border border-white/[0.07] bg-zinc-950 px-2 py-1.5 text-xs text-zinc-300"><option value="">Switch floor</option>{floors.map(floor => <option key={floor.id} value={floor.id}>{floor.label}</option>)}</select><select value={role} onChange={event => setRole(event.target.value)} className="rounded-md border border-white/[0.07] bg-zinc-950 px-2 py-1.5 text-xs text-zinc-300"><option value="endpoint">Endpoint</option><option value="uplink">Uplink</option><option value="infrastructure">Infrastructure</option></select><button onClick={save} className="rounded-md border border-white/[0.08] px-2.5 py-1.5 text-[10px] font-medium text-zinc-300 hover:border-emerald-500/40">Add</button></div></details>
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactElement<{ className?: string }> }) {
  return <label className="block"><span className="mb-1.5 flex items-center justify-between text-xs font-medium text-zinc-400"><span>{label}</span>{hint && <span className="font-normal text-zinc-600">{hint}</span>}</span><span className="block [&_input]:w-full [&_input]:rounded-lg [&_input]:border [&_input]:border-white/[0.08] [&_input]:bg-zinc-950 [&_input]:px-3 [&_input]:py-2.5 [&_input]:text-sm [&_input]:text-zinc-100 [&_input]:outline-none focus-within:[&_input]:border-emerald-500/60">{children}</span></label>
}
