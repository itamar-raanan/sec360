import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, Clipboard, KeyRound, Loader2, Plus, RotateCw, Server, ShieldCheck, Trash2 } from 'lucide-react'

import apiClient from '../api/client'
import { useConfirm } from '../components/shared/ConfirmDialog'
import NetworkMapTabs from '../features/networkMap/NetworkMapTabs'

interface Collector {
  id: string
  name: string
  status: string
  version: string | null
  token_prefix: string
  last_seen_at: string | null
  last_ip: string | null
  metadata: { queue_depth?: number; sources?: Record<string, { type?: string; name?: string; status?: string; last_push?: string; records?: number; error?: string }> }
  revoked_at: string | null
  created_at: string
  token?: string
}
interface Connection { id: string; connection_type: string; display_name: string; collector_id: string | null; source_identifier: string | null; managed_by_collector: boolean; status: string; last_collected_at: string | null; last_error: string | null; records_synced: number }
interface Floor { id: string; ordinal: number; label: string; managed: boolean }
interface Equipment { id: string; kind: 'ap' | 'switch'; name: string; floor_id: string | null; position_x: number; position_z: number; port_overrides: Record<string, { floor_id?: string; role?: string }>; last_seen: string | null }

function errorText(error: unknown) { return (error as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Request failed' }
function relativeTime(value: string | null) {
  if (!value) return 'Never'
  const minutes = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60_000))
  if (minutes < 1) return 'Just now'
  if (minutes < 60) return `${minutes}m ago`
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`
  return `${Math.floor(minutes / 1440)}d ago`
}

export default function NetworkMapConnections() {
  const queryClient = useQueryClient()
  const confirm = useConfirm()
  const [name, setName] = useState('')
  const [issued, setIssued] = useState<Collector | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const { data: collectors = [], isLoading } = useQuery<Collector[]>({ queryKey: ['network-map-collectors'], queryFn: () => apiClient.get('/network-map/collectors').then(response => response.data), refetchInterval: 30_000 })
  const { data: connections = [] } = useQuery<Connection[]>({ queryKey: ['network-map-connections'], queryFn: () => apiClient.get('/network-map/connections').then(response => response.data), refetchInterval: 30_000 })
  const { data: floors = [] } = useQuery<Floor[]>({ queryKey: ['network-map-floors'], queryFn: () => apiClient.get('/network-map/floors').then(response => response.data) })
  const { data: equipment = [] } = useQuery<Equipment[]>({ queryKey: ['network-map-equipment'], queryFn: () => apiClient.get('/network-map/equipment').then(response => response.data) })
  const managedFloors = floors.filter(floor => floor.managed)

  const refresh = async () => { await Promise.all([queryClient.invalidateQueries({ queryKey: ['network-map-collectors'] }), queryClient.invalidateQueries({ queryKey: ['network-map-connections'] })]) }
  const createMutation = useMutation({
    mutationFn: () => apiClient.post('/network-map/collectors', { name: name.trim() }).then(response => response.data as Collector),
    onSuccess: async result => { setIssued(result); setName(''); setMessage(null); await refresh() },
    onError: error => setMessage(errorText(error)),
  })
  const rotate = async (item: Collector) => {
    const approved = await confirm({ title: 'Rotate collector token?', message: `${item.name} will stop sending data until the new token is installed and the collector restarts.`, confirmLabel: 'Rotate token', tone: 'danger' })
    if (!approved) return
    try { const result = await apiClient.post(`/network-map/collectors/${item.id}/rotate-token`).then(response => response.data as Collector); setIssued(result); await refresh() } catch (error) { setMessage(errorText(error)) }
  }
  const revoke = async (item: Collector) => {
    const approved = await confirm({ title: 'Revoke collector?', message: `${item.name} will immediately lose push access. Retained observations remain visible until replaced.`, confirmLabel: 'Revoke', tone: 'danger' })
    if (!approved) return
    try { await apiClient.delete(`/network-map/collectors/${item.id}`); await refresh() } catch (error) { setMessage(errorText(error)) }
  }
  const refreshEquipment = () => queryClient.invalidateQueries({ queryKey: ['network-map-equipment'] })

  return <div className="h-full overflow-y-auto bg-[#070b12] px-5 py-6 text-slate-200 lg:px-8">
    <div className="mx-auto max-w-6xl">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between"><div><p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-300">Network Map</p><h1 className="mt-1 text-2xl font-semibold tracking-tight text-white">Collector configuration</h1><p className="mt-1 max-w-2xl text-sm text-slate-500">Deploy the collector inside the management network. It fetches local devices and pushes complete snapshots outbound to SEC360.</p></div><NetworkMapTabs /></div>

      <section className="mt-6 rounded-2xl border border-cyan-300/10 bg-cyan-300/[0.025] p-5">
        <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between"><div><div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.15em] text-cyan-300"><ShieldCheck size={13} /> Trust boundary</div><h2 className="mt-2 text-base font-semibold text-white">Create an on-prem collector</h2><p className="mt-1 max-w-2xl text-xs leading-5 text-slate-500">WLC, FortiGate, and MikroTik credentials stay in the collector configuration. SEC360 stores only its revocable push token and normalized observations.</p></div><div className="flex min-w-[300px] gap-2"><input value={name} onChange={event => setName(event.target.value)} onKeyDown={event => { if (event.key === 'Enter' && name.trim()) createMutation.mutate() }} placeholder="Collector name, e.g. Tel Aviv DC" className="min-w-0 flex-1 rounded-lg border border-white/[0.08] bg-black/20 px-3 py-2.5 text-xs text-white outline-none placeholder:text-slate-700 focus:border-cyan-300/40" /><button onClick={() => createMutation.mutate()} disabled={!name.trim() || createMutation.isPending} className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-300 px-3 py-2.5 text-xs font-semibold text-[#041017] disabled:opacity-40">{createMutation.isPending ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />} Create</button></div></div>
        {message && <div className="mt-4 flex items-center gap-2 rounded-lg border border-red-400/15 bg-red-400/[0.05] px-3 py-2 text-xs text-red-300"><AlertTriangle size={13} /> {message}</div>}
      </section>

      {issued?.token && <TokenPanel collector={issued} onClose={() => setIssued(null)} />}

      <section className="mt-5">
        <div className="flex items-end justify-between"><div><p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-600">Collectors</p><h2 className="mt-1 text-base font-semibold text-white">Push status</h2></div><span className="text-[10px] text-slate-600">Auto-refreshes every 30 seconds</span></div>
        <div className="mt-3 grid gap-3 lg:grid-cols-2">
          {isLoading && <div className="h-40 animate-pulse rounded-xl bg-white/[0.025]" />}
          {!isLoading && collectors.length === 0 && <div className="col-span-full rounded-xl border border-dashed border-white/[0.08] px-6 py-12 text-center text-sm text-slate-600">No collector enrolled yet.</div>}
          {collectors.map(item => <CollectorCard key={item.id} item={item} connections={connections.filter(connection => connection.collector_id === item.id)} onRotate={() => rotate(item)} onRevoke={() => revoke(item)} />)}
        </div>
      </section>

      <section className="mt-6 rounded-2xl border border-white/[0.07] bg-white/[0.025] p-5">
        <div><p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-cyan-300">Placement</p><h2 className="mt-1 text-base font-semibold text-white">Floors &amp; infrastructure</h2><p className="mt-1 text-xs text-slate-500">Assign discovered access points and switches to your managed floors. Source credentials remain on the collector.</p></div>
        <div className="mt-5 grid gap-5 lg:grid-cols-[260px_1fr]">
          <div className="space-y-1.5">{managedFloors.length === 0 ? <a href="/network-map" className="block rounded-lg border border-dashed border-white/[0.08] px-3 py-5 text-center text-xs text-slate-600 hover:border-cyan-300/30 hover:text-cyan-200">Choose managed floors in Visual</a> : managedFloors.map(floor => <div key={floor.id} className="flex items-center gap-2 rounded-md border border-white/[0.06] bg-black/15 px-2.5 py-2"><span className="w-6 text-[10px] text-slate-600">{floor.ordinal}</span><span className="truncate text-xs text-slate-300">{floor.label}</span></div>)}</div>
          <div className="max-h-96 space-y-2 overflow-y-auto pr-1">
            {equipment.length === 0 && <div className="rounded-lg border border-dashed border-white/[0.08] px-4 py-8 text-center text-xs text-slate-600">APs and switches appear after the first accepted collector snapshot.</div>}
            {equipment.map(item => <div key={item.id} className="rounded-lg border border-white/[0.06] bg-black/10 p-2.5"><div className="grid items-center gap-2 sm:grid-cols-[1fr_150px_72px_72px]"><div className="min-w-0"><p className="truncate text-xs font-medium text-slate-300">{item.name}</p><p className="text-[9px] uppercase tracking-wide text-slate-600">{item.kind} · {relativeTime(item.last_seen)}</p></div><select value={item.floor_id || ''} onChange={async event => { await apiClient.put(`/network-map/equipment/${item.id}`, { floor_id: event.target.value || null }); await refreshEquipment() }} className="rounded-md border border-white/[0.07] bg-[#070b12] px-2 py-1.5 text-xs text-slate-300"><option value="">Unassigned</option>{managedFloors.map(floor => <option key={floor.id} value={floor.id}>{floor.label}</option>)}</select><input type="number" step="0.25" defaultValue={item.position_x} title="X position" onBlur={async event => { await apiClient.put(`/network-map/equipment/${item.id}`, { position_x: Number(event.target.value) }); await refreshEquipment() }} className="rounded-md border border-white/[0.07] bg-[#070b12] px-2 py-1.5 text-xs text-slate-300" /><input type="number" step="0.25" defaultValue={item.position_z} title="Z position" onBlur={async event => { await apiClient.put(`/network-map/equipment/${item.id}`, { position_z: Number(event.target.value) }); await refreshEquipment() }} className="rounded-md border border-white/[0.07] bg-[#070b12] px-2 py-1.5 text-xs text-slate-300" /></div>{item.kind === 'switch' && <PortOverrideEditor item={item} floors={managedFloors} onSaved={refreshEquipment} />}</div>)}
          </div>
        </div>
      </section>
    </div>
  </div>
}

function TokenPanel({ collector, onClose }: { collector: Collector; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => { await navigator.clipboard.writeText(collector.token || ''); setCopied(true); window.setTimeout(() => setCopied(false), 1800) }
  return <section className="mt-5 rounded-2xl border border-amber-300/20 bg-amber-300/[0.045] p-5"><div className="flex items-start justify-between gap-4"><div><div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.15em] text-amber-300"><KeyRound size={13} /> One-time credential</div><h2 className="mt-2 text-base font-semibold text-white">Save this token now</h2><p className="mt-1 text-xs text-slate-500">It cannot be retrieved again. Put it in the collector host’s <code className="text-amber-200/80">.env</code> as <code className="text-amber-200/80">SEC360_COLLECTOR_TOKEN</code>.</p></div><button onClick={onClose} className="text-xs text-slate-500 hover:text-white">Dismiss</button></div><div className="mt-4 flex items-center gap-2 rounded-lg border border-white/[0.08] bg-black/25 p-2"><code className="min-w-0 flex-1 select-all overflow-x-auto whitespace-nowrap px-2 text-xs text-amber-100">{collector.token}</code><button onClick={copy} className="inline-flex shrink-0 items-center gap-1.5 rounded-md bg-amber-300 px-3 py-2 text-[10px] font-semibold text-[#171004]">{copied ? <Check size={12} /> : <Clipboard size={12} />}{copied ? 'Copied' : 'Copy'}</button></div><p className="mt-3 text-[10px] text-slate-600">Use <code>collector/docker-compose.yml</code> and <code>collector/config.example.yml</code> from the repository on the middle server.</p></section>
}

function CollectorCard({ item, connections, onRotate, onRevoke }: { item: Collector; connections: Connection[]; onRotate: () => void; onRevoke: () => void }) {
  const live = !item.revoked_at && item.status === 'connected'
  const sources = item.metadata.sources || {}
  return <article className={`rounded-xl border p-4 ${item.revoked_at ? 'border-red-400/10 bg-red-400/[0.02]' : 'border-white/[0.07] bg-white/[0.02]'}`}><div className="flex items-start justify-between gap-3"><div className="flex min-w-0 items-start gap-3"><span className={`rounded-lg p-2 ${live ? 'bg-emerald-400/10 text-emerald-300' : item.revoked_at ? 'bg-red-400/10 text-red-300' : 'bg-slate-400/10 text-slate-500'}`}><Server size={15} /></span><div className="min-w-0"><h3 className="truncate text-sm font-semibold text-white">{item.name}</h3><p className="mt-1 text-[10px] text-slate-600">{item.status} · last seen {relativeTime(item.last_seen_at)}{item.version ? ` · v${item.version}` : ''}</p></div></div>{!item.revoked_at && <div className="flex gap-1"><button onClick={onRotate} title="Rotate token" className="rounded-md p-2 text-slate-600 hover:bg-white/[0.05] hover:text-cyan-200"><RotateCw size={13} /></button><button onClick={onRevoke} title="Revoke collector" className="rounded-md p-2 text-slate-600 hover:bg-red-400/10 hover:text-red-300"><Trash2 size={13} /></button></div>}</div><div className="mt-4 grid grid-cols-3 gap-2 text-[10px]"><Stat label="Sources" value={String(Object.keys(sources).length || connections.length)} /><Stat label="Queued" value={String(item.metadata.queue_depth || 0)} /><Stat label="Token" value={`${item.token_prefix}…`} /></div><div className="mt-3 space-y-1.5">{connections.map(source => <div key={source.id} className="flex items-center justify-between gap-3 rounded-lg border border-white/[0.05] bg-black/10 px-3 py-2"><div className="min-w-0"><p className="truncate text-[11px] text-slate-300">{source.display_name}</p><p className="mt-0.5 truncate text-[9px] text-slate-700">{source.connection_type.replace('_', ' ')} · {source.source_identifier}</p></div><div className="text-right"><p className={`text-[10px] ${source.status === 'connected' ? 'text-emerald-300' : 'text-amber-300'}`}>{source.records_synced} records</p><p className="mt-0.5 text-[9px] text-slate-700">{relativeTime(source.last_collected_at)}</p></div></div>)}{!connections.length && !item.revoked_at && <div className="rounded-lg border border-dashed border-white/[0.06] px-3 py-4 text-center text-[10px] text-slate-700">Waiting for the first snapshot</div>}</div>{Object.values(sources).some(source => source.status === 'error' || source.error) && <div className="mt-3 flex items-start gap-2 rounded-lg border border-amber-400/10 bg-amber-400/[0.04] p-2 text-[10px] text-amber-200"><AlertTriangle size={12} className="mt-0.5 shrink-0" /> One or more local sources report an error. Check collector logs on the middle server.</div>}</article>
}
function Stat({ label, value }: { label: string; value: string }) { return <div className="rounded-lg border border-white/[0.05] bg-black/10 p-2"><p className="uppercase tracking-wider text-slate-700">{label}</p><p className="mt-1 truncate text-slate-400">{value}</p></div> }

function PortOverrideEditor({ item, floors, onSaved }: { item: Equipment; floors: Floor[]; onSaved: () => Promise<unknown> }) {
  const [port, setPort] = useState(''); const [floorId, setFloorId] = useState(''); const [role, setRole] = useState('endpoint')
  const save = async () => { if (!port.trim()) return; await apiClient.put(`/network-map/equipment/${item.id}`, { port_overrides: { ...item.port_overrides, [port.trim()]: { floor_id: floorId || undefined, role } } }); setPort(''); setFloorId(''); setRole('endpoint'); await onSaved() }
  return <details className="mt-2 border-t border-white/[0.05] pt-2"><summary className="cursor-pointer text-[10px] font-medium text-slate-500 hover:text-slate-300">Port floor overrides · {Object.keys(item.port_overrides || {}).length}</summary><div className="mt-2 grid gap-2 sm:grid-cols-[80px_1fr_105px_auto]"><input value={port} onChange={event => setPort(event.target.value)} placeholder="Port" className="rounded-md border border-white/[0.07] bg-[#070b12] px-2 py-1.5 text-xs text-slate-300" /><select value={floorId} onChange={event => setFloorId(event.target.value)} className="rounded-md border border-white/[0.07] bg-[#070b12] px-2 py-1.5 text-xs text-slate-300"><option value="">Switch floor</option>{floors.map(floor => <option key={floor.id} value={floor.id}>{floor.label}</option>)}</select><select value={role} onChange={event => setRole(event.target.value)} className="rounded-md border border-white/[0.07] bg-[#070b12] px-2 py-1.5 text-xs text-slate-300"><option value="endpoint">Endpoint</option><option value="uplink">Uplink</option><option value="infrastructure">Infrastructure</option></select><button onClick={save} className="rounded-md border border-white/[0.08] px-2.5 py-1.5 text-[10px] font-medium text-slate-300 hover:border-cyan-300/40">Add</button></div></details>
}
