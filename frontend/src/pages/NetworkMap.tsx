import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Box, ChevronLeft, ChevronRight, CircleDot, Map, Network, RefreshCw, Search, Settings2, Wifi, X } from 'lucide-react'

import apiClient from '../api/client'
import NetworkMapScene from '../features/networkMap/NetworkMapScene'
import type { MapAttachment, MapEquipment, NetworkMapPayload } from '../features/networkMap/types'
import { useAuthStore } from '../store/auth'

function relativeTime(value: string | null) {
  if (!value) return 'Never collected'
  const minutes = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60_000))
  if (minutes < 1) return 'Just now'
  if (minutes < 60) return `${minutes}m ago`
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`
  return `${Math.floor(minutes / 1440)}d ago`
}

function labelForAttachment(item: MapAttachment) {
  return item.endpoint.hostname || item.endpoint.ip_address || item.mac_address
}

export default function NetworkMapPage() {
  const { user } = useAuthStore()
  const queryClient = useQueryClient()
  const { data, isLoading, isError, error } = useQuery<NetworkMapPayload>({
    queryKey: ['network-map'],
    queryFn: () => apiClient.get('/network-map').then(response => response.data),
    refetchInterval: 60_000,
  })
  const [floorId, setFloorId] = useState<string | null>(null)
  const [equipmentId, setEquipmentId] = useState<string | null>(null)
  const [attachmentId, setAttachmentId] = useState<string | null>(null)
  const [search, setSearch] = useState('')

  const collectMutation = useMutation({
    mutationFn: async () => {
      const enabled = (data?.connections || []).filter(item => item.enabled)
      await Promise.allSettled(enabled.map(item => apiClient.post(`/network-map/connections/${item.id}/collect`)))
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['network-map'] }),
  })

  const selectedFloor = data?.floors.find(item => item.id === floorId)
  const selectedEquipment = data?.equipment.find(item => item.id === equipmentId) || null
  const selectedAttachment = data?.attachments.find(item => item.id === attachmentId) || null
  const floorEquipment = useMemo(() => data?.equipment.filter(item => item.floor_id === floorId) || [], [data, floorId])
  const floorAttachments = useMemo(() => data?.attachments.filter(item => item.floor_id === floorId) || [], [data, floorId])
  const results = useMemo(() => {
    const needle = search.trim().toLowerCase()
    if (!needle || !data) return []
    return data.attachments.filter(item => [item.mac_address, item.endpoint.hostname, item.endpoint.ip_address, item.endpoint.owner, item.ssid, item.port, item.vlan].some(value => String(value || '').toLowerCase().includes(needle))).slice(0, 12)
  }, [data, search])

  const selectAttachment = (id: string) => {
    const item = data?.attachments.find(row => row.id === id)
    if (item?.floor_id) setFloorId(item.floor_id)
    setEquipmentId(item?.equipment_id || null)
    setAttachmentId(id)
  }

  if (isLoading) return <div className="h-full overflow-hidden p-5 lg:p-7"><div className="h-full animate-pulse rounded-2xl border border-white/[0.06] bg-white/[0.025]" /></div>
  if (isError || !data) return <div className="flex h-full items-center justify-center p-8"><div className="max-w-md text-center"><AlertTriangle className="mx-auto text-red-400" /><h1 className="mt-3 text-lg font-semibold text-white">Network Map could not load</h1><p className="mt-1 text-sm text-zinc-500">{(error as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'The latest retained topology is temporarily unavailable.'}</p></div></div>

  return (
    <div className="network-map-dark relative h-full overflow-hidden bg-[#070b12]">
      <NetworkMapScene
        floors={data.floors}
        equipment={data.equipment}
        attachments={data.attachments}
        selectedFloorId={floorId}
        selectedEquipmentId={equipmentId}
        selectedAttachmentId={attachmentId}
        onSelectFloor={id => { setFloorId(id); setEquipmentId(null); setAttachmentId(null) }}
        onSelectEquipment={id => { setEquipmentId(id); setAttachmentId(null) }}
        onSelectAttachment={selectAttachment}
      />

      <header className="pointer-events-none absolute inset-x-0 top-0 z-10 flex items-start justify-between gap-4 bg-gradient-to-b from-[#030913] via-[#030913]/88 to-transparent px-5 pb-16 pt-5 lg:px-7">
        <div><div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-300"><Network size={13} /> 3D Network Map <span className="ml-1 rounded border border-cyan-300/20 bg-cyan-300/[0.06] px-1.5 py-0.5 text-[8px] tracking-[0.12em] text-cyan-200/80">Live</span></div><h1 className="mt-1.5 text-[28px] font-semibold leading-none tracking-[-0.03em] text-white">{selectedFloor ? selectedFloor.label : 'Building overview'}</h1><p className="mt-2 text-xs text-slate-400">{selectedFloor ? `${floorAttachments.length} observed endpoints · ${floorEquipment.length} infrastructure devices` : `${data.summary.floors} floors · ${data.summary.endpoints} observed endpoints`}</p></div>
        <div className="pointer-events-auto flex items-center gap-2">
          <div className="hidden rounded-xl border border-cyan-100/[0.09] bg-[#07111c]/65 px-3.5 py-2.5 text-[10px] text-slate-400 shadow-[0_16px_50px_rgba(0,0,0,.28)] backdrop-blur-xl md:flex md:items-center md:gap-4"><span className="flex items-center gap-1.5"><span className="h-px w-7 border-t border-dashed border-cyan-300" /> Wi-Fi</span><span className="flex items-center gap-1.5"><span className="h-px w-7 bg-teal-300" /> Ethernet</span></div>
          {user?.role === 'admin' && <a href="/network-map/connections" className="rounded-xl border border-cyan-100/[0.09] bg-[#07111c]/65 p-2.5 text-slate-400 shadow-[0_16px_50px_rgba(0,0,0,.28)] backdrop-blur-xl transition-[color,transform,border-color] duration-200 hover:border-cyan-300/25 hover:text-white active:scale-[.97]" title="Network Map connections"><Settings2 size={15} /></a>}
          {user?.role !== 'viewer' && <button onClick={() => collectMutation.mutate()} disabled={collectMutation.isPending || !data.connections.some(item => item.enabled)} className="rounded-xl border border-cyan-100/[0.09] bg-[#07111c]/65 p-2.5 text-slate-400 shadow-[0_16px_50px_rgba(0,0,0,.28)] backdrop-blur-xl transition-[color,transform,border-color] duration-200 hover:border-cyan-300/25 hover:text-white active:scale-[.97] disabled:opacity-40" title="Refresh topology"><RefreshCw size={15} className={collectMutation.isPending ? 'animate-spin' : ''} /></button>}
        </div>
      </header>

      <aside className="absolute bottom-5 left-5 top-32 z-10 w-60 overflow-hidden rounded-2xl border border-cyan-100/[0.08] bg-[#07111c]/82 shadow-[0_24px_80px_rgba(0,0,0,.42),inset_0_1px_0_rgba(255,255,255,.04)] backdrop-blur-2xl lg:left-7">
        <div className="border-b border-white/[0.06] p-3">
          <div className="relative"><Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600" /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Find endpoint…" className="w-full rounded-lg border border-white/[0.07] bg-black/25 py-2 pl-8 pr-3 text-xs text-zinc-200 outline-none placeholder:text-zinc-700 focus:border-emerald-500/50" /></div>
        </div>
        <div className="h-[calc(100%-57px)] overflow-y-auto p-2">
          {search.trim() ? <div className="space-y-1">{results.length === 0 && <p className="px-2 py-5 text-center text-xs text-zinc-600">No endpoint matches</p>}{results.map(item => <button key={item.id} onClick={() => selectAttachment(item.id)} className="w-full rounded-lg px-2.5 py-2 text-left hover:bg-white/[0.04]"><span className="block truncate text-xs font-medium text-zinc-300">{labelForAttachment(item)}</span><span className="mt-0.5 block text-[10px] text-zinc-600">{item.mac_address} · {item.match_state.replace(/_/g, ' ')}</span></button>)}</div> : <>
            <button onClick={() => { setFloorId(null); setEquipmentId(null); setAttachmentId(null) }} className={`mb-1 flex w-full items-center gap-2 rounded-lg px-2.5 py-2.5 text-left text-xs ${floorId === null ? 'bg-emerald-500/10 text-emerald-300' : 'text-zinc-400 hover:bg-white/[0.04]'}`}><Box size={14} /> Building overview</button>
            <p className="px-2.5 pb-1 pt-3 text-[9px] font-semibold uppercase tracking-[0.15em] text-zinc-700">Floors</p>
            {data.floors.slice().reverse().map(floor => {
              const count = data.attachments.filter(item => item.floor_id === floor.id).length
              return <button key={floor.id} onClick={() => { setFloorId(floor.id); setEquipmentId(null); setAttachmentId(null) }} className={`flex w-full items-center justify-between rounded-lg px-2.5 py-2 text-left text-xs ${floorId === floor.id ? 'bg-emerald-500/10 text-emerald-300' : 'text-zinc-400 hover:bg-white/[0.04]'}`}><span>{floor.label}</span><span className="text-[10px] text-zinc-600">{count}</span></button>
            })}
            {data.summary.unassigned_equipment > 0 && <div className="mt-3 rounded-lg border border-amber-500/15 bg-amber-500/[0.04] p-2.5"><p className="text-[10px] font-medium text-amber-300">{data.summary.unassigned_equipment} unassigned devices</p><p className="mt-1 text-[9px] leading-3 text-zinc-600">Assign them to a floor in Connections.</p></div>}
            {selectedFloor && <>
              <p className="px-2.5 pb-1 pt-4 text-[9px] font-semibold uppercase tracking-[0.15em] text-zinc-700">Infrastructure</p>
              {floorEquipment.map(item => <button key={item.id} onClick={() => { setEquipmentId(item.id); setAttachmentId(null) }} className="flex w-full items-center justify-between rounded-lg px-2.5 py-2 text-left hover:bg-white/[0.04]"><span className="truncate text-xs text-zinc-400">{item.name}</span><span className="text-[9px] uppercase text-zinc-700">{item.kind}</span></button>)}
              <p className="px-2.5 pb-1 pt-4 text-[9px] font-semibold uppercase tracking-[0.15em] text-zinc-700">Observed endpoints</p>
              {floorAttachments.slice(0, 100).map(item => <button key={item.id} onClick={() => selectAttachment(item.id)} className="w-full rounded-lg px-2.5 py-2 text-left hover:bg-white/[0.04]"><span className="block truncate text-xs text-zinc-400">{labelForAttachment(item)}</span><span className="mt-0.5 block truncate text-[9px] text-zinc-700">{item.mac_address}</span></button>)}
              {floorAttachments.length > 100 && <p className="px-2.5 py-2 text-[9px] text-zinc-700">Showing 100 of {floorAttachments.length}; use search for the rest.</p>}
            </>}
          </>}
        </div>
      </aside>

      {data.connections.some(item => item.status === 'error') && <div className="absolute bottom-5 left-64 z-10 hidden max-w-sm rounded-lg border border-amber-500/20 bg-[#17130b]/90 px-3 py-2 text-[10px] text-amber-200 backdrop-blur md:block lg:left-72"><AlertTriangle size={12} className="mr-1.5 inline" />Some sources failed. The map is showing retained data from successful snapshots.</div>}

      <div className="pointer-events-none absolute bottom-5 left-1/2 z-10 hidden -translate-x-1/2 items-center gap-2 rounded-full border border-cyan-100/[0.07] bg-[#07111c]/58 px-3.5 py-2 text-[9px] font-medium tracking-wide text-slate-500 shadow-lg backdrop-blur-xl xl:flex"><span className="h-1.5 w-1.5 rounded-full bg-cyan-300/70 shadow-[0_0_10px_rgba(103,232,249,.65)]" /> Drag to orbit · Scroll to zoom · Select a floor or device</div>

      {selectedFloor && <div className="absolute bottom-5 right-5 z-10 flex items-center gap-2 rounded-lg border border-white/[0.08] bg-black/40 p-1.5 backdrop-blur lg:right-7"><button onClick={() => { const index = data.floors.findIndex(item => item.id === floorId); setFloorId(data.floors[Math.max(0, index - 1)]?.id || floorId) }} className="rounded-md p-1.5 text-zinc-500 hover:bg-white/[0.05] hover:text-white" aria-label="Previous floor"><ChevronLeft size={14} /></button><span className="min-w-20 text-center text-[10px] font-medium text-zinc-300">{selectedFloor.label}</span><button onClick={() => { const index = data.floors.findIndex(item => item.id === floorId); setFloorId(data.floors[Math.min(data.floors.length - 1, index + 1)]?.id || floorId) }} className="rounded-md p-1.5 text-zinc-500 hover:bg-white/[0.05] hover:text-white" aria-label="Next floor"><ChevronRight size={14} /></button></div>}

      {(selectedAttachment || selectedEquipment) && <DetailDrawer attachment={selectedAttachment} equipment={selectedEquipment} endpointCount={selectedEquipment ? data.attachments.filter(item => item.equipment_id === selectedEquipment.id).length : 0} connections={data.connections} onClose={() => { setAttachmentId(null); setEquipmentId(null) }} />}

      {!data.connections.length && <div className="absolute inset-0 z-20 flex items-center justify-center bg-[#070b12]/70 backdrop-blur-sm"><div className="max-w-sm rounded-2xl border border-white/[0.08] bg-[#0b111b] p-7 text-center shadow-2xl"><Map className="mx-auto text-emerald-400" size={24} /><h2 className="mt-4 text-base font-semibold text-white">Connect your network sources</h2><p className="mt-2 text-sm leading-5 text-zinc-500">Add Cisco WLC, FortiGate, or MikroTik SwOS connections to begin building the topology.</p>{user?.role === 'admin' && <a href="/network-map/connections" className="mt-5 inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-2.5 text-xs font-semibold text-white hover:bg-emerald-500"><Settings2 size={13} /> Configure connections</a>}</div></div>}
    </div>
  )
}

function DetailDrawer({ attachment, equipment, endpointCount, connections, onClose }: { attachment: MapAttachment | null; equipment: MapEquipment | null; endpointCount: number; connections: NetworkMapPayload['connections']; onClose: () => void }) {
  const item = attachment?.endpoint
  const connection = equipment ? connections.find(row => row.id === equipment.connection_id) : null
  return <aside className="absolute bottom-5 right-5 top-28 z-20 w-[min(360px,calc(100%-40px))] overflow-y-auto rounded-xl border border-white/[0.09] bg-[#0b111b]/95 p-5 shadow-2xl backdrop-blur-xl lg:right-7"><button onClick={onClose} className="absolute right-3 top-3 rounded-md p-1.5 text-zinc-600 hover:bg-white/[0.05] hover:text-white" aria-label="Close details"><X size={14} /></button>{attachment ? <><div className="flex items-center gap-2"><span className={`rounded-md p-1.5 ${attachment.attachment_type === 'wireless' ? 'bg-cyan-500/10 text-cyan-300' : 'bg-teal-500/10 text-teal-300'}`}>{attachment.attachment_type === 'wireless' ? <Wifi size={14} /> : <CircleDot size={14} />}</span><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">{attachment.attachment_type} endpoint</p></div><h2 className="mt-3 break-words text-lg font-semibold text-white">{labelForAttachment(attachment)}</h2><span className={`mt-2 inline-flex rounded-full px-2 py-1 text-[10px] ${attachment.match_state === 'matched' ? 'bg-emerald-500/10 text-emerald-300' : attachment.match_state === 'ambiguous' ? 'bg-amber-500/10 text-amber-300' : 'bg-zinc-500/10 text-zinc-400'}`}>{attachment.match_state === 'no_current_match' ? 'No current Puppet match' : attachment.match_state}</span><dl className="mt-5 space-y-3">{[['MAC address', attachment.mac_address], ['IP address', item?.ip_address], ['Owner', item?.owner || item?.username], ['Operating system', item?.os_version], ['SSID', attachment.ssid], ['Switch port', attachment.port], ['VLAN', attachment.vlan], ['Last observed', relativeTime(attachment.observed_at)]].map(([label, value]) => value ? <div key={label} className="flex items-start justify-between gap-4 border-b border-white/[0.05] pb-3"><dt className="text-xs text-zinc-600">{label}</dt><dd className="max-w-[60%] break-words text-right text-xs text-zinc-300">{value}</dd></div> : null)}</dl>{item?.products.length ? <div className="mt-4 flex flex-wrap gap-1.5">{item.products.map(product => <span key={product} className="rounded-md border border-white/[0.07] px-2 py-1 text-[10px] text-zinc-400">{product}</span>)}</div> : null}</> : equipment ? <><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-emerald-400">{equipment.kind === 'ap' ? 'Access point' : 'Switch'}</p><h2 className="mt-2 text-lg font-semibold text-white">{equipment.name}</h2><dl className="mt-5 space-y-3">{[['Source', connection?.name], ['Status', connection?.status], ['Endpoints', String(endpointCount)], ['Last observed', relativeTime(equipment.last_seen)]].map(([label, value]) => <div key={label} className="flex justify-between gap-4 border-b border-white/[0.05] pb-3"><dt className="text-xs text-zinc-600">{label}</dt><dd className="text-xs text-zinc-300">{value}</dd></div>)}</dl></> : null}</aside>
}
