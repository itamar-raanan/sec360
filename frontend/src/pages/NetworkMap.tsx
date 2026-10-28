import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Box, Building2, Check, ChevronLeft, ChevronRight, CircleDot, Network, RefreshCw, Search, Settings2, SlidersHorizontal, Wifi, X } from 'lucide-react'

import apiClient from '../api/client'
import NetworkMapScene from '../features/networkMap/NetworkMapScene'
import NetworkMapTabs from '../features/networkMap/NetworkMapTabs'
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
  const [floorManagerOpen, setFloorManagerOpen] = useState(false)
  const hasConnections = Boolean(data?.connections.length)

  const collectMutation = useMutation({
    mutationFn: async () => {
      const enabled = (data?.connections || []).filter(item => item.enabled && !item.managed_by_collector)
      await Promise.allSettled(enabled.map(item => apiClient.post(`/network-map/connections/${item.id}/collect`)))
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['network-map'] }),
  })

  const floorMutation = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: { managed?: boolean; label?: string } }) => apiClient.put(`/network-map/floors/${id}`, patch).then(response => response.data),
    onSuccess: updated => {
      queryClient.setQueryData<NetworkMapPayload>(['network-map'], current => current ? {
        ...current,
        floors: current.floors.map(floor => floor.id === updated.id ? updated : floor),
        summary: { ...current.summary, floors: current.floors.reduce((count, floor) => count + ((floor.id === updated.id ? updated.managed : floor.managed) ? 1 : 0), 0) },
      } : current)
      queryClient.invalidateQueries({ queryKey: ['network-map-floors'] })
    },
  })

  const selectedFloor = data?.floors.find(item => item.id === floorId)
  const managedFloors = useMemo(() => data?.floors.filter(item => item.managed) || [], [data])
  const selectedEquipment = data?.equipment.find(item => item.id === equipmentId) || null
  const selectedAttachment = data?.attachments.find(item => item.id === attachmentId) || null
  const floorEquipment = useMemo(() => selectedFloor?.managed ? data?.equipment.filter(item => item.floor_id === floorId) || [] : [], [data, floorId, selectedFloor?.managed])
  const floorAttachments = useMemo(() => selectedFloor?.managed ? data?.attachments.filter(item => item.floor_id === floorId) || [] : [], [data, floorId, selectedFloor?.managed])
  const results = useMemo(() => {
    const needle = search.trim().toLowerCase()
    if (!needle || !data) return []
    const managedIds = new Set(data.floors.filter(floor => floor.managed).map(floor => floor.id))
    return data.attachments.filter(item => item.floor_id && managedIds.has(item.floor_id) && [item.mac_address, item.endpoint.hostname, item.endpoint.ip_address, item.endpoint.owner, item.ssid, item.port, item.vlan].some(value => String(value || '').toLowerCase().includes(needle))).slice(0, 12)
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

      <header className="pointer-events-none absolute inset-x-0 top-0 z-10 flex items-start justify-between gap-4 border-b border-white/[0.06] bg-[#030913]/95 px-5 py-5 lg:px-7">
        <div><div className="ui-context flex items-center gap-2"><Network size={13} /> 3D Network Map <span className="ui-status-chip ml-1">{hasConnections ? 'Live' : 'Preview'}</span></div><div className="mt-1.5 flex items-center gap-2"><h1 className="ui-page-title">{selectedFloor ? selectedFloor.label : 'Building overview'}</h1>{selectedFloor && !selectedFloor.managed && <span className="ui-status-chip">Available</span>}</div><p className="ui-page-description !mt-2">{selectedFloor ? (selectedFloor.managed ? `${floorAttachments.length} observed endpoints · ${floorEquipment.length} infrastructure devices` : `Floor ${selectedFloor.ordinal} · not currently managed`) : `${data.summary.building_floors} floors · ${data.summary.floors} managed · ${data.summary.endpoints} observed endpoints`}</p></div>
        <div className="pointer-events-auto flex items-center gap-2">
          <div className="hidden rounded-xl border border-cyan-100/[0.09] bg-[#07111c]/65 px-3.5 py-2.5 text-[10px] text-slate-400 shadow-[0_16px_50px_rgba(0,0,0,.28)] backdrop-blur-xl md:flex md:items-center md:gap-4"><span className="flex items-center gap-1.5"><span className="h-px w-7 border-t border-dashed border-cyan-300" /> Wi-Fi</span><span className="flex items-center gap-1.5"><span className="h-px w-7 bg-teal-300" /> Ethernet</span></div>
          {user?.role === 'admin' && <button onClick={() => setFloorManagerOpen(true)} className="ui-secondary-button"><SlidersHorizontal size={14} /> Manage floors</button>}
          <NetworkMapTabs floating />
          {user?.role !== 'viewer' && data.connections.some(item => item.enabled && !item.managed_by_collector) && <button onClick={() => collectMutation.mutate()} disabled={collectMutation.isPending} className="ui-icon-button" title="Refresh direct topology sources"><RefreshCw size={15} className={collectMutation.isPending ? 'animate-spin' : ''} /></button>}
        </div>
      </header>

      <aside className="absolute bottom-5 left-5 top-32 z-10 w-60 overflow-hidden rounded-2xl border border-cyan-100/[0.08] bg-[#07111c]/82 shadow-[0_24px_80px_rgba(0,0,0,.42),inset_0_1px_0_rgba(255,255,255,.04)] backdrop-blur-2xl lg:left-7">
        <div className="border-b border-white/[0.06] p-3">
          <div className="relative"><Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600" /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Find endpoint…" className="w-full rounded-lg border border-white/[0.07] bg-black/25 py-2 pl-8 pr-3 text-xs text-zinc-200 outline-none placeholder:text-zinc-700 focus:border-emerald-500/50" /></div>
        </div>
        <div className="h-[calc(100%-57px)] overflow-y-auto p-2">
          {search.trim() ? <div className="space-y-1">{results.length === 0 && <p className="px-2 py-5 text-center text-xs text-zinc-600">No endpoint matches</p>}{results.map(item => <button key={item.id} onClick={() => selectAttachment(item.id)} className="w-full rounded-lg px-2.5 py-2 text-left hover:bg-white/[0.04]"><span className="block truncate text-xs font-medium text-zinc-300">{labelForAttachment(item)}</span><span className="mt-0.5 block text-[10px] text-zinc-600">{item.mac_address} · {item.match_state.replace(/_/g, ' ')}</span></button>)}</div> : <>
            <button onClick={() => { setFloorId(null); setEquipmentId(null); setAttachmentId(null) }} className={`mb-1 flex w-full items-center gap-2 rounded-lg px-2.5 py-2.5 text-left text-xs ${floorId === null ? 'bg-emerald-500/10 text-emerald-300' : 'text-zinc-400 hover:bg-white/[0.04]'}`}><Box size={14} /> Building overview</button>
            <div className="flex items-center justify-between px-2.5 pb-1 pt-3"><p className="text-[9px] font-semibold uppercase tracking-[0.15em] text-zinc-700">My floors</p><span className="text-[9px] tabular-nums text-cyan-300/60">{managedFloors.length}/31</span></div>
            {managedFloors.length === 0 && <button onClick={() => setFloorManagerOpen(true)} className="mx-1 my-2 w-[calc(100%-8px)] rounded-lg border border-dashed border-cyan-200/[0.12] px-3 py-4 text-center text-[10px] leading-4 text-slate-500 transition-colors hover:border-cyan-200/25 hover:text-cyan-100">Choose the floors your team manages</button>}
            {managedFloors.slice().reverse().map(floor => {
              const count = data.attachments.filter(item => item.floor_id === floor.id).length
              return <button key={floor.id} onClick={() => { setFloorId(floor.id); setEquipmentId(null); setAttachmentId(null) }} className={`flex w-full items-center justify-between rounded-lg px-2.5 py-2 text-left text-xs ${floorId === floor.id ? 'bg-cyan-500/10 text-cyan-300' : 'text-zinc-400 hover:bg-white/[0.04]'}`}><span>{floor.label}</span><span className="text-[10px] text-zinc-600">{count}</span></button>
            })}
            {data.summary.unassigned_equipment > 0 && <div className="mt-3 rounded-lg border border-amber-500/15 bg-amber-500/[0.04] p-2.5"><p className="text-[10px] font-medium text-amber-300">{data.summary.unassigned_equipment} unassigned devices</p><p className="mt-1 text-[9px] leading-3 text-zinc-600">Assign them to a floor in Config.</p></div>}
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

      {!hasConnections && <section className="absolute right-5 top-24 z-10 w-[min(310px,calc(100%-40px))] rounded-2xl border border-cyan-200/[0.10] bg-[#07111c]/82 p-4 shadow-[0_24px_70px_rgba(0,0,0,.38),inset_0_1px_0_rgba(255,255,255,.05)] backdrop-blur-2xl lg:right-7">
        <div className="flex items-start gap-3"><span className="mt-0.5 rounded-lg border border-cyan-300/15 bg-cyan-300/[0.07] p-2 text-cyan-200"><Box size={14} /></span><div className="min-w-0"><p className="text-xs font-semibold text-white">Exploring in preview mode</p><p className="mt-1 text-[10px] leading-4 text-slate-400">Select any floor to inspect its 3D layout. Live access points, switches, endpoints, and traffic paths will appear when a source is connected.</p>{user?.role === 'admin' && <a href="/network-map/config" className="mt-3 inline-flex items-center gap-1.5 text-[10px] font-semibold text-cyan-200 transition-colors hover:text-white"><Settings2 size={12} /> Configure when ready</a>}</div></div>
      </section>}

      {floorManagerOpen && user?.role === 'admin' && <FloorManager floors={data.floors} pending={floorMutation.isPending} onChange={(id, patch) => floorMutation.mutate({ id, patch })} onClose={() => setFloorManagerOpen(false)} />}

      <div className="pointer-events-none absolute bottom-5 left-1/2 z-10 hidden -translate-x-1/2 items-center gap-2 rounded-full border border-cyan-100/[0.07] bg-[#07111c]/58 px-3.5 py-2 text-[9px] font-medium tracking-wide text-slate-500 shadow-lg backdrop-blur-xl xl:flex"><span className="h-1.5 w-1.5 rounded-full bg-cyan-300/70 shadow-[0_0_10px_rgba(103,232,249,.65)]" /> Select a floor to focus · Select a device for details</div>

      {selectedFloor && <div className="absolute bottom-5 right-5 z-10 flex items-center gap-2 rounded-full border border-white/[0.08] bg-[#07111c]/72 p-1.5 shadow-xl backdrop-blur-xl lg:right-7"><button onClick={() => { const index = data.floors.findIndex(item => item.id === floorId); setFloorId(data.floors[Math.max(0, index - 1)]?.id || floorId) }} className="rounded-full p-1.5 text-zinc-500 transition-colors hover:bg-white/[0.06] hover:text-white" aria-label="Previous floor"><ChevronLeft size={14} /></button><span className="min-w-28 text-center text-[10px] font-medium text-zinc-300"><span className="text-cyan-300/70">{String(selectedFloor.ordinal).padStart(2, '0')}</span> · {selectedFloor.label}</span><button onClick={() => { const index = data.floors.findIndex(item => item.id === floorId); setFloorId(data.floors[Math.min(data.floors.length - 1, index + 1)]?.id || floorId) }} className="rounded-full p-1.5 text-zinc-500 transition-colors hover:bg-white/[0.06] hover:text-white" aria-label="Next floor"><ChevronRight size={14} /></button></div>}

      {(selectedAttachment || selectedEquipment) && <DetailDrawer attachment={selectedAttachment} equipment={selectedEquipment} endpointCount={selectedEquipment ? data.attachments.filter(item => item.equipment_id === selectedEquipment.id).length : 0} connections={data.connections} onClose={() => { setAttachmentId(null); setEquipmentId(null) }} />}

    </div>
  )
}

function FloorManager({ floors, pending, onChange, onClose }: { floors: NetworkMapPayload['floors']; pending: boolean; onChange: (id: string, patch: { managed?: boolean; label?: string }) => void; onClose: () => void }) {
  return <aside className="absolute bottom-4 right-4 top-20 z-30 flex w-[min(390px,calc(100%-32px))] flex-col overflow-hidden rounded-2xl border border-cyan-100/[0.11] bg-[#07111c]/95 shadow-[0_32px_100px_rgba(0,0,0,.62),inset_0_1px_0_rgba(255,255,255,.05)] backdrop-blur-2xl lg:right-7 lg:top-24">
    <div className="flex items-start justify-between border-b border-white/[0.06] px-5 py-4"><div><div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-cyan-300"><Building2 size={13} /> Building directory</div><h2 className="mt-1.5 text-lg font-semibold tracking-[-0.02em] text-white">Manage your floors</h2><p className="mt-1 text-[10px] leading-4 text-slate-500">Select the floors you operate, then give each one the name your team uses.</p></div><button onClick={onClose} className="rounded-lg p-2 text-slate-600 transition-colors hover:bg-white/[0.05] hover:text-white" aria-label="Close floor manager"><X size={15} /></button></div>
    <div className="flex items-center justify-between border-b border-white/[0.05] px-5 py-2.5 text-[9px] uppercase tracking-[0.14em] text-slate-600"><span>{floors.filter(floor => floor.managed).length} of 31 managed</span><span className={pending ? 'text-cyan-300' : 'text-emerald-400/70'}>{pending ? 'Saving…' : 'Saved'}</span></div>
    <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-3 py-2">{floors.slice().reverse().map(floor => <div key={floor.id} className={`group my-1 flex items-center gap-3 rounded-xl border px-3 py-2.5 transition-colors duration-200 ${floor.managed ? 'border-cyan-300/[0.14] bg-cyan-300/[0.055]' : 'border-transparent hover:border-white/[0.05] hover:bg-white/[0.025]'}`}>
      <button onClick={() => onChange(floor.id, { managed: !floor.managed })} className={`grid h-5 w-5 shrink-0 place-items-center rounded-md border transition-[background-color,border-color,color] duration-200 ${floor.managed ? 'border-cyan-300/60 bg-cyan-300 text-[#041017]' : 'border-white/[0.13] bg-black/20 text-slate-900 [&_svg]:opacity-0 hover:border-cyan-300/35'}`} aria-label={`${floor.managed ? 'Remove' : 'Manage'} floor ${floor.ordinal}`}><Check size={12} strokeWidth={3} /></button>
      <span className={`w-7 text-right text-[10px] font-semibold tabular-nums ${floor.managed ? 'text-cyan-300/80' : 'text-slate-700'}`}>{String(floor.ordinal).padStart(2, '0')}</span>
      <input defaultValue={floor.label} key={`${floor.id}:${floor.label}`} disabled={!floor.managed} onBlur={event => { const label = event.target.value.trim(); if (label && label !== floor.label) onChange(floor.id, { label }) }} className="min-w-0 flex-1 border-0 bg-transparent px-1 py-1 text-xs text-slate-200 outline-none placeholder:text-slate-700 disabled:text-slate-600" aria-label={`Name for floor ${floor.ordinal}`} />
    </div>)}</div>
    <div className="border-t border-white/[0.06] p-3"><button onClick={onClose} className="ui-primary-button ui-button-lg w-full">Done</button></div>
  </aside>
}

function DetailDrawer({ attachment, equipment, endpointCount, connections, onClose }: { attachment: MapAttachment | null; equipment: MapEquipment | null; endpointCount: number; connections: NetworkMapPayload['connections']; onClose: () => void }) {
  const item = attachment?.endpoint
  const connection = equipment ? connections.find(row => row.id === equipment.connection_id) : null
  return <aside className="absolute bottom-5 right-5 top-28 z-20 w-[min(360px,calc(100%-40px))] overflow-y-auto rounded-xl border border-white/[0.09] bg-[#0b111b]/95 p-5 shadow-2xl backdrop-blur-xl lg:right-7"><button onClick={onClose} className="absolute right-3 top-3 rounded-md p-1.5 text-zinc-600 hover:bg-white/[0.05] hover:text-white" aria-label="Close details"><X size={14} /></button>{attachment ? <><div className="flex items-center gap-2"><span className={`rounded-md p-1.5 ${attachment.attachment_type === 'wireless' ? 'bg-cyan-500/10 text-cyan-300' : 'bg-teal-500/10 text-teal-300'}`}>{attachment.attachment_type === 'wireless' ? <Wifi size={14} /> : <CircleDot size={14} />}</span><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">{attachment.attachment_type} endpoint</p></div><h2 className="mt-3 break-words text-lg font-semibold text-white">{labelForAttachment(attachment)}</h2><span className={`mt-2 inline-flex rounded-full px-2 py-1 text-[10px] ${attachment.match_state === 'matched' ? 'bg-emerald-500/10 text-emerald-300' : attachment.match_state === 'ambiguous' ? 'bg-amber-500/10 text-amber-300' : 'bg-zinc-500/10 text-zinc-400'}`}>{attachment.match_state === 'no_current_match' ? 'No current Puppet match' : attachment.match_state}</span><dl className="mt-5 space-y-3">{[['MAC address', attachment.mac_address], ['IP address', item?.ip_address], ['Owner', item?.owner || item?.username], ['Operating system', item?.os_version], ['SSID', attachment.ssid], ['Switch port', attachment.port], ['VLAN', attachment.vlan], ['Last observed', relativeTime(attachment.observed_at)]].map(([label, value]) => value ? <div key={label} className="flex items-start justify-between gap-4 border-b border-white/[0.05] pb-3"><dt className="text-xs text-zinc-600">{label}</dt><dd className="max-w-[60%] break-words text-right text-xs text-zinc-300">{value}</dd></div> : null)}</dl>{item?.products.length ? <div className="mt-4 flex flex-wrap gap-1.5">{item.products.map(product => <span key={product} className="rounded-md border border-white/[0.07] px-2 py-1 text-[10px] text-zinc-400">{product}</span>)}</div> : null}</> : equipment ? <><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-emerald-400">{equipment.kind === 'ap' ? 'Access point' : 'Switch'}</p><h2 className="mt-2 text-lg font-semibold text-white">{equipment.name}</h2><dl className="mt-5 space-y-3">{[['Source', connection?.name], ['Status', connection?.status], ['Endpoints', String(endpointCount)], ['Last observed', relativeTime(equipment.last_seen)]].map(([label, value]) => <div key={label} className="flex justify-between gap-4 border-b border-white/[0.05] pb-3"><dt className="text-xs text-zinc-600">{label}</dt><dd className="text-xs text-zinc-300">{value}</dd></div>)}</dl></> : null}</aside>
}
