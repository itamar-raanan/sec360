import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ChevronDown, CircleDot, RadioTower, Search, Server, Wifi } from 'lucide-react'

import apiClient from '../api/client'
import NetworkMapTabs from '../features/networkMap/NetworkMapTabs'
import type { NetworkMapPayload, NetworkTableEntity } from '../features/networkMap/types'

function relativeTime(value: string | null) {
  if (!value) return 'Never'
  const minutes = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60_000))
  if (minutes < 1) return 'Now'
  if (minutes < 60) return `${minutes}m`
  if (minutes < 1440) return `${Math.floor(minutes / 60)}h`
  return `${Math.floor(minutes / 1440)}d`
}

export default function NetworkMapTable() {
  const { data, isLoading, isError } = useQuery<NetworkMapPayload>({ queryKey: ['network-map'], queryFn: () => apiClient.get('/network-map').then(response => response.data), refetchInterval: 60_000 })
  const [search, setSearch] = useState('')
  const [attachmentType, setAttachmentType] = useState('all')
  const [match, setMatch] = useState('all')
  const [floor, setFloor] = useState('all')
  const [expanded, setExpanded] = useState<string | null>(null)

  const equipment = useMemo(() => new Map((data?.equipment || []).map(item => [item.id, item])), [data])
  const floors = useMemo(() => new Map((data?.floors || []).map(item => [item.id, item])), [data])
  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return (data?.table_entities || []).filter(item => {
      if (attachmentType !== 'all' && item.attachment_type !== attachmentType) return false
      if (match !== 'all' && item.match_state !== match) return false
      if (floor !== 'all' && (item.floor_id || 'unassigned') !== floor) return false
      if (!needle) return true
      return [item.endpoint.hostname, item.endpoint.username, item.endpoint.owner, item.endpoint.ip_address, item.mac_address, item.ssid, item.port, item.vlan, item.equipment_id ? equipment.get(item.equipment_id)?.name : null].some(value => String(value || '').toLowerCase().includes(needle))
    }).sort((a, b) => new Date(b.observed_at).getTime() - new Date(a.observed_at).getTime())
  }, [attachmentType, data, equipment, floor, match, search])

  if (isLoading) return <div className="h-full overflow-hidden p-6"><div className="h-full animate-pulse rounded-2xl bg-white/[0.025]" /></div>
  if (isError || !data) return <div className="flex h-full items-center justify-center text-sm text-red-300"><AlertTriangle size={16} className="mr-2" /> Network data could not load.</div>

  return <div className="h-full overflow-y-auto bg-[#070b12] px-5 py-6 text-slate-200 lg:px-8">
    <div className="mx-auto max-w-[1600px]">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div><p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-300">Network Map</p><h1 className="mt-1 text-2xl font-semibold tracking-tight text-white">Connected entities</h1><p className="mt-1 text-sm text-slate-500">One operational view of discovered clients, their network attachment, identity match, products, and source evidence.</p></div>
        <NetworkMapTabs />
      </div>

      <section className="mt-6 grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Metric label="Observed" value={data.table_entities.length} icon={CircleDot} />
        <Metric label="Matched" value={data.table_entities.filter(item => item.match_state === 'matched').length} icon={Server} />
        <Metric label="Wireless" value={data.table_entities.filter(item => item.attachment_type === 'wireless').length} icon={Wifi} />
        <Metric label="Infrastructure" value={data.equipment.length} icon={RadioTower} />
      </section>

      <section className="mt-4 overflow-hidden rounded-2xl border border-white/[0.07] bg-[#0a111b]">
        <div className="flex flex-wrap gap-2 border-b border-white/[0.06] p-3">
          <div className="relative min-w-[220px] flex-1"><Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600" /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search hostname, user, IP, MAC, SSID, switch…" className="w-full rounded-lg border border-white/[0.07] bg-black/20 py-2.5 pl-9 pr-3 text-xs text-white outline-none placeholder:text-slate-700 focus:border-cyan-300/35" /></div>
          <Select value={attachmentType} onChange={setAttachmentType} options={[['all', 'All observations'], ['wireless', 'Wi-Fi'], ['wired', 'Ethernet'], ['dhcp', 'DHCP only']]} />
          <Select value={match} onChange={setMatch} options={[['all', 'All identities'], ['matched', 'Matched'], ['ambiguous', 'Ambiguous'], ['no_current_match', 'Unmatched']]} />
          <Select value={floor} onChange={setFloor} options={[['all', 'All floors'], ['unassigned', 'Unassigned'], ...data.floors.filter(item => item.managed).map(item => [item.id, item.label])]} />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[1220px] border-collapse text-left">
            <thead><tr className="border-b border-white/[0.06] text-[9px] font-semibold uppercase tracking-[0.14em] text-slate-600">{['State', 'Endpoint / identity', 'MAC & IP', 'Connection', 'Network', 'Floor', 'Compliance signal', 'Products', 'Last seen', ''].map(label => <th key={label} className="px-4 py-3">{label}</th>)}</tr></thead>
            <tbody>{rows.map(item => <TableRow key={item.id} item={item} equipmentName={item.equipment_id ? equipment.get(item.equipment_id)?.name || 'Unknown device' : 'No attachment device'} floorName={item.floor_id ? floors.get(item.floor_id)?.label || 'Unknown' : 'Unassigned'} expanded={expanded === item.id} onToggle={() => setExpanded(expanded === item.id ? null : item.id)} />)}</tbody>
          </table>
          {rows.length === 0 && <div className="px-5 py-16 text-center text-sm text-slate-600">No entities match these filters.</div>}
        </div>
        <div className="border-t border-white/[0.06] px-4 py-3 text-[10px] text-slate-600">Showing {rows.length} current network observations · complete snapshots replace prior source state.</div>
      </section>
    </div>
  </div>
}

function TableRow({ item, equipmentName, floorName, expanded, onToggle }: { item: NetworkTableEntity; equipmentName: string; floorName: string; expanded: boolean; onToggle: () => void }) {
  const label = item.endpoint.hostname || item.endpoint.ip_address || item.mac_address
  return <><tr onClick={onToggle} className="cursor-pointer border-b border-white/[0.045] text-xs transition-colors hover:bg-white/[0.025]">
    <td className="px-4 py-3"><span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-1 text-[10px] ${item.match_state === 'matched' ? 'bg-emerald-400/10 text-emerald-300' : item.match_state === 'ambiguous' ? 'bg-amber-400/10 text-amber-300' : 'bg-slate-400/10 text-slate-400'}`}><span className="h-1.5 w-1.5 rounded-full bg-current" />{item.match_state === 'no_current_match' ? 'Unmatched' : item.match_state}</span></td>
    <td className="px-4 py-3"><p className="max-w-52 truncate font-medium text-slate-200">{label}</p><p className="mt-1 max-w-52 truncate text-[10px] text-slate-600">{item.endpoint.owner || item.endpoint.username || 'No owner'}</p></td>
    <td className="px-4 py-3 font-mono text-[10px] text-slate-500"><p>{item.mac_address}</p><p className="mt-1 text-slate-600">{item.endpoint.ip_address || '—'}</p></td>
    <td className="px-4 py-3"><p className="max-w-44 truncate text-slate-300">{equipmentName}</p><p className="mt-1 text-[10px] capitalize text-cyan-300/60">{item.attachment_type}</p></td>
    <td className="px-4 py-3 text-[10px] text-slate-500">{item.attachment_type === 'wireless' ? <><p>{item.ssid || 'Unknown SSID'}</p><p className="mt-1">{item.state || 'Wi-Fi'}</p></> : item.attachment_type === 'wired' ? <><p>Port {item.port || '—'}</p><p className="mt-1">VLAN {item.vlan || '—'}</p></> : <><p>DHCP lease</p><p className="mt-1">Awaiting network attachment</p></>}</td>
    <td className="px-4 py-3 text-slate-400">{floorName}</td>
    <td className="px-4 py-3"><span className={`text-[10px] ${item.endpoint.id ? 'text-cyan-300' : 'text-slate-600'}`}>{item.endpoint.id ? `Risk ${Math.round(item.endpoint.risk_score || 0)}` : 'No endpoint match'}</span></td>
    <td className="px-4 py-3"><div className="flex max-w-48 flex-wrap gap-1">{item.endpoint.products.length ? item.endpoint.products.slice(0, 3).map(product => <span key={product} className="rounded border border-white/[0.07] px-1.5 py-0.5 text-[9px] text-slate-500">{product}</span>) : <span className="text-slate-700">—</span>}</div></td>
    <td className="px-4 py-3 text-[10px] text-slate-500">{relativeTime(item.observed_at)}</td>
    <td className="px-4 py-3"><ChevronDown size={13} className={`text-slate-600 transition-transform ${expanded ? 'rotate-180' : ''}`} /></td>
  </tr>{expanded && <tr className="border-b border-cyan-300/10 bg-cyan-300/[0.025]"><td colSpan={10} className="px-4 py-4"><div className="grid gap-4 text-[10px] sm:grid-cols-3 lg:grid-cols-6">{[['Observation ID', item.id], ['Endpoint ID', item.endpoint.id || 'Not correlated'], ['OS', item.endpoint.os_version || 'Unknown'], ['SSID', item.ssid || '—'], ['Port / VLAN', [item.port, item.vlan].filter(Boolean).join(' / ') || '—'], ['Observed at', new Date(item.observed_at).toLocaleString()]].map(([key, value]) => <div key={key}><p className="uppercase tracking-wider text-slate-700">{key}</p><p className="mt-1 break-all text-slate-400">{value}</p></div>)}</div></td></tr>}</>
}

function Metric({ label, value, icon: Icon }: { label: string; value: number; icon: typeof CircleDot }) { return <div className="rounded-xl border border-white/[0.07] bg-white/[0.025] p-3"><div className="flex items-center justify-between"><p className="text-[10px] uppercase tracking-wider text-slate-600">{label}</p><Icon size={13} className="text-cyan-300/50" /></div><p className="mt-2 text-xl font-semibold text-white">{value.toLocaleString()}</p></div> }
function Select({ value, onChange, options }: { value: string; onChange: (value: string) => void; options: string[][] }) { return <select value={value} onChange={event => onChange(event.target.value)} className="rounded-lg border border-white/[0.07] bg-[#090f18] px-3 py-2 text-xs text-slate-400 outline-none focus:border-cyan-300/35">{options.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select> }
