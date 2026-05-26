import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { format, formatDistanceToNow } from 'date-fns'
import {
  Search,
  User,
  Monitor,
  Activity,
  Shield,
  ShieldOff,
  AlertTriangle,
  ChevronRight,
  LogIn,
  Globe,
  Wifi,
  MonitorSmartphone,
  CheckCircle,
  XCircle,
} from 'lucide-react'
import RiskBadge from '../components/shared/RiskBadge'
import StatusBadge from '../components/shared/StatusBadge'
import SearchBar from '../components/shared/SearchBar'
import apiClient from '../api/client'
import type { User as UserType, Endpoint, SearchResults, ActivityEvent } from '../types'

type TabKey = 'overview' | 'activity' | 'devices'

function UserPanel({ user }: { user: UserType }) {
  const [tab, setTab] = useState<TabKey>('overview')

  const { data: timeline } = useQuery({
    queryKey: ['user', user.id, 'timeline'],
    queryFn: async () => {
      const res = await apiClient.get<ActivityEvent[]>(`/users/${user.id}/timeline`, {
        params: { days: 14 },
      })
      return res.data
    },
    enabled: tab === 'activity',
  })

  const { data: devices } = useQuery({
    queryKey: ['user', user.id, 'devices'],
    queryFn: async () => {
      const res = await apiClient.get<Endpoint[]>(`/users/${user.id}/devices`)
      return res.data
    },
    enabled: tab === 'devices',
  })

  return (
    <div className="rounded-xl overflow-hidden card">
      {/* Header */}
      <div className="p-5" style={{ borderBottom: "1px solid var(--border)" }}>
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 bg-emerald-900 rounded-full flex items-center justify-center text-emerald-300 text-lg font-bold flex-shrink-0">
            {user.full_name[0]}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-lg font-semibold text-white">{user.full_name}</h2>
              <RiskBadge score={user.risk_score} />
              <StatusBadge status={user.employment_status} />
            </div>
            <div className="text-sm text-gray-400 mt-0.5">{user.email}</div>
            <div className="flex gap-4 mt-2 text-xs text-gray-500">
              {user.department && <span>{user.department}</span>}
              {user.manager && <span>Reports to: {user.manager}</span>}
              {user.last_login && (
                <span>Last login: {formatDistanceToNow(new Date(user.last_login), { addSuffix: true })}</span>
              )}
            </div>
          </div>
          <div className="flex-shrink-0">
            {user.mfa_enabled ? (
              <div className="flex items-center gap-1 text-emerald-300 text-xs">
                <Shield size={14} />
                MFA On
              </div>
            ) : (
              <div className="flex items-center gap-1 text-red-400 text-xs">
                <ShieldOff size={14} />
                No MFA
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-800">
        {(['overview', 'activity', 'devices'] as TabKey[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-5 py-3 text-sm font-medium capitalize transition-colors border-b-2 ${
              tab === t
                ? 'text-emerald-400 border-emerald-500'
                : 'text-gray-500 border-transparent hover:text-gray-300'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="p-5">
        {tab === 'overview' && (
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'Risk Score', value: <RiskBadge score={user.risk_score} /> },
              { label: 'MFA', value: user.mfa_enabled ? '✓ Enabled' : '✗ Disabled' },
              { label: 'Department', value: user.department || '—' },
              { label: 'Manager', value: user.manager || '—' },
              { label: 'Status', value: <StatusBadge status={user.employment_status} /> },
              { label: 'Member Since', value: format(new Date(user.created_at), 'MMM d, yyyy') },
            ].map(({ label, value }) => (
              <div key={label} className="p-3 bg-gray-800/50 rounded-lg">
                <div className="text-xs text-gray-500 mb-1">{label}</div>
                <div className="text-sm text-white">{value}</div>
              </div>
            ))}
          </div>
        )}

        {tab === 'activity' && (
          <div className="space-y-2">
            {!timeline ? (
              <div className="text-sm text-gray-500">Loading...</div>
            ) : timeline.length === 0 ? (
              <div className="text-sm text-gray-500">No recent activity</div>
            ) : (
              timeline.map((e) => (
                <div
                  key={e.id}
                  className={`flex items-center gap-3 p-2.5 rounded-lg ${
                    e.is_suspicious ? 'bg-red-500/5 border border-red-500/20' : 'bg-gray-800/40'
                  }`}
                >
                  <div className="text-gray-500 flex-shrink-0">
                    {e.event_type === 'login' ? <LogIn size={14} /> :
                     e.event_type === 'network' ? <Globe size={14} /> :
                     e.event_type === 'vpn' ? <Wifi size={14} /> :
                     <MonitorSmartphone size={14} />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-300 capitalize">{e.event_type.replace('_', ' ')}</span>
                      {e.country && <span className="text-xs text-gray-500">{e.country}</span>}
                      {e.is_suspicious && <AlertTriangle size={11} className="text-red-400" />}
                    </div>
                    {e.ip_address && (
                      <div className="text-xs text-gray-600 font-mono">{e.ip_address}</div>
                    )}
                  </div>
                  <div className="text-xs text-gray-500 flex-shrink-0">
                    {format(new Date(e.timestamp), 'MMM d HH:mm')}
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {tab === 'devices' && (
          <div className="space-y-3">
            {!devices ? (
              <div className="text-sm text-gray-500">Loading...</div>
            ) : devices.length === 0 ? (
              <div className="text-sm text-gray-500">No devices found</div>
            ) : (
              devices.map((d) => (
                <div key={d.id} className="p-3.5 bg-gray-800/50 rounded-lg border border-gray-700/50">
                  <div className="flex items-center gap-3">
                    <Monitor size={16} className="text-gray-400" />
                    <div>
                      <div className="text-sm font-medium text-white">{d.hostname}</div>
                      <div className="text-xs text-gray-500">{d.os_version} · {d.ip_address}</div>
                    </div>
                    {d.compliance_status && (
                      <StatusBadge status={d.compliance_status.status} />
                    )}
                  </div>
                  {d.agents && d.agents.length > 0 && (
                    <div className="flex gap-1 mt-2">
                      {d.agents.map((a) => (
                        <span
                          key={a.id}
                          className={`text-xs px-1.5 py-0.5 rounded border ${
                            a.status === 'active'
                              ? 'border-green-500/30 text-emerald-300 bg-emerald-500/10'
                              : 'border-red-500/30 text-red-400 bg-red-500/10'
                          }`}
                        >
                          {a.product_name}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function EndpointPanel({ endpoint }: { endpoint: Endpoint }) {
  const cs = endpoint.compliance_status

  const checks = cs ? [
    { label: 'EDR Installed',  value: cs.edr_installed },
    { label: 'EDR Up-to-date', value: cs.edr_version_ok },
    { label: 'DLP Installed',  value: cs.dlp_installed },
    { label: 'DLP Up-to-date', value: cs.dlp_version_ok },
  ] : []

  return (
    <div className="rounded-xl overflow-hidden card">
      <div className="p-5" style={{ borderBottom: "1px solid var(--border)" }}>
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 bg-purple-900 rounded-lg flex items-center justify-center flex-shrink-0">
            <Monitor size={20} className="text-purple-300" />
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-lg font-semibold text-white">{endpoint.hostname}</h2>
              {cs && <StatusBadge status={cs.status} />}
              <RiskBadge score={endpoint.risk_score} />
            </div>
            <div className="text-sm text-gray-400 mt-0.5">{endpoint.os_version}</div>
            <div className="flex gap-4 mt-2 text-xs text-gray-500">
              {endpoint.ip_address && <span>{endpoint.ip_address}</span>}
              {endpoint.location && <span>{endpoint.location}</span>}
              {endpoint.last_seen && (
                <span>Last seen: {formatDistanceToNow(new Date(endpoint.last_seen), { addSuffix: true })}</span>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="p-5 space-y-4">
        {/* Compliance checks */}
        {cs && (
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Compliance Checks</div>
            <div className="space-y-1.5">
              {checks.map(({ label, value }) => (
                <div key={label} className="flex items-center gap-2">
                  {value ? (
                    <CheckCircle size={14} className="text-emerald-300" />
                  ) : (
                    <XCircle size={14} className="text-red-400" />
                  )}
                  <span className={`text-sm ${value ? 'text-gray-300' : 'text-red-400'}`}>{label}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Agents */}
        {endpoint.agents && endpoint.agents.length > 0 && (
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Security Agents</div>
            <div className="space-y-1.5">
              {endpoint.agents.map((a) => (
                <div key={a.id} className="flex items-center gap-3 p-2.5 bg-gray-800/50 rounded-lg">
                  <Shield size={14} className={a.status === 'active' ? 'text-emerald-300' : 'text-red-400'} />
                  <span className="text-sm text-white capitalize">{a.product_name}</span>
                  <span className={`text-xs px-1.5 py-0.5 rounded ${
                    a.status === 'active' ? 'bg-emerald-500/15 text-emerald-300' : 'bg-red-500/15 text-red-400'
                  }`}>
                    {a.status}
                  </span>
                  {a.version && <span className="text-xs text-gray-500 ml-auto">{a.version}</span>}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Owner */}
        {endpoint.owner && (
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Assigned User</div>
            <div className="flex items-center gap-3 p-2.5 bg-gray-800/50 rounded-lg">
              <User size={14} className="text-emerald-400" />
              <div>
                <div className="text-sm text-white">{endpoint.owner.full_name}</div>
                <div className="text-xs text-gray-500">{endpoint.owner.email}</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function Investigation() {
  const [query, setQuery] = useState('')
  const [submitted, setSubmitted] = useState('')
  const [selectedUser, setSelectedUser] = useState<UserType | null>(null)
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(null)

  const { data: searchResults, isLoading } = useQuery({
    queryKey: ['search', submitted],
    queryFn: async () => {
      const res = await apiClient.get<SearchResults>('/search', { params: { q: submitted } })
      return res.data
    },
    enabled: submitted.length > 0,
  })

  const handleSearch = () => {
    if (query.trim()) {
      setSubmitted(query.trim())
      setSelectedUser(null)
      setSelectedEndpoint(null)
    }
  }

  return (
    <div className="absolute inset-0 overflow-y-auto p-6">
    <div className="space-y-5">
      {/* Search */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h2 className="text-sm font-semibold text-white mb-3">Search Users & Devices</h2>
        <div className="flex gap-3">
          <SearchBar
            placeholder="Search by user name, email, or device hostname..."
            value={query}
            onChange={setQuery}
            onSearch={handleSearch}
            className="flex-1"
          />
          <button
            onClick={handleSearch}
            disabled={!query.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-900 text-white text-sm font-medium rounded-lg pressable"
          >
            <Search size={16} />
            Search
          </button>
        </div>
      </div>

      {/* Results */}
      {submitted && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Left: search results */}
          <div className="space-y-4">
            {isLoading ? (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-2">
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="flex gap-3 px-3 py-3.5" style={{ borderBottom: "1px solid var(--border)" }}><div className="w-7 h-7 shimmer rounded-full flex-shrink-0" style={{ animationDelay: `${i*35}ms` }} /><div className="flex-1 space-y-1.5"><div className="h-3 shimmer rounded w-32" style={{ animationDelay: `${i*35+20}ms` }} /><div className="h-2.5 shimmer rounded w-48 opacity-50" style={{ animationDelay: `${i*35+35}ms` }} /></div></div>
                ))}
              </div>
            ) : (
              <>
                {/* Users */}
                {searchResults?.users && searchResults.users.length > 0 && (
                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                    <div className="text-xs text-gray-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                      <User size={12} />
                      Users ({searchResults.users.length})
                    </div>
                    <div className="space-y-1">
                      {searchResults.users.map((u) => (
                        <button
                          key={u.id}
                          onClick={() => { setSelectedUser(u); setSelectedEndpoint(null) }}
                          className={`w-full flex items-center gap-3 p-2.5 rounded-lg text-left transition-colors ${
                            selectedUser?.id === u.id ? 'bg-emerald-500/10 border border-emerald-500/15' : 'hover:bg-gray-800'
                          }`}
                        >
                          <div className="w-8 h-8 bg-emerald-900 rounded-full flex items-center justify-center text-emerald-300 text-xs font-bold flex-shrink-0">
                            {u.full_name[0]}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="text-sm text-white font-medium truncate">{u.full_name}</div>
                            <div className="text-xs text-gray-500 truncate">{u.department}</div>
                          </div>
                          <RiskBadge score={u.risk_score} />
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Endpoints */}
                {searchResults?.endpoints && searchResults.endpoints.length > 0 && (
                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                    <div className="text-xs text-gray-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                      <Monitor size={12} />
                      Devices ({searchResults.endpoints.length})
                    </div>
                    <div className="space-y-1">
                      {searchResults.endpoints.map((ep) => (
                        <button
                          key={ep.id}
                          onClick={() => { setSelectedEndpoint(ep); setSelectedUser(null) }}
                          className={`w-full flex items-center gap-3 p-2.5 rounded-lg text-left transition-colors ${
                            selectedEndpoint?.id === ep.id ? 'bg-purple-600/15 border border-emerald-500/20' : 'hover:bg-gray-800'
                          }`}
                        >
                          <Monitor size={16} className="text-gray-500 flex-shrink-0" />
                          <div className="flex-1 min-w-0">
                            <div className="text-sm text-white font-medium truncate">{ep.hostname}</div>
                            <div className="text-xs text-gray-500 truncate">{ep.os_version}</div>
                          </div>
                          {ep.compliance_status && (
                            <StatusBadge status={ep.compliance_status.status} />
                          )}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {searchResults?.users.length === 0 && searchResults?.endpoints.length === 0 && (
                  <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center text-gray-500 text-sm">
                    No results for "{submitted}"
                  </div>
                )}
              </>
            )}
          </div>

          {/* Right: detail panel */}
          <div className="lg:col-span-2">
            {selectedUser && <UserPanel user={selectedUser} />}
            {selectedEndpoint && <EndpointPanel endpoint={selectedEndpoint} />}
            {!selectedUser && !selectedEndpoint && searchResults && (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 flex flex-col items-center justify-center text-center">
                <Search size={32} className="text-gray-700 mb-3" />
                <div className="text-gray-500 text-sm">Select a user or device to view details</div>
              </div>
            )}
          </div>
        </div>
      )}

      {!submitted && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-16 flex flex-col items-center justify-center text-center">
          <Search size={40} className="text-gray-700 mb-4" />
          <div className="text-white font-medium mb-2">Investigate Users & Devices</div>
          <div className="text-gray-500 text-sm max-w-sm">
            Search for a user by name or email, or a device by hostname or IP address to begin your investigation.
          </div>
        </div>
      )}
    </div>
    </div>
  )
}
