import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  FileText, Download, Send, Plus, Trash2, Play, Clock, ToggleLeft, ToggleRight,
  ChevronDown, AlertCircle, X, Filter, Calendar, Printer,
} from 'lucide-react'
import apiClient from '../api/client'

// ── Types ─────────────────────────────────────────────────────────────────────

type ReportType = 'compliance' | 'risk' | 'users' | 'endpoints' | 'activity'
type Frequency = 'daily' | 'weekly' | 'monthly'

interface ReportRow { headers: string[]; rows: string[][] }

interface ScheduledReport {
  id: string
  name: string
  report_type: ReportType
  frequency: Frequency
  recipients: string[]
  filters: Record<string, unknown>
  is_active: boolean
  last_sent: string | null
  next_send: string | null
  created_by: string
  created_at: string
}

const TYPE_LABELS: Record<ReportType, string> = {
  compliance: 'Compliance',
  risk: 'Risk',
  users: 'Users',
  endpoints: 'Endpoints',
  activity: 'Activity',
}

const TYPE_COLORS: Record<ReportType, string> = {
  compliance: 'blue',
  risk:       'red',
  users:      'purple',
  endpoints:  'orange',
  activity:   'green',
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function buildFilters(type: ReportType, filterState: Record<string, string>): Record<string, unknown> {
  const f: Record<string, unknown> = {}
  if (type === 'compliance' && filterState.status) f.status = filterState.status
  if (type === 'risk') {
    if (filterState.min_score) f.min_score = Number(filterState.min_score)
    if (filterState.entity) f.entity = filterState.entity
  }
  if (type === 'users') {
    if (filterState.department) f.department = filterState.department
    if (filterState.risk_min) f.risk_min = Number(filterState.risk_min)
  }
  if (type === 'endpoints' && filterState.compliance_status) f.compliance_status = filterState.compliance_status
  if (type === 'activity') {
    if (filterState.days) f.days = Number(filterState.days)
    if (filterState.event_type) f.event_type = filterState.event_type
    if (filterState.suspicious_only) f.suspicious_only = filterState.suspicious_only === 'true'
  }
  return f
}

function fmtDate(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })
}

// ── Filter panel per report type ──────────────────────────────────────────────

function FilterPanel({
  type, filters, onChange,
}: { type: ReportType; filters: Record<string, string>; onChange: (k: string, v: string) => void }) {
  const inp = 'w-full bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-1.5 text-xs focus:outline-none focus:border-emerald-500'

  if (type === 'compliance') return (
    <div>
      <label className="block text-xs text-zinc-400 mb-1">Status</label>
      <select value={filters.status ?? ''} onChange={e => onChange('status', e.target.value)} className={inp}>
        <option value="">All</option>
        <option value="compliant">Compliant</option>
        <option value="partial">Partial</option>
        <option value="non_compliant">Non-compliant</option>
      </select>
    </div>
  )

  if (type === 'risk') return (
    <div className="grid grid-cols-2 gap-2">
      <div>
        <label className="block text-xs text-zinc-400 mb-1">Min risk score</label>
        <input type="number" min={0} max={100} value={filters.min_score ?? ''} onChange={e => onChange('min_score', e.target.value)} placeholder="0" className={inp} />
      </div>
      <div>
        <label className="block text-xs text-zinc-400 mb-1">Entity</label>
        <select value={filters.entity ?? ''} onChange={e => onChange('entity', e.target.value)} className={inp}>
          <option value="">All</option>
          <option value="users">Users only</option>
          <option value="endpoints">Endpoints only</option>
        </select>
      </div>
    </div>
  )

  if (type === 'users') return (
    <div className="grid grid-cols-2 gap-2">
      <div>
        <label className="block text-xs text-zinc-400 mb-1">Department</label>
        <input value={filters.department ?? ''} onChange={e => onChange('department', e.target.value)} placeholder="e.g. Engineering" className={inp} />
      </div>
      <div>
        <label className="block text-xs text-zinc-400 mb-1">Min risk score</label>
        <input type="number" min={0} max={100} value={filters.risk_min ?? ''} onChange={e => onChange('risk_min', e.target.value)} placeholder="0" className={inp} />
      </div>
    </div>
  )

  if (type === 'endpoints') return (
    <div>
      <label className="block text-xs text-zinc-400 mb-1">Compliance status</label>
      <select value={filters.compliance_status ?? ''} onChange={e => onChange('compliance_status', e.target.value)} className={inp}>
        <option value="">All</option>
        <option value="compliant">Compliant</option>
        <option value="partial">Partial</option>
        <option value="non_compliant">Non-compliant</option>
      </select>
    </div>
  )

  if (type === 'activity') return (
    <div className="grid grid-cols-3 gap-2">
      <div>
        <label className="block text-xs text-zinc-400 mb-1">Days back</label>
        <input type="number" min={1} max={90} value={filters.days ?? '7'} onChange={e => onChange('days', e.target.value)} className={inp} />
      </div>
      <div>
        <label className="block text-xs text-zinc-400 mb-1">Event type</label>
        <input value={filters.event_type ?? ''} onChange={e => onChange('event_type', e.target.value)} placeholder="e.g. login" className={inp} />
      </div>
      <div>
        <label className="block text-xs text-zinc-400 mb-1">Suspicious only</label>
        <select value={filters.suspicious_only ?? ''} onChange={e => onChange('suspicious_only', e.target.value)} className={inp}>
          <option value="">All</option>
          <option value="true">Yes</option>
        </select>
      </div>
    </div>
  )

  return null
}

// ── Schedule modal ────────────────────────────────────────────────────────────

function ScheduleModal({
  onClose, onSave, initial,
}: {
  onClose: () => void
  onSave: (data: { name: string; report_type: string; frequency: string; recipients: string[]; filters: Record<string, unknown> }) => void
  initial?: ScheduledReport
}) {
  const [name, setName] = useState(initial?.name ?? '')
  const [type, setType] = useState<ReportType>((initial?.report_type as ReportType) ?? 'compliance')
  const [frequency, setFrequency] = useState<Frequency>(initial?.frequency ?? 'weekly')
  const [recipientInput, setRecipientInput] = useState(initial?.recipients.join(', ') ?? '')
  const [filterState, setFilterState] = useState<Record<string, string>>({})
  const [err, setErr] = useState('')

  const inp = 'w-full bg-zinc-950 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-emerald-500'

  const handleSave = () => {
    const recipients = recipientInput.split(',').map(s => s.trim()).filter(Boolean)
    if (!name.trim()) { setErr('Name is required'); return }
    if (!recipients.length) { setErr('At least one recipient is required'); return }
    const badEmails = recipients.filter(e => !e.includes('@'))
    if (badEmails.length) { setErr(`Invalid email: ${badEmails[0]}`); return }
    onSave({ name: name.trim(), report_type: type, frequency, recipients, filters: buildFilters(type, filterState) })
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-zinc-950 border border-white/[0.08] rounded-2xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/[0.06]">
          <h2 className="text-sm font-semibold text-white">{initial ? 'Edit scheduled report' : 'Schedule a report'}</h2>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-300"><X size={16} /></button>
        </div>
        <div className="px-6 py-5 space-y-4">
          {err && <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 text-red-400 text-xs px-3 py-2 rounded-lg"><AlertCircle size={13} />{err}</div>}
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Report name</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Weekly Compliance Summary" className={inp} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Report type</label>
              <select value={type} onChange={e => { setType(e.target.value as ReportType); setFilterState({}) }} className={inp}>
                {Object.entries(TYPE_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Frequency</label>
              <select value={frequency} onChange={e => setFrequency(e.target.value as Frequency)} className={inp}>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-zinc-400 mb-1">Recipients (comma-separated)</label>
            <input value={recipientInput} onChange={e => setRecipientInput(e.target.value)} placeholder="alice@co.com, bob@co.com" className={inp} />
          </div>
          <div>
            <label className="block text-xs text-zinc-400 mb-2 flex items-center gap-1"><Filter size={11} /> Filters</label>
            <FilterPanel type={type} filters={filterState} onChange={(k, v) => setFilterState(p => ({ ...p, [k]: v }))} />
          </div>
        </div>
        <div className="flex gap-2 px-6 py-4 border-t border-white/[0.06]">
          <button onClick={handleSave}
            className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium px-4 py-2 rounded-lg pressable">
            <Calendar size={14} /> {initial ? 'Save changes' : 'Schedule report'}
          </button>
          <button onClick={onClose} className="text-sm text-zinc-400 hover:text-white px-3 py-2">Cancel</button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Reports() {
  const qc = useQueryClient()

  // Ad-hoc report state
  const [reportType, setReportType] = useState<ReportType>('compliance')
  const [filterState, setFilterState] = useState<Record<string, string>>({})
  const [preview, setPreview] = useState<ReportRow | null>(null)
  const [previewMeta, setPreviewMeta] = useState<{ count: number; truncated: boolean } | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewErr, setPreviewErr] = useState('')

  // Scheduled reports state
  const [showScheduleModal, setShowScheduleModal] = useState(false)
  const [editTarget, setEditTarget] = useState<ScheduledReport | null>(null)
  const [sendFeedback, setSendFeedback] = useState<Record<string, string>>({})

  const { data: scheduled = [] } = useQuery<ScheduledReport[]>({
    queryKey: ['scheduled-reports'],
    queryFn: () => apiClient.get('/reports/scheduled').then(r => r.data),
  })

  const createSchedule = useMutation({
    mutationFn: (d: object) => apiClient.post('/reports/scheduled', d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scheduled-reports'] }); setShowScheduleModal(false) },
  })

  const updateSchedule = useMutation({
    mutationFn: ({ id, ...d }: { id: string } & object) => apiClient.patch(`/reports/scheduled/${id}`, d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scheduled-reports'] }); setEditTarget(null) },
  })

  const toggleSchedule = useMutation({
    mutationFn: (id: string) => apiClient.patch(`/reports/scheduled/${id}/toggle`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scheduled-reports'] }),
  })

  const deleteSchedule = useMutation({
    mutationFn: (id: string) => apiClient.delete(`/reports/scheduled/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scheduled-reports'] }),
  })

  const sendNow = useMutation({
    mutationFn: (id: string) => apiClient.post(`/reports/scheduled/${id}/send-now`),
    onSuccess: (res, id) => {
      qc.invalidateQueries({ queryKey: ['scheduled-reports'] })
      const rows = res.data?.rows ?? 0
      setSendFeedback(p => ({ ...p, [id]: `Sent (${rows} rows)` }))
      setTimeout(() => setSendFeedback(p => { const n = { ...p }; delete n[id]; return n }), 4000)
    },
    onError: (_, id) => {
      setSendFeedback(p => ({ ...p, [id]: 'Failed to send' }))
      setTimeout(() => setSendFeedback(p => { const n = { ...p }; delete n[id]; return n }), 4000)
    },
  })

  const handleGenerate = async () => {
    setPreviewLoading(true)
    setPreviewErr('')
    setPreview(null)
    try {
      const filters = JSON.stringify(buildFilters(reportType, filterState))
      const res = await apiClient.get(`/reports/generate?report_type=${reportType}&filters=${encodeURIComponent(filters)}`)
      setPreview({ headers: res.data.headers, rows: res.data.rows })
      setPreviewMeta({ count: res.data.row_count, truncated: res.data.truncated })
    } catch {
      setPreviewErr('Failed to generate report')
    } finally {
      setPreviewLoading(false)
    }
  }

  const handleExportCSV = () => {
    const filters = JSON.stringify(buildFilters(reportType, filterState))
    const url = `/api/reports/export/csv?report_type=${reportType}&filters=${encodeURIComponent(filters)}`
    window.open(url, '_blank')
  }

  const handlePrint = () => {
    if (!preview) return
    const title = `${TYPE_LABELS[reportType]} Report — ${new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}`
    const tableRows = preview.rows.map(row =>
      `<tr>${row.map(cell => `<td>${String(cell).replace(/</g, '&lt;')}</td>`).join('')}</tr>`
    ).join('')
    const html = `<!DOCTYPE html><html><head><title>${title}</title><style>
      body{font-family:system-ui,sans-serif;font-size:12px;color:#111;padding:24px}
      h1{font-size:18px;font-weight:700;margin-bottom:4px}
      p{color:#666;margin-bottom:16px;font-size:11px}
      table{width:100%;border-collapse:collapse}
      th{background:#f3f4f6;text-align:left;padding:6px 10px;font-size:10px;text-transform:uppercase;letter-spacing:.05em;border-bottom:2px solid #e5e7eb}
      td{padding:6px 10px;border-bottom:1px solid #f3f4f6;vertical-align:top}
      tr:nth-child(even) td{background:#fafafa}
    </style></head><body>
      <h1>${title}</h1>
      <p>${preview.rows.length} rows · Generated by SEC360</p>
      <table><thead><tr>${preview.headers.map(h => `<th>${h}</th>`).join('')}</tr></thead>
      <tbody>${tableRows}</tbody></table>
    </body></html>`
    const w = window.open('', '_blank')
    if (!w) return
    w.document.write(html)
    w.document.close()
    w.focus()
    w.print()
  }

  const handleTypeChange = (t: ReportType) => {
    setReportType(t)
    setFilterState({})
    setPreview(null)
    setPreviewErr('')
  }

  const colorCls = (color: string) => ({
    blue:   'bg-emerald-500/10 text-emerald-400 border-emerald-500/15',
    red:    'bg-red-500/10 text-red-400 border-red-500/20',
    purple: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    orange: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    green:  'bg-emerald-500/10 text-emerald-300 border-green-500/20',
  })[color] ?? ''

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-white">Reports</h1>
        <p className="text-sm text-zinc-500 mt-1">Generate, export, and schedule security reports.</p>
      </div>

      {/* ── Ad-hoc report ── */}
      <div className="bg-zinc-950 border border-white/[0.06] rounded-2xl p-6">
        <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <FileText size={15} className="text-emerald-400" /> Generate report
        </h2>

        {/* Type pills */}
        <div className="flex flex-wrap gap-2 mb-5">
          {(Object.keys(TYPE_LABELS) as ReportType[]).map(t => (
            <button key={t} onClick={() => handleTypeChange(t)}
              className={`px-3.5 py-1.5 rounded-full text-xs font-medium border transition-colors ${
                reportType === t
                  ? colorCls(TYPE_COLORS[t])
                  : 'border-white/[0.08] text-zinc-500 hover:text-zinc-300 hover:border-gray-600'
              }`}>
              {TYPE_LABELS[t]}
            </button>
          ))}
        </div>

        {/* Filters */}
        <div className="bg-zinc-900/50 border border-white/[0.08] rounded-xl p-4 mb-4">
          <p className="text-xs text-zinc-400 mb-3 flex items-center gap-1.5"><Filter size={11} /> Filters</p>
          <FilterPanel type={reportType} filters={filterState} onChange={(k, v) => setFilterState(p => ({ ...p, [k]: v }))} />
        </div>

        {/* Actions */}
        <div className="flex gap-2">
          <button onClick={handleGenerate} disabled={previewLoading}
            className="flex items-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-emerald-900 disabled:cursor-not-allowed text-white text-sm font-medium px-4 py-2 rounded-lg pressable">
            {previewLoading ? 'Generating…' : <><ChevronDown size={14} /> Generate preview</>}
          </button>
          <button onClick={handleExportCSV}
            className="flex items-center gap-1.5 border border-white/[0.08] hover:border-gray-600 text-zinc-300 hover:text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
            <Download size={14} /> Export CSV
          </button>
          <button onClick={handlePrint} disabled={!preview}
            className="flex items-center gap-1.5 border border-white/[0.08] hover:border-gray-600 text-zinc-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed text-sm font-medium px-4 py-2 rounded-lg transition-colors">
            <Printer size={14} /> Print / PDF
          </button>
        </div>

        {previewErr && (
          <div className="mt-4 flex items-center gap-2 bg-red-500/10 border border-red-500/20 text-red-400 text-sm px-3 py-2 rounded-lg">
            <AlertCircle size={14} />{previewErr}
          </div>
        )}

        {/* Preview table */}
        {preview && (
          <div className="mt-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-zinc-500">
                {previewMeta?.count.toLocaleString()} rows
                {previewMeta?.truncated && <span className="text-yellow-500 ml-1">(preview shows first 500)</span>}
              </span>
            </div>
            <div className="overflow-x-auto rounded-xl border border-white/[0.06]">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-zinc-900/80 border-b border-white/[0.08]">
                    {preview.headers.map(h => (
                      <th key={h} className="text-left px-3 py-2.5 text-zinc-400 font-medium whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {preview.rows.slice(0, 100).map((row, i) => (
                    <tr key={i} className="hover:bg-white/[0.025] transition-colors">
                      {row.map((cell, j) => (
                        <td key={j} className="px-3 py-2 text-zinc-300 whitespace-nowrap max-w-[200px] truncate">{cell}</td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
              {preview.rows.length > 100 && (
                <div className="px-3 py-2 text-xs text-zinc-500 border-t border-white/[0.06] text-center">
                  Showing 100 of {preview.rows.length} rows — export to CSV for the full dataset
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Scheduled reports ── */}
      <div className="bg-zinc-950 border border-white/[0.06] rounded-2xl p-6">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Clock size={15} className="text-emerald-400" /> Scheduled reports
            </h2>
            <p className="text-xs text-zinc-500 mt-0.5">Reports are sent by email on the configured frequency.</p>
          </div>
          <button onClick={() => setShowScheduleModal(true)}
            className="flex items-center gap-1.5 bg-purple-600 hover:bg-emerald-500 text-white text-sm font-medium px-3.5 py-2 rounded-lg transition-colors">
            <Plus size={14} /> Schedule report
          </button>
        </div>

        {scheduled.length === 0 ? (
          <div className="text-center py-10 text-zinc-600">
            <Clock size={28} className="mx-auto mb-2 opacity-40" />
            <p className="text-sm">No scheduled reports yet.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {scheduled.map(r => (
              <div key={r.id} className="flex items-center gap-4 bg-zinc-900/40 border border-white/[0.08] rounded-xl px-4 py-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-white text-sm font-medium truncate">{r.name}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${colorCls(TYPE_COLORS[r.report_type as ReportType])}`}>
                      {TYPE_LABELS[r.report_type as ReportType]}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full border border-white/[0.08] text-zinc-400 capitalize">{r.frequency}</span>
                  </div>
                  <p className="text-xs text-zinc-500 truncate">
                    To: {r.recipients.join(', ')} · Next: {fmtDate(r.next_send)} · Last: {fmtDate(r.last_sent)}
                  </p>
                </div>

                <div className="flex items-center gap-1 flex-shrink-0">
                  {sendFeedback[r.id] && (
                    <span className={`text-xs mr-2 ${sendFeedback[r.id].startsWith('Sent') ? 'text-emerald-300' : 'text-red-400'}`}>
                      {sendFeedback[r.id]}
                    </span>
                  )}
                  <button onClick={() => sendNow.mutate(r.id)}
                    className="p-1.5 text-zinc-500 hover:text-emerald-400 transition-colors rounded" title="Send now">
                    <Send size={14} />
                  </button>
                  <button onClick={() => setEditTarget(r)}
                    className="p-1.5 text-zinc-500 hover:text-zinc-300 transition-colors rounded" title="Edit">
                    <Play size={14} />
                  </button>
                  <button onClick={() => toggleSchedule.mutate(r.id)}
                    className="p-1.5 transition-colors rounded" title={r.is_active ? 'Pause' : 'Resume'}>
                    {r.is_active
                      ? <ToggleRight size={16} className="text-emerald-300 hover:text-green-300" />
                      : <ToggleLeft size={16} className="text-zinc-500 hover:text-zinc-400" />}
                  </button>
                  <button onClick={() => { if (confirm(`Delete "${r.name}"?`)) deleteSchedule.mutate(r.id) }}
                    className="p-1.5 text-zinc-500 hover:text-red-400 transition-colors rounded" title="Delete">
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Modals */}
      {showScheduleModal && (
        <ScheduleModal
          onClose={() => setShowScheduleModal(false)}
          onSave={d => createSchedule.mutate(d)}
        />
      )}
      {editTarget && (
        <ScheduleModal
          initial={editTarget}
          onClose={() => setEditTarget(null)}
          onSave={d => updateSchedule.mutate({ id: editTarget.id, ...d })}
        />
      )}
    </div>
  )
}
