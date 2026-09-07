import React, { useState, useEffect, useRef } from 'react'
import { ShieldCheck } from 'lucide-react'

const FEED_EVENTS = [
  { level: 'BLOCK',  color: '#ef4444', msg: 'Malware execution blocked',        host: 'WIN-DEV-042' },
  { level: 'ALERT',  color: '#f97316', msg: 'Unusual login attempt detected',   host: 'user@eng.corp' },
  { level: 'OK',     color: '#10b981', msg: 'Endpoint compliance verified',     host: 'MBP-DESIGN-07' },
  { level: 'BLOCK',  color: '#ef4444', msg: 'USB device access blocked',        host: 'WIN-SRV-001' },
  { level: 'ALERT',  color: '#eab308', msg: 'Outdated EDR version detected',    host: 'MAC-FINANCE-03' },
  { level: 'OK',     color: '#10b981', msg: 'DLP policy applied',               host: 'WIN-HR-015' },
  { level: 'BLOCK',  color: '#ef4444', msg: 'C2 callback attempt blocked',      host: '192.168.4.22' },
  { level: 'ALERT',  color: '#f97316', msg: 'MFA bypass attempt flagged',       host: 'svc-acct@it' },
  { level: 'OK',     color: '#10b981', msg: 'Vulnerability patch applied',      host: 'LNX-PROD-08' },
  { level: 'BLOCK',  color: '#ef4444', msg: 'Ransomware pattern detected',      host: 'WIN-ACCT-006' },
  { level: 'ALERT',  color: '#eab308', msg: 'Disk encryption disabled',         host: 'MAC-EXEC-01' },
  { level: 'OK',     color: '#10b981', msg: 'Zero-trust policy enforced',       host: 'WIN-DEV-088' },
  { level: 'BLOCK',  color: '#ef4444', msg: 'Lateral movement attempt stopped', host: '10.0.2.55' },
  { level: 'ALERT',  color: '#f97316', msg: 'Privileged account anomaly',       host: 'admin@domain' },
  { level: 'OK',     color: '#10b981', msg: 'SentinelOne agent updated',        host: 'WIN-FIN-019' },
]

function getTime() {
  return new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

type FeedItem = (typeof FEED_EVENTS)[0] & { id: number; time: string }

export default function AuthLeftPanel() {
  const [feed, setFeed] = useState<FeedItem[]>(() =>
    FEED_EVENTS.slice(0, 6).map((e, i) => ({ ...e, id: i, time: getTime() }))
  )
  const idRef  = useRef(100)
  const idxRef = useRef(6)

  useEffect(() => {
    const t = setInterval(() => {
      const next = FEED_EVENTS[idxRef.current % FEED_EVENTS.length]
      idxRef.current++
      setFeed(prev => [{ ...next, id: idRef.current++, time: getTime() }, ...prev].slice(0, 7))
    }, 1800)
    return () => clearInterval(t)
  }, [])

  return (
    <div
      className="hidden lg:flex lg:w-[54%] relative flex-col overflow-hidden"
      style={{ background: 'var(--surface-0)', borderRight: '1px solid var(--border)' }}
    >
      {/* Scan beam */}
      <div
        className="absolute inset-x-0 pointer-events-none"
        style={{
          height: 2,
          background: 'rgba(16,185,129,0.32)',
          animation: 'scan-beam 5s linear infinite',
        }}
      />

      <div className="relative z-10 flex flex-col h-full px-10 py-9">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: 'var(--accent)' }}
          >
            <ShieldCheck size={16} className="text-white" strokeWidth={2.5} />
          </div>
          <span className="text-white font-bold tracking-tight" style={{ fontSize: 17, letterSpacing: '-0.02em' }}>SEC360</span>
        </div>

        {/* Hero */}
        <div className="mt-12">
          <div
            className="inline-flex items-center gap-2 rounded px-2.5 py-1 mb-5"
            style={{ background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.18)' }}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 flex-shrink-0" style={{ animation: 'pulse-dot 2s ease-in-out infinite' }} />
            <span className="text-[10px] font-bold tracking-[0.12em] uppercase" style={{ color: 'var(--accent)' }}>Live Threat Monitor</span>
          </div>

          <h2 className="text-white font-bold leading-[1.06] mb-3" style={{ fontSize: 38, letterSpacing: '-0.035em' }}>
            Security<br />
            <span style={{ color: 'var(--accent)' }}>Operations</span><br />
            Center
          </h2>
          <p className="text-[13px] max-w-[260px]" style={{ color: 'var(--text-4)', lineHeight: 1.65 }}>
            Real-time endpoint protection, identity compliance, and threat detection — unified.
          </p>
        </div>

        {/* Terminal event feed */}
        <div
          className="mt-8 rounded-xl overflow-hidden flex-1 flex flex-col"
          style={{ background: 'var(--surface-inset-strong)', border: '1px solid var(--border)', maxHeight: 300 }}
        >
          <div
            className="flex items-center gap-2 px-3.5 py-2 flex-shrink-0"
            style={{ borderBottom: '1px solid var(--border)', background: 'rgba(255,255,255,0.02)' }}
          >
            <div className="flex gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: 'rgba(239,68,68,0.5)' }} />
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: 'rgba(234,179,8,0.5)' }} />
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: 'rgba(34,197,94,0.5)' }} />
            </div>
            <span className="font-mono text-[10px] ml-2" style={{ color: 'var(--text-4)' }}>sec360 — threat_activity.log</span>
            <div className="ml-auto flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" style={{ animation: 'pulse-dot 1.2s ease-in-out infinite' }} />
              <span className="font-mono text-[10px] font-bold" style={{ color: '#10b981' }}>LIVE</span>
            </div>
          </div>

          <div className="p-3.5 flex-1 overflow-hidden">
            <div className="space-y-2">
              {feed.map((ev, i) => (
                <div
                  key={ev.id}
                  className="flex items-center gap-2.5 font-mono"
                  style={{
                    fontSize: 10.5,
                    opacity: Math.max(0.18, 1 - i * 0.14),
                    animation: i === 0 ? 'fade-in 0.25s ease both' : undefined,
                  }}
                >
                  <span style={{ color: 'var(--text-4)', flexShrink: 0 }}>{ev.time}</span>
                  <span className="font-bold flex-shrink-0" style={{ color: ev.color, width: 44, textAlign: 'right' }}>[{ev.level}]</span>
                  <span className="truncate" style={{ color: '#606068' }}>{ev.msg}</span>
                  <span className="flex-shrink-0 ml-auto" style={{ color: 'var(--text-4)' }}>{ev.host}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Stats row */}
        <div className="mt-5 grid grid-cols-3 gap-2.5">
          {[
            { label: 'Endpoints',   value: '1,247', color: '#10b981' },
            { label: 'Threats/24h', value: '38',    color: '#f97316' },
            { label: 'Compliant',   value: '94%',   color: '#10b981' },
          ].map(s => (
            <div
              key={s.label}
              className="rounded-lg px-3 py-2.5"
              style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--shimmer-a)' }}
            >
              <div className="font-bold tabular-nums" style={{ fontSize: 20, color: s.color, letterSpacing: '-0.03em' }}>{s.value}</div>
              <div className="font-semibold uppercase tracking-widest mt-0.5" style={{ fontSize: 9, color: 'var(--text-4)' }}>{s.label}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
