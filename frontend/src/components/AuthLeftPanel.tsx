import React, { useState, useEffect, useRef } from 'react'
import { ShieldCheck } from 'lucide-react'

const FEED_EVENTS = [
  { level: 'BLOCK', color: '#ef4444', msg: 'Malware execution blocked', host: 'WIN-DEV-042' },
  { level: 'ALERT', color: '#f97316', msg: 'Unusual login attempt detected', host: 'user@eng.corp' },
  { level: 'OK', color: '#10b981', msg: 'Endpoint compliance verified', host: 'MBP-DESIGN-07' },
  { level: 'BLOCK', color: '#ef4444', msg: 'USB device access blocked', host: 'WIN-SRV-001' },
  { level: 'ALERT', color: '#eab308', msg: 'Outdated EDR version detected', host: 'MAC-FINANCE-03' },
  { level: 'OK', color: '#10b981', msg: 'DLP policy applied', host: 'WIN-HR-015' },
  { level: 'BLOCK', color: '#ef4444', msg: 'C2 callback attempt blocked', host: '192.168.4.22' },
  { level: 'ALERT', color: '#f97316', msg: 'MFA bypass attempt flagged', host: 'svc-acct@it' },
  { level: 'OK', color: '#10b981', msg: 'Vulnerability patch applied', host: 'LNX-PROD-08' },
  { level: 'BLOCK', color: '#ef4444', msg: 'Ransomware pattern detected', host: 'WIN-ACCT-006' },
  { level: 'ALERT', color: '#eab308', msg: 'Disk encryption disabled', host: 'MAC-EXEC-01' },
  { level: 'OK', color: '#10b981', msg: 'Zero-trust policy enforced', host: 'WIN-DEV-088' },
  { level: 'BLOCK', color: '#ef4444', msg: 'Lateral movement attempt stopped', host: '10.0.2.55' },
  { level: 'ALERT', color: '#f97316', msg: 'Privileged account anomaly', host: 'admin@domain' },
  { level: 'OK', color: '#10b981', msg: 'SentinelOne agent updated', host: 'WIN-FIN-019' },
]

function getTime() {
  return new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

type FeedItem = (typeof FEED_EVENTS)[0] & { id: number; time: string }

export default function AuthLeftPanel() {
  const [feed, setFeed] = useState<FeedItem[]>(() =>
    FEED_EVENTS.slice(0, 6).map((event, index) => ({ ...event, id: index, time: getTime() })),
  )
  const idRef = useRef(100)
  const indexRef = useRef(6)

  useEffect(() => {
    const timer = setInterval(() => {
      const next = FEED_EVENTS[indexRef.current % FEED_EVENTS.length]
      indexRef.current += 1
      setFeed(previous => [{ ...next, id: idRef.current++, time: getTime() }, ...previous].slice(0, 7))
    }, 1800)
    return () => clearInterval(timer)
  }, [])

  return (
    <aside
      className="relative hidden flex-col overflow-hidden lg:flex lg:w-[54%]"
      style={{
        background: 'var(--surface-1)',
        borderRight: '1px solid var(--border)',
      }}
    >
      <div
        className="pointer-events-none absolute inset-x-0"
        style={{ height: 2, background: 'rgba(16,185,129,0.32)', animation: 'scan-beam 5s linear infinite' }}
      />

      <div className="relative z-10 flex h-full flex-col px-10 py-9">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg" style={{ background: 'var(--accent)' }}>
            <ShieldCheck size={16} className="text-white" strokeWidth={2.5} />
          </div>
          <span className="text-[17px] font-bold tracking-[-0.02em] text-white">SEC360</span>
        </div>

        <div className="mt-12">
          <div
            className="mb-5 inline-flex items-center gap-2 rounded px-2.5 py-1"
            style={{ background: 'rgba(16,185,129,0.06)', border: '1px solid rgba(16,185,129,0.18)' }}
          >
            <span className="h-1.5 w-1.5 flex-shrink-0 rounded-full bg-emerald-400" style={{ animation: 'pulse-dot 2s ease-in-out infinite' }} />
            <span className="text-[10px] font-bold uppercase tracking-[0.12em]" style={{ color: 'var(--accent)' }}>Live Threat Monitor</span>
          </div>

          <h2 className="mb-3 text-[38px] font-bold leading-[1.06] tracking-[-0.035em] text-white">
            Security<br />
            <span style={{ color: 'var(--accent)' }}>Operations</span><br />
            Center
          </h2>
          <p className="max-w-[300px] text-[13px] leading-[1.65]" style={{ color: 'var(--text-3)' }}>
            Real-time endpoint protection, identity compliance, and threat detection — unified.
          </p>
        </div>

        <div
          className="mt-8 flex max-h-[300px] flex-1 flex-col overflow-hidden rounded-xl"
          style={{ background: '#07070d', border: '1px solid rgba(255,255,255,0.08)', boxShadow: '0 20px 60px rgba(0,0,0,0.28)' }}
        >
          <div className="flex flex-shrink-0 items-center gap-2 px-3.5 py-2" style={{ borderBottom: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.025)' }}>
            <div className="flex gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full" style={{ background: 'rgba(239,68,68,0.5)' }} />
              <span className="h-2.5 w-2.5 rounded-full" style={{ background: 'rgba(234,179,8,0.5)' }} />
              <span className="h-2.5 w-2.5 rounded-full" style={{ background: 'rgba(34,197,94,0.5)' }} />
            </div>
            <span className="ml-2 font-mono text-[10px]" style={{ color: 'var(--text-3)' }}>sec360 — threat_activity.log</span>
            <div className="ml-auto flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" style={{ animation: 'pulse-dot 1.2s ease-in-out infinite' }} />
              <span className="font-mono text-[10px] font-bold text-emerald-500">LIVE</span>
            </div>
          </div>

          <div className="flex-1 overflow-hidden p-3.5">
            <div className="space-y-2">
              {feed.map((event, index) => (
                <div
                  key={event.id}
                  className="flex items-center gap-2.5 font-mono text-[10.5px]"
                  style={{ opacity: Math.max(0.18, 1 - index * 0.14), animation: index === 0 ? 'fade-in 0.25s ease both' : undefined }}
                >
                  <span className="flex-shrink-0" style={{ color: 'var(--text-3)' }}>{event.time}</span>
                  <span className="w-11 flex-shrink-0 text-right font-bold" style={{ color: event.color }}>[{event.level}]</span>
                  <span className="truncate" style={{ color: 'var(--text-3)' }}>{event.msg}</span>
                  <span className="ml-auto flex-shrink-0" style={{ color: 'var(--text-4)' }}>{event.host}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-5 grid grid-cols-3 gap-2.5">
          {[
            { label: 'Endpoints', value: '1,247', color: '#10b981' },
            { label: 'Threats/24h', value: '38', color: '#f97316' },
            { label: 'Compliant', value: '94%', color: '#10b981' },
          ].map(stat => (
            <div key={stat.label} className="rounded-[var(--radius-panel)] px-3 py-2.5" style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}>
              <div className="text-xl font-bold tabular-nums tracking-[-0.03em]" style={{ color: stat.color }}>{stat.value}</div>
              <div className="mt-0.5 text-[10px] font-semibold" style={{ color: 'var(--text-4)' }}>{stat.label}</div>
            </div>
          ))}
        </div>
      </div>
    </aside>
  )
}
