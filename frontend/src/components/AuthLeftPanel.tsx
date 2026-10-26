import React from 'react'
import { Activity, Braces, Database, ShieldCheck } from 'lucide-react'

const SIGNAL_PATHS = [
  { icon: Activity, label: 'Endpoint state', sources: 'SentinelOne · Puppet', detail: 'Agent, software, and configuration evidence' },
  { icon: ShieldCheck, label: 'Identity context', sources: 'AD · Google Workspace', detail: 'Ownership, access, and account activity' },
  { icon: Database, label: 'Policy evidence', sources: 'DLP · Proxy Audit', detail: 'Exclusions, revisions, and audit history' },
]

export default function AuthLeftPanel() {
  return (
    <aside
      className="hidden lg:flex lg:w-[54%] flex-col overflow-hidden"
      style={{ background: 'var(--surface-0)', borderRight: '1px solid var(--border)' }}
    >
      <div className="flex h-full flex-col px-10 py-9 xl:px-14 xl:py-11">
        <div className="flex items-center gap-3" data-login-brand data-login-motion>
          <span className="brand-mark"><ShieldCheck size={16} strokeWidth={2.3} /></span>
          <span className="text-[17px] font-semibold tracking-[-0.025em]" style={{ color: 'var(--text-1)' }}>SEC360</span>
          <span className="ml-auto text-[13px]" style={{ color: 'var(--text-3)' }}>Security workspace</span>
        </div>

        <div className="my-auto max-w-[680px] py-12">
          <h2 className="max-w-[560px] text-[clamp(36px,4.3vw,64px)] font-semibold leading-[0.98] tracking-[-0.05em]" style={{ color: 'var(--text-1)' }} data-login-hero data-login-motion>
            Security posture, without blind spots.
          </h2>
          <p className="mt-6 max-w-[560px] text-[16px] leading-7" style={{ color: 'var(--text-2)' }} data-login-copy data-login-motion>
            Correlate endpoint, identity, compliance, vulnerability, audit, and policy evidence in one operational view.
          </p>

          <section className="mt-12 max-w-[660px]" aria-labelledby="signal-path-title">
            <div className="flex items-end justify-between border-b pb-3" style={{ borderColor: 'var(--border-mid)' }} data-login-index data-login-motion>
              <div>
                <h3 id="signal-path-title" className="text-[14px] font-semibold" style={{ color: 'var(--text-1)' }}>Correlation paths</h3>
                <p className="mt-1 text-[13px]" style={{ color: 'var(--text-3)' }}>The evidence behind every posture decision</p>
              </div>
              <Braces size={16} style={{ color: 'var(--accent)' }} aria-hidden />
            </div>

            <div>
              {SIGNAL_PATHS.map(({ icon: Icon, label, sources, detail }) => (
                <div key={label} className="grid grid-cols-[22px_minmax(0,1fr)_minmax(150px,0.7fr)] items-center gap-4 border-b py-4" style={{ borderColor: 'var(--border)' }} data-login-row data-login-motion>
                  <Icon size={16} strokeWidth={1.7} style={{ color: 'var(--text-3)' }} aria-hidden />
                  <div className="min-w-0">
                    <p className="text-[14px] font-medium" style={{ color: 'var(--text-1)' }}>{label}</p>
                    <p className="mt-1 truncate text-[13px]" style={{ color: 'var(--text-3)' }}>{detail}</p>
                  </div>
                  <p className="text-right text-[13px] tabular-nums" style={{ color: 'var(--text-2)' }}>{sources}</p>
                </div>
              ))}
            </div>
          </section>
        </div>

        <p className="text-[13px]" style={{ color: 'var(--text-3)' }} data-login-footer data-login-motion>One endpoint. Every control. One decision.</p>
      </div>
    </aside>
  )
}
