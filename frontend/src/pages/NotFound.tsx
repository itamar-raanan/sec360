import React from 'react'
import { ArrowLeft, SearchX } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

export default function NotFound() {
  const navigate = useNavigate()
  return (
    <div className="ui-page">
      <div className="ui-page-container flex min-h-full items-center justify-center">
        <section className="w-full max-w-[520px] border-l-2 px-6 py-2" style={{ borderColor: 'var(--accent)' }}>
          <div className="flex items-center gap-2"><SearchX size={15} style={{ color: 'var(--accent)' }} /><p className="ui-eyebrow">Navigation error · 404</p></div>
          <h1 className="mt-4 text-[24px] font-semibold tracking-[-0.035em]" style={{ color: 'var(--text-1)' }}>This view does not exist</h1>
          <p className="mt-2 max-w-md text-[13px] leading-relaxed" style={{ color: 'var(--text-3)' }}>The address may be outdated or the page may have moved. Your session and current data are unchanged.</p>
          <button className="ui-primary-button mt-5" onClick={() => navigate('/dashboard')}><ArrowLeft size={13} /> Return to overview</button>
        </section>
      </div>
    </div>
  )
}
