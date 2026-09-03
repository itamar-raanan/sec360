import React, { useState, useRef, useEffect, useCallback } from 'react'
import { Bot, Send, User, Sparkles, RotateCcw, Copy, Check, Square } from 'lucide-react'
import { sendChatMessageStream, type ChatMessage } from '../api/chat'

// ── Types ─────────────────────────────────────────────────────────────────────

interface DisplayMessage {
  role: 'user' | 'assistant'
  content: string
  suggestions?: string[]
  timestamp: Date
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function parseSuggestions(text: string): { content: string; suggestions: string[] } {
  const match = text.match(/\n?<!--SUGGESTIONS:([\s\S]*?)-->$/)
  if (!match) return { content: text, suggestions: [] }
  const suggestions = match[1].split('|').map(s => s.trim()).filter(Boolean)
  const content = text.slice(0, text.length - match[0].length)
  return { content, suggestions }
}

function relativeTime(date: Date): string {
  const secs = Math.floor((Date.now() - date.getTime()) / 1000)
  if (secs < 15) return 'just now'
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

// ── Simple markdown renderer ──────────────────────────────────────────────────

function renderMarkdown(text: string): React.ReactNode[] {
  const lines = text.split('\n')
  const nodes: React.ReactNode[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]

    if (line.startsWith('```')) {
      const codeLines: string[] = []
      i++
      while (i < lines.length && !lines[i].startsWith('```')) {
        codeLines.push(lines[i])
        i++
      }
      nodes.push(
        <pre key={i} className="my-2 rounded-lg p-3 overflow-x-auto text-[12px] font-mono"
          style={{ background: 'var(--surface-3)', border: '1px solid var(--border)' }}>
          <code style={{ color: '#34d399' }}>{codeLines.join('\n')}</code>
        </pre>
      )
      i++; continue
    }

    if (line.includes('|') && lines[i + 1]?.includes('---')) {
      const headerCells = line.split('|').map(c => c.trim()).filter(Boolean)
      i += 2
      const rows: string[][] = []
      while (i < lines.length && lines[i].includes('|')) {
        rows.push(lines[i].split('|').map(c => c.trim()).filter(Boolean))
        i++
      }
      nodes.push(
        <div key={i} className="my-3 overflow-x-auto">
          <table className="w-full text-[12px] border-collapse">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {headerCells.map((h, j) => (
                  <th key={j} className="px-3 py-1.5 text-left font-semibold"
                    style={{ color: 'var(--text-3)', background: 'var(--surface-2)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, ri) => (
                <tr key={ri} style={{ borderBottom: '1px solid var(--border)' }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--hover-1)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                  {row.map((cell, ci) => (
                    <td key={ci} className="px-3 py-1.5 font-mono"
                      style={{ color: 'var(--text-2)' }}>{inlineFormat(cell)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
      continue
    }

    if (line.startsWith('### ')) {
      nodes.push(<h3 key={i} className="font-semibold mt-3 mb-1 text-[14px]"
        style={{ color: 'var(--text-1)' }}>{inlineFormat(line.slice(4))}</h3>)
      i++; continue
    }
    if (line.startsWith('## ')) {
      nodes.push(<h2 key={i} className="font-bold mt-3 mb-1 text-[15px]"
        style={{ color: 'var(--text-1)' }}>{inlineFormat(line.slice(3))}</h2>)
      i++; continue
    }
    if (line.startsWith('# ')) {
      nodes.push(<h1 key={i} className="font-bold mt-3 mb-1 text-[16px]"
        style={{ color: 'var(--text-1)' }}>{inlineFormat(line.slice(2))}</h1>)
      i++; continue
    }

    if (line.startsWith('- ') || line.startsWith('* ')) {
      const items: string[] = []
      while (i < lines.length && (lines[i].startsWith('- ') || lines[i].startsWith('* '))) {
        items.push(lines[i].slice(2)); i++
      }
      nodes.push(
        <ul key={i} className="my-1.5 space-y-0.5 pl-4">
          {items.map((item, j) => (
            <li key={j} className="flex gap-2 text-[13px]" style={{ color: 'var(--text-2)' }}>
              <span className="mt-1.5 w-1 h-1 rounded-full flex-shrink-0" style={{ background: 'var(--accent)' }} />
              <span>{inlineFormat(item)}</span>
            </li>
          ))}
        </ul>
      )
      continue
    }

    if (line.startsWith('---') || line.startsWith('***')) {
      nodes.push(<hr key={i} className="my-3" style={{ borderColor: 'var(--border)' }} />)
      i++; continue
    }

    if (line.trim() === '') {
      nodes.push(<div key={i} className="h-1.5" />)
      i++; continue
    }

    nodes.push(
      <p key={i} className="text-[13px] leading-relaxed" style={{ color: 'var(--text-1)' }}>
        {inlineFormat(line)}
      </p>
    )
    i++
  }

  return nodes
}

function inlineFormat(text: string): React.ReactNode {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/)
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**'))
      return <strong key={i} style={{ color: 'var(--text-1)' }}>{part.slice(2, -2)}</strong>
    if (part.startsWith('*') && part.endsWith('*') && part.length > 2)
      return <em key={i} style={{ color: 'var(--text-2)' }}>{part.slice(1, -1)}</em>
    if (part.startsWith('`') && part.endsWith('`'))
      return <code key={i} className="px-1 py-0.5 rounded text-[11px] font-mono"
        style={{ background: 'var(--surface-3)', color: '#34d399' }}>{part.slice(1, -1)}</code>
    return part
  })
}

// ── Thinking dots ─────────────────────────────────────────────────────────────

function ThinkingDots() {
  return (
    <div className="flex items-center gap-1.5 px-1 py-1.5">
      {[0, 1, 2].map(i => (
        <span
          key={i}
          className="w-1.5 h-1.5 rounded-full block"
          style={{
            background: '#a78bfa',
            animation: `thinking-dot 1.4s ease-in-out ${i * 0.18}s infinite`,
          }}
        />
      ))}
    </div>
  )
}

// ── Typing cursor ─────────────────────────────────────────────────────────────

function TypingCursor() {
  return (
    <span
      className="inline-block w-[2px] h-[13px] ml-0.5 align-middle rounded-full"
      style={{
        background: '#a78bfa',
        animation: 'blink-cursor 0.8s ease-in-out infinite',
      }}
    />
  )
}

// ── Message bubble ────────────────────────────────────────────────────────────

interface MsgProps {
  msg: DisplayMessage
  streaming?: boolean
  tick: number
  onSuggestion: (text: string) => void
}

function MessageBubble({ msg, streaming = false, tick, onSuggestion }: MsgProps) {
  const [copied, setCopied] = useState(false)
  const isUser = msg.role === 'user'

  const copy = () => {
    navigator.clipboard.writeText(msg.content)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // suppress unused-variable lint for tick — it's used to force timestamp re-render
  void tick

  return (
    <div
      className={`flex gap-3 ${isUser ? 'flex-row-reverse' : 'flex-row'}`}
      style={{ animation: 'msg-in 0.22s var(--ease-out, cubic-bezier(0.23,1,0.32,1)) both' }}
    >
      <div className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5 ${
        isUser ? 'bg-emerald-600/30' : 'bg-violet-600/25'
      }`}>
        {isUser
          ? <User size={13} className="text-emerald-300" />
          : <Bot size={13} className="text-violet-400" />}
      </div>

      <div className={`max-w-[85%] group relative ${isUser ? 'items-end' : 'items-start'} flex flex-col gap-1`}>
        <div
          className="rounded-2xl px-4 py-2.5"
          style={{
            background: isUser ? 'var(--accent)' : 'var(--surface-2)',
            border: isUser ? 'none' : '1px solid var(--border)',
            borderTopRightRadius: isUser ? 4 : undefined,
            borderTopLeftRadius:  isUser ? undefined : 4,
          }}
        >
          {isUser ? (
            <p className="text-[13px] text-white leading-relaxed">{msg.content}</p>
          ) : (
            <div className="space-y-0.5">
              {streaming && msg.content === ''
                ? <ThinkingDots />
                : renderMarkdown(msg.content)
              }
              {streaming && msg.content !== '' && <TypingCursor />}
            </div>
          )}
        </div>

        {/* Timestamp */}
        <span
          className={`text-[10px] px-1 ${isUser ? 'self-end' : 'self-start'}`}
          style={{ color: 'var(--text-4)' }}
        >
          {relativeTime(msg.timestamp)}
        </span>

        {/* Copy button */}
        {!isUser && !streaming && msg.content !== '' && (
          <button
            onClick={copy}
            className="absolute -bottom-5 right-0 opacity-0 group-hover:opacity-100 flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-md transition-[opacity,background-color]"
            style={{ color: 'var(--text-4)', background: 'var(--surface-3)', border: '1px solid var(--border)' }}
          >
            {copied ? <Check size={9} /> : <Copy size={9} />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        )}

        {/* Follow-up suggestion chips */}
        {!isUser && !streaming && msg.suggestions && msg.suggestions.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mt-2">
            {msg.suggestions.map(s => (
              <button
                key={s}
                onClick={() => onSuggestion(s)}
                className="text-[11px] px-2.5 py-1 rounded-lg transition-[background-color,border-color,color] duration-150"
                style={{
                  background: 'var(--surface-3)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-3)',
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.borderColor = 'rgba(139,92,246,0.45)'
                  e.currentTarget.style.color = 'var(--text-1)'
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.borderColor = 'var(--border)'
                  e.currentTarget.style.color = 'var(--text-3)'
                }}
              >
                {s}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Initial suggestions ───────────────────────────────────────────────────────

const SUGGESTIONS = [
  'Show me all endpoints with outdated S1 agent',
  'Show users without MFA enabled',
  'Login activity from Israel in the last 30 days',
  'Which endpoints have no WSS installed?',
  'Show non-compliant endpoints',
  'Users with high risk score',
  'Suspicious activity events this month',
  'Endpoints with inactive security agents',
  'Show compliance summary',
  'Which users have no linked endpoint?',
]

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AIChat() {
  const [messages, setMessages]       = useState<DisplayMessage[]>([])
  const [streamingText, setStreaming] = useState<string | null>(null)
  const [input, setInput]             = useState('')
  const [error, setError]             = useState<string | null>(null)
  const [tick, setTick]               = useState(0)
  const bottomRef  = useRef<HTMLDivElement>(null)
  const inputRef   = useRef<HTMLTextAreaElement>(null)
  const abortRef   = useRef<AbortController | null>(null)

  const isStreaming = streamingText !== null

  // Tick every 30s so relative timestamps update
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 30_000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, streamingText])

  const send = useCallback(async (text: string) => {
    const trimmed = text.trim()
    if (!trimmed || isStreaming) return

    const userMsg: DisplayMessage = { role: 'user', content: trimmed, timestamp: new Date() }
    const history: ChatMessage[] = messages.map(m => ({ role: m.role, content: m.content }))
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setError(null)
    setStreaming('')

    abortRef.current = new AbortController()

    try {
      await sendChatMessageStream(
        trimmed,
        history,
        (token) => setStreaming(prev => (prev ?? '') + token),
        abortRef.current.signal,
      )

      setStreaming(prev => {
        const raw = prev ?? ''
        const { content, suggestions } = parseSuggestions(raw)
        const assistantMsg: DisplayMessage = {
          role: 'assistant',
          content,
          suggestions: suggestions.length ? suggestions : undefined,
          timestamp: new Date(),
        }
        setMessages(m => [...m, assistantMsg])
        return null
      })
    } catch (e: any) {
      setStreaming(null)
      if (e?.name === 'AbortError') return
      setError(e?.message ?? 'Something went wrong. Please try again.')
    } finally {
      abortRef.current = null
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [isStreaming, messages])

  const stop = () => {
    abortRef.current?.abort()
    setStreaming(prev => {
      if (prev) {
        const { content } = parseSuggestions(prev)
        setMessages(m => [...m, { role: 'assistant', content, timestamp: new Date() }])
      }
      return null
    })
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      send(input)
    }
  }

  const reset = () => {
    abortRef.current?.abort()
    setMessages([])
    setStreaming(null)
    setError(null)
    setInput('')
    setTimeout(() => inputRef.current?.focus(), 50)
  }

  const isEmpty = messages.length === 0 && streamingText === null

  // Streaming display message (thinking or in-progress)
  const streamingMsg: DisplayMessage | null = isStreaming
    ? { role: 'assistant', content: streamingText ?? '', timestamp: new Date() }
    : null

  return (
    <div className="absolute inset-0 flex flex-col overflow-hidden">
      <style>{`
        @keyframes blink-cursor {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0; }
        }
        @keyframes thinking-dot {
          0%, 60%, 100% { transform: translateY(0);   opacity: 0.4; }
          30%            { transform: translateY(-5px); opacity: 1;   }
        }
        @keyframes msg-in {
          from { opacity: 0; transform: translateY(6px); }
          to   { opacity: 1; transform: translateY(0);   }
        }
      `}</style>

      {/* Header */}
      <div className="flex-shrink-0 px-6 py-3.5 flex items-center justify-between"
        style={{ borderBottom: '1px solid var(--border)' }}>
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-xl flex items-center justify-center relative"
            style={{ background: 'rgba(139,92,246,0.15)', border: '1px solid rgba(139,92,246,0.25)' }}>
            <Sparkles size={14} style={{ color: '#a78bfa' }} />
            {/* Online status dot */}
            <span
              className="absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full"
              style={{ background: '#10b981', border: '2px solid var(--surface-0, #07070f)' }}
            />
          </div>
          <div>
            <h1 className="text-[14px] font-semibold" style={{ color: 'var(--text-1)' }}>
              Security Assistant
            </h1>
            <p className="text-[11px]" style={{ color: 'var(--text-4)' }}>
              {isStreaming ? 'Analyzing…' : 'Online · Llama 3.2 · running locally'}
            </p>
          </div>
        </div>
        {(messages.length > 0 || isStreaming) && (
          <button
            onClick={reset}
            className="flex items-center gap-1.5 text-[12px] px-3 py-1.5 rounded-lg transition-colors"
            style={{ color: 'var(--text-4)', border: '1px solid var(--border)' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-2)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-4)')}
          >
            <RotateCcw size={11} /> New chat
          </button>
        )}
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto">
        {isEmpty ? (
          <div className="flex flex-col items-center justify-center h-full px-6 pb-8 gap-6">
            <div className="flex flex-col items-center gap-3 text-center max-w-sm">
              <div className="w-14 h-14 rounded-2xl flex items-center justify-center"
                style={{ background: 'rgba(139,92,246,0.12)', border: '1px solid rgba(139,92,246,0.20)' }}>
                <Bot size={26} style={{ color: '#a78bfa' }} />
              </div>
              <div>
                <p className="text-[15px] font-semibold" style={{ color: 'var(--text-1)' }}>
                  How can I help?
                </p>
                <p className="text-[13px] mt-1" style={{ color: 'var(--text-4)' }}>
                  Ask me anything about your security posture — endpoints, users, login activity, compliance, and more.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 w-full max-w-2xl">
              {SUGGESTIONS.map(s => (
                <button
                  key={s}
                  onClick={() => send(s)}
                  disabled={isStreaming}
                  className="text-left px-3.5 py-2.5 rounded-xl text-[12px] transition-[background-color,border-color] duration-150 disabled:opacity-40"
                  style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', color: 'var(--text-2)' }}
                  onMouseEnter={e => {
                    if (!isStreaming) {
                      e.currentTarget.style.background = 'var(--surface-3)'
                      e.currentTarget.style.borderColor = 'rgba(139,92,246,0.35)'
                      e.currentTarget.style.color = 'var(--text-1)'
                    }
                  }}
                  onMouseLeave={e => {
                    e.currentTarget.style.background = 'var(--surface-2)'
                    e.currentTarget.style.borderColor = 'var(--border)'
                    e.currentTarget.style.color = 'var(--text-2)'
                  }}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="px-6 py-5 space-y-6 max-w-4xl mx-auto w-full">
            {messages.map((msg, i) => (
              <MessageBubble key={i} msg={msg} tick={tick} onSuggestion={send} />
            ))}

            {/* Live streaming bubble (thinking dots or in-progress text) */}
            {streamingMsg && (
              <MessageBubble
                msg={streamingMsg}
                streaming
                tick={tick}
                onSuggestion={send}
              />
            )}

            {error && (
              <div className="rounded-xl px-4 py-3 text-[13px]"
                style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.20)', color: '#f87171' }}>
                {error}
              </div>
            )}

            <div ref={bottomRef} />
          </div>
        )}
      </div>

      {/* Input bar */}
      <div className="flex-shrink-0 px-6 py-4"
        style={{ borderTop: '1px solid var(--border)', background: 'var(--surface-0)' }}>
        <div className="max-w-4xl mx-auto w-full">
          <div className="flex items-end gap-3 rounded-2xl px-4 py-3"
            style={{ background: 'var(--surface-2)', border: '1px solid var(--border-mid)' }}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about endpoints, users, logins, compliance…"
              rows={1}
              disabled={isStreaming}
              className="flex-1 resize-none bg-transparent text-[14px] outline-none placeholder-zinc-600 leading-relaxed disabled:opacity-50"
              style={{ color: 'var(--text-1)', maxHeight: 160, overflowY: 'auto' }}
              onInput={e => {
                const el = e.currentTarget
                el.style.height = 'auto'
                el.style.height = `${Math.min(el.scrollHeight, 160)}px`
              }}
            />

            {isStreaming ? (
              <button
                onClick={stop}
                className="flex-shrink-0 w-8 h-8 rounded-xl flex items-center justify-center transition-opacity"
                style={{ background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.25)' }}
                title="Stop generating"
              >
                <Square size={12} style={{ color: '#f87171' }} />
              </button>
            ) : (
              <button
                onClick={() => send(input)}
                disabled={!input.trim()}
                className="flex-shrink-0 w-8 h-8 rounded-xl flex items-center justify-center transition-[background-color,opacity] duration-150 disabled:opacity-30"
                style={{ background: 'var(--accent)' }}
              >
                <Send size={14} className="text-white" />
              </button>
            )}
          </div>
          <p className="text-[10px] text-center mt-2" style={{ color: 'var(--text-4)' }}>
            Enter to send · Shift+Enter for new line{isStreaming ? ' · Generating…' : ''}
          </p>
        </div>
      </div>
    </div>
  )
}
