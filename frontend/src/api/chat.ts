import apiClient from './client'

export interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
}

/**
 * Stream a chat response token-by-token.
 * onToken is called for each text chunk received.
 * Returns the full accumulated response.
 */
export async function sendChatMessageStream(
  message: string,
  history: ChatMessage[],
  onToken: (token: string) => void,
  signal?: AbortSignal,
): Promise<string> {
  const baseURL: string = (apiClient.defaults.baseURL ?? '/api').replace(/\/$/, '')

  const res = await fetch(`${baseURL}/ai/chat/stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',   // send HttpOnly auth cookies
    body: JSON.stringify({ message, history }),
    signal,
  })

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }))
    throw new Error(err.detail ?? `HTTP ${res.status}`)
  }

  const reader = res.body?.getReader()
  if (!reader) throw new Error('No response body')

  const decoder = new TextDecoder()
  const chunks: string[] = []

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    const text = decoder.decode(value, { stream: true })
    chunks.push(text)
    onToken(text)
  }

  return chunks.join('')
}

export async function sendChatMessage(
  message: string,
  history: ChatMessage[],
): Promise<string> {
  const res = await apiClient.post('/ai/chat', { message, history })
  return res.data.response as string
}
