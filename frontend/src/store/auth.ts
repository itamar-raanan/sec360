import { create } from 'zustand'
import type { AuthUser } from '../types'
import apiClient from '../api/client'

export type LoginResult = { mfa_required: true } | { mfa_required: false }

interface AuthState {
  user: AuthUser | null
  isAuthenticated: boolean
  /** true while the initial /auth/me check is in-flight — prevents premature redirects on refresh */
  sessionLoading: boolean
  login: (email: string, password: string, totpCode?: string) => Promise<LoginResult>
  logout: () => Promise<void>
  setAuth: (user: AuthUser) => void
  restoreSession: () => Promise<void>
}

export const useAuthStore = create<AuthState>((set) => ({
  // Token lives in HttpOnly cookie — we only track the user object in memory.
  // Attempt to restore from /auth/me on app start (restoreSession).
  user: null,
  isAuthenticated: false,
  sessionLoading: true,

  setAuth: (user) => {
    set({ user, isAuthenticated: true, sessionLoading: false })
  },

  login: async (email, password, totpCode?) => {
    const res = await apiClient.post('/auth/login', {
      email,
      password,
      totp_code: totpCode ?? null,
    })
    if (res.data.mfa_required) {
      return { mfa_required: true }
    }
    // Cookie is set by the server — just store user info in memory.
    set({ user: res.data.user, isAuthenticated: true, sessionLoading: false })
    return { mfa_required: false }
  },

  logout: async () => {
    try {
      await apiClient.post('/auth/logout')
    } catch {
      // Best-effort — clear state regardless
    }
    set({ user: null, isAuthenticated: false, sessionLoading: false })
  },

  restoreSession: async () => {
    try {
      const res = await apiClient.get('/auth/me')
      set({ user: res.data, isAuthenticated: true, sessionLoading: false })
    } catch {
      set({ user: null, isAuthenticated: false, sessionLoading: false })
    }
  },
}))
