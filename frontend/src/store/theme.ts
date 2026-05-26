import { create } from 'zustand'

type Theme = 'dark' | 'light'

interface ThemeStore {
  theme: Theme
  toggle: () => void
  setTheme: (t: Theme) => void
}

function applyTheme(t: Theme) {
  document.documentElement.setAttribute('data-theme', t)
}

function getInitial(): Theme {
  const stored = localStorage.getItem('sec360-theme') as Theme | null
  if (stored === 'dark' || stored === 'light') return stored
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

const initial = getInitial()
applyTheme(initial)

export const useThemeStore = create<ThemeStore>((set) => ({
  theme: initial,
  toggle: () =>
    set((s) => {
      const next: Theme = s.theme === 'dark' ? 'light' : 'dark'
      localStorage.setItem('sec360-theme', next)
      applyTheme(next)
      return { theme: next }
    }),
  setTheme: (t) => {
    localStorage.setItem('sec360-theme', t)
    applyTheme(t)
    set({ theme: t })
  },
}))
