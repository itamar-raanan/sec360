import { create } from 'zustand'

export type PanelType = 'endpoint' | 'user'

export interface FloatingPanel {
  id: string
  type: PanelType
  objectId: string
  title: string
  minimized: boolean
}

interface PanelStore {
  panels: FloatingPanel[]
  openPanel: (type: PanelType, objectId: string, title: string) => void
  closePanel: (id: string) => void
  toggleMinimize: (id: string) => void
}

const MAX_PANELS = 4

export const usePanelStore = create<PanelStore>((set) => ({
  panels: [],

  openPanel: (type, objectId, title) => set(state => {
    const panelId = `${type}-${objectId}`
    const existing = state.panels.find(p => p.id === panelId)
    if (existing) {
      return { panels: state.panels.map(p => p.id === panelId ? { ...p, minimized: false } : p) }
    }
    const newPanel: FloatingPanel = { id: panelId, type, objectId, title, minimized: false }
    const panels = state.panels.length >= MAX_PANELS
      ? [...state.panels.slice(1), newPanel]
      : [...state.panels, newPanel]
    return { panels }
  }),

  closePanel: (id) => set(state => ({
    panels: state.panels.filter(p => p.id !== id),
  })),

  toggleMinimize: (id) => set(state => ({
    panels: state.panels.map(p => p.id === id ? { ...p, minimized: !p.minimized } : p),
  })),
}))
