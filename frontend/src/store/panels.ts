import { create } from 'zustand'

export type PanelType = 'endpoint' | 'user'

export interface PanelSequenceItem {
  id: string
  title: string
}

export interface EntityPanel {
  id: string
  type: PanelType
  objectId: string
  title: string
  sequence?: PanelSequenceItem[]
}

interface PanelStore {
  panels: EntityPanel[]
  openPanel: (type: PanelType, objectId: string, title: string, sequence?: PanelSequenceItem[]) => void
  closePanel: (id: string) => void
  movePanel: (direction: -1 | 1) => void
  syncPanelFromUrl: (type: PanelType | null, objectId?: string) => void
  setPanelTitle: (id: string, title: string) => void
}

const ENTITY_TYPE_PARAM = 'entity'
const ENTITY_ID_PARAM = 'entityId'

function writeEntityUrl(type: PanelType | null, objectId?: string) {
  if (typeof window === 'undefined') return

  const url = new URL(window.location.href)
  const drawerAlreadyOpen = Boolean(url.searchParams.get(ENTITY_TYPE_PARAM) && url.searchParams.get(ENTITY_ID_PARAM))

  if (type && objectId) {
    url.searchParams.set(ENTITY_TYPE_PARAM, type)
    url.searchParams.set(ENTITY_ID_PARAM, objectId)
    const state = { ...(window.history.state ?? {}), sec360EntityDrawer: true }
    if (drawerAlreadyOpen) window.history.replaceState(state, '', url)
    else window.history.pushState(state, '', url)
  } else {
    url.searchParams.delete(ENTITY_TYPE_PARAM)
    url.searchParams.delete(ENTITY_ID_PARAM)
    window.history.replaceState({ ...(window.history.state ?? {}), sec360EntityDrawer: false }, '', url)
  }

  window.dispatchEvent(new PopStateEvent('popstate', { state: window.history.state }))
}

export const usePanelStore = create<PanelStore>((set) => ({
  panels: [],

  openPanel: (type, objectId, title, sequence) => {
    const panelId = `${type}-${objectId}`
    set({ panels: [{ id: panelId, type, objectId, title, sequence }] })
    writeEntityUrl(type, objectId)
  },

  closePanel: (id) => {
    set(state => ({ panels: state.panels.filter(p => p.id !== id) }))
    writeEntityUrl(null)
  },

  movePanel: (direction) => {
    const panel = usePanelStore.getState().panels[0]
    if (!panel?.sequence?.length) return
    const index = panel.sequence.findIndex(item => item.id === panel.objectId)
    const next = panel.sequence[index + direction]
    if (!next) return
    const nextPanel = { ...panel, id: `${panel.type}-${next.id}`, objectId: next.id, title: next.title }
    set({ panels: [nextPanel] })
    writeEntityUrl(panel.type, next.id)
  },

  syncPanelFromUrl: (type, objectId) => set(state => {
    if (!type || !objectId) return state.panels.length ? { panels: [] } : state
    const id = `${type}-${objectId}`
    const current = state.panels[0]
    if (current?.id === id) return state
    return {
      panels: [{
        id,
        type,
        objectId,
        title: type === 'endpoint' ? 'Endpoint details' : 'User identity',
      }],
    }
  }),

  setPanelTitle: (id, title) => set(state => ({
    panels: state.panels.map(panel => panel.id === id ? { ...panel, title } : panel),
  })),
}))
