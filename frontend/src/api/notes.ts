import apiClient from './client'

export interface Note {
  id: string
  entity_type: string
  entity_id: string
  content: string
  author_email: string
  created_at: string
}

export async function fetchNotes(entityType: 'endpoint' | 'user', entityId: string): Promise<Note[]> {
  const res = await apiClient.get<Note[]>('/notes', {
    params: { entity_type: entityType, entity_id: entityId },
  })
  return res.data
}

export async function createNote(
  entityType: 'endpoint' | 'user',
  entityId: string,
  content: string,
): Promise<Note> {
  const res = await apiClient.post<Note>('/notes', {
    entity_type: entityType,
    entity_id: entityId,
    content,
  })
  return res.data
}

export async function deleteNote(noteId: string): Promise<void> {
  await apiClient.delete(`/notes/${noteId}`)
}
