import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow, format } from 'date-fns'
import { MessageSquare, Send, Trash2, Loader2 } from 'lucide-react'
import { fetchNotes, createNote, deleteNote, type Note } from '../../api/notes'

interface NoteBoxProps {
  entityType: 'endpoint' | 'user'
  entityId: string
  /** Email of the currently logged-in user, used to show delete button on own notes */
  currentUserEmail: string
  /** Role of the current user */
  currentUserRole: string
}

export default function NoteBox({ entityType, entityId, currentUserEmail, currentUserRole }: NoteBoxProps) {
  const [draft, setDraft] = useState('')
  const qc = useQueryClient()
  const queryKey = ['notes', entityType, entityId]

  const { data: notes = [], isLoading } = useQuery<Note[]>({
    queryKey,
    queryFn: () => fetchNotes(entityType, entityId),
    staleTime: 30_000,
  })

  const addMutation = useMutation({
    mutationFn: (content: string) => createNote(entityType, entityId, content),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey })
      setDraft('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (noteId: string) => deleteNote(noteId),
    onSuccess: () => qc.invalidateQueries({ queryKey }),
  })

  const canWrite = currentUserRole === 'analyst' || currentUserRole === 'admin'
  const canDeleteNote = (note: Note) =>
    currentUserRole === 'admin' || note.author_email === currentUserEmail

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const trimmed = draft.trim()
    if (!trimmed || addMutation.isPending) return
    addMutation.mutate(trimmed)
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      handleSubmit(e as unknown as React.FormEvent)
    }
  }

  return (
    <div className="space-y-3">
      {/* Section header */}
      <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wider flex items-center gap-1.5">
        <MessageSquare className="w-3.5 h-3.5" />
        Notes {notes.length > 0 && <span className="text-zinc-600">({notes.length})</span>}
      </div>

      {/* Notes list */}
      <div className="space-y-2">
        {isLoading ? (
          <div className="flex items-center justify-center py-4">
            <Loader2 className="w-4 h-4 animate-spin text-zinc-500" />
          </div>
        ) : notes.length === 0 ? (
          <div className="text-xs text-zinc-600 text-center py-4 bg-zinc-900/50 rounded-lg border border-dashed border-white/[0.08]">
            No notes yet
          </div>
        ) : (
          notes.map(note => (
            <div
              key={note.id}
              className="bg-zinc-900 rounded-lg px-3.5 py-3 space-y-1.5 group"
            >
              {/* Note body */}
              <p className="text-sm text-zinc-200 whitespace-pre-wrap leading-relaxed break-words">
                {note.content}
              </p>
              {/* Author + time row */}
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 min-w-0">
                  <div className="w-4 h-4 rounded-full bg-emerald-500/20 flex items-center justify-center text-emerald-300 text-[8px] font-bold flex-shrink-0">
                    {note.author_email[0].toUpperCase()}
                  </div>
                  <span className="text-xs text-zinc-400 truncate">{note.author_email}</span>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span
                    className="text-xs text-zinc-600"
                    title={format(new Date(note.created_at), 'PPpp')}
                  >
                    {formatDistanceToNow(new Date(note.created_at), { addSuffix: true })}
                  </span>
                  {canDeleteNote(note) && (
                    <button
                      onClick={() => deleteMutation.mutate(note.id)}
                      disabled={deleteMutation.isPending}
                      className="opacity-0 group-hover:opacity-100 text-zinc-600 hover:text-red-400 transition-[opacity,color] duration-150 disabled:opacity-50"
                      title="Delete note"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Input area — only for analysts and admins */}
      {canWrite && (
        <form onSubmit={handleSubmit} className="space-y-2">
          <textarea
            value={draft}
            onChange={e => setDraft(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Add a note… (Ctrl+Enter to submit)"
            rows={3}
            maxLength={4000}
            className="w-full bg-zinc-900 border border-white/[0.08] text-white placeholder-gray-600 rounded-lg px-3 py-2.5 text-sm resize-none focus:outline-none focus:border-emerald-500 transition-colors"
          />
          <div className="flex items-center justify-between">
            <span className="text-xs text-zinc-600">{draft.length}/4000</span>
            <button
              type="submit"
              disabled={!draft.trim() || addMutation.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-zinc-500 text-white text-xs font-medium rounded-lg transition-colors"
            >
              {addMutation.isPending ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Send className="w-3.5 h-3.5" />
              )}
              Add Note
            </button>
          </div>
          {addMutation.isError && (
            <p className="text-xs text-red-400">Failed to save note. Please try again.</p>
          )}
        </form>
      )}
    </div>
  )
}
