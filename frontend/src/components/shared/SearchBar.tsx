import React, { useState } from 'react'
import { Search, X } from 'lucide-react'

interface SearchBarProps {
  placeholder?: string
  value?: string
  onChange?: (value: string) => void
  onSearch?: (value: string) => void
  className?: string
}

export default function SearchBar({ placeholder = 'Search...', value, onChange, onSearch, className = '' }: SearchBarProps) {
  const [internalValue, setInternalValue] = useState(value || '')

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const v = e.target.value
    setInternalValue(v)
    onChange?.(v)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      onSearch?.(internalValue)
    }
  }

  const handleClear = () => {
    setInternalValue('')
    onChange?.('')
    onSearch?.('')
  }

  const displayValue = value !== undefined ? value : internalValue

  return (
    <div className={`relative flex items-center ${className}`}>
      <Search className="absolute left-3 text-zinc-500" size={16} />
      <input
        type="text"
        value={displayValue}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        placeholder={placeholder}
        className="w-full bg-zinc-900 border border-white/[0.08] text-white placeholder-gray-500 rounded-lg pl-9 pr-9 py-2 text-sm focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
      />
      {displayValue && (
        <button onClick={handleClear} className="absolute right-3 text-zinc-500 hover:text-zinc-300 transition-colors">
          <X size={14} />
        </button>
      )}
    </div>
  )
}
