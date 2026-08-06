import { useState, useEffect, useRef, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, CornerDownLeft, ArrowUp, ArrowDown } from 'lucide-react'
import { NAV } from './Sidebar.jsx'

const FLAT_ITEMS = NAV.flatMap(g => g.items.map(i => ({ ...i, group: g.group })))

export default function CommandPalette({ open, onClose }) {
  const [query, setQuery] = useState('')
  const [activeIdx, setActiveIdx] = useState(0)
  const inputRef = useRef(null)
  const navigate = useNavigate()

  const results = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return FLAT_ITEMS
    return FLAT_ITEMS.filter(i =>
      i.label.toLowerCase().includes(q) || i.group.toLowerCase().includes(q) || i.path.toLowerCase().includes(q)
    )
  }, [query])

  useEffect(() => {
    if (open) {
      setQuery('')
      setActiveIdx(0)
      setTimeout(() => inputRef.current?.focus(), 10)
    }
  }, [open])

  useEffect(() => { setActiveIdx(0) }, [query])

  function go(item) {
    if (!item) return
    navigate(item.path)
    onClose()
  }

  function onKeyDown(e) {
    if (e.key === 'Escape') { onClose(); return }
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIdx(i => Math.min(i + 1, results.length - 1)) }
    if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIdx(i => Math.max(i - 1, 0)) }
    if (e.key === 'Enter') { e.preventDefault(); go(results[activeIdx]) }
  }

  if (!open) return null

  return (
    <div
      style={{ position: 'fixed', inset: 0, zIndex: 1000, background: 'rgba(0,0,0,0.55)', backdropFilter: 'blur(2px)', display: 'flex', alignItems: 'flex-start', justifyContent: 'center', paddingTop: '12vh' }}
      onClick={onClose}
      role="presentation"
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: 'min(560px, 92vw)', background: 'var(--cat-card-final, var(--cat-card))',
          border: '1px solid var(--cat-border)', borderRadius: 'calc(14px * var(--cat-radius, 1))',
          boxShadow: '0 24px 60px rgba(0,0,0,0.5)', overflow: 'hidden',
        }}
        className="animate-slide-up"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderBottom: '1px solid var(--cat-border)' }}>
          <Search size={16} style={{ color: 'var(--cat-sub)', flexShrink: 0 }} />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Search pages, rules, IPs, settings…"
            aria-label="Search"
            style={{ flex: 1, background: 'none', border: 'none', outline: 'none', color: 'var(--cat-text)', fontSize: 14 }}
          />
          <kbd style={{ fontSize: 10, color: 'var(--cat-sub)', border: '1px solid var(--cat-border)', borderRadius: 4, padding: '2px 5px' }}>ESC</kbd>
        </div>
        <div style={{ maxHeight: '52vh', overflowY: 'auto', padding: 6 }}>
          {results.length === 0 && (
            <div style={{ padding: 20, textAlign: 'center', fontSize: 12.5, color: 'var(--cat-sub)' }}>No matches for "{query}"</div>
          )}
          {results.map((item, i) => {
            const Icon = item.icon
            const active = i === activeIdx
            return (
              <button
                key={item.path}
                onMouseEnter={() => setActiveIdx(i)}
                onClick={() => go(item)}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', gap: 10, padding: '9px 10px',
                  borderRadius: 'calc(8px * var(--cat-radius, 1))', border: 'none', textAlign: 'left', cursor: 'pointer',
                  background: active ? 'color-mix(in srgb, var(--cat-accent) 12%, transparent)' : 'transparent',
                  color: active ? 'var(--cat-accent)' : 'var(--cat-text)',
                }}
              >
                {Icon && <Icon size={15} style={{ opacity: 0.85, flexShrink: 0 }} />}
                <span style={{ fontSize: 13, fontWeight: 500 }}>{item.label}</span>
                <span style={{ marginLeft: 'auto', fontSize: 10.5, color: 'var(--cat-sub)' }}>{item.group}</span>
              </button>
            )
          })}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '8px 16px', borderTop: '1px solid var(--cat-border)', fontSize: 10.5, color: 'var(--cat-sub)' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><ArrowUp size={11} /><ArrowDown size={11} /> Navigate</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><CornerDownLeft size={11} /> Open</span>
        </div>
      </div>
    </div>
  )
}
