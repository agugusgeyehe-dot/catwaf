
import { useCallback, useEffect, useRef, useState } from 'react'
import { X, Send, MessageCircle } from 'lucide-react'
import { api, postStream } from '../../utils/api.js'
import { Mascot, ActivityTrail } from './Mascot.jsx'
import { ActionCard } from './ActionCard.jsx'
import { Markdown } from './Markdown.jsx'

const WELCOME = "Hi, I'm CatAI — ask me anything about CatWAF, or tell me what you want to change (\"block traffic from China\", \"set paranoia to 2\")."

const POS_KEY = 'catai-dock-pos'
const PANEL_POS_KEY = 'catai-panel-pos'
const BUTTON_SIZE = 52
const CLOSE_MS = 180
const MARGIN = 22

function defaultPos() {
  return { x: window.innerWidth - BUTTON_SIZE - MARGIN, y: window.innerHeight - BUTTON_SIZE - MARGIN }
}
function loadPos() {
  try {
    const saved = JSON.parse(localStorage.getItem(POS_KEY) || 'null')
    if (saved && Number.isFinite(saved.x) && Number.isFinite(saved.y)) return clampPos(saved)
  } catch {}
  return defaultPos()
}
function clampPos({ x, y }) {
  const maxX = window.innerWidth - BUTTON_SIZE - 4
  const maxY = window.innerHeight - BUTTON_SIZE - 4
  return { x: Math.min(Math.max(x, 4), Math.max(4, maxX)), y: Math.min(Math.max(y, 4), Math.max(4, maxY)) }
}

// The chat panel itself can also be dragged around (grab it by the header
// or the footer strip — its "outline") independently of the round toggle
// button. Position is only ever set once the user actually drags it; until
// then the panel stays anchored next to the button, same as before.
// 380/520 mirror the panel's base width/height in CSS — the real box can
// only ever be smaller (max-width/max-height cap it on small viewports),
// so clamping against these is always at least as strict as clamping
// against the actual rendered size.
const PANEL_BASE_W = 380
const PANEL_BASE_H = 520
function loadPanelPos() {
  try {
    const saved = JSON.parse(localStorage.getItem(PANEL_POS_KEY) || 'null')
    // Clamp against the *current* viewport at load time too — otherwise a
    // position saved on a larger screen/window can reopen off-screen and
    // unreachable on a smaller one, only fixing itself on the next resize.
    if (saved && Number.isFinite(saved.x) && Number.isFinite(saved.y)) return clampPanelPos(saved, PANEL_BASE_W, PANEL_BASE_H)
  } catch {}
  return null
}
function clampPanelPos({ x, y }, w, h) {
  const maxX = window.innerWidth - w - 4
  const maxY = window.innerHeight - h - 4
  return { x: Math.min(Math.max(x, 4), Math.max(4, maxX)), y: Math.min(Math.max(y, 4), Math.max(4, maxY)) }
}

export function CatAIDock() {
  const [open, setOpen] = useState(false)
  const [status, setStatus] = useState(null)
  const [messages, setMessages] = useState([{ role: 'assistant', text: WELCOME, sources: [] }])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [mascotState, setMascotState] = useState('idle')
  const [trail, setTrail] = useState([])
  const [pos, setPos] = useState(loadPos)
  const [panelPos, setPanelPos] = useState(loadPanelPos)
  const [closing, setClosing] = useState(false)
  const closeTimer = useRef(null)
  const dragRef = useRef({ dragging: false, moved: false, startX: 0, startY: 0, origX: 0, origY: 0 })
  const panelDragRef = useRef({ dragging: false, moved: false, startX: 0, startY: 0, origX: 0, origY: 0, w: 0, h: 0 })
  const inputRef = useRef(null)
  const listRef = useRef(null)
  const panelRef = useRef(null)

  const closePanel = useCallback(() => {
    if (closeTimer.current) return
    setClosing(true)
    closeTimer.current = setTimeout(() => {
      setOpen(false)
      setClosing(false)
      closeTimer.current = null
    }, CLOSE_MS)
  }, [])

  const togglePanel = useCallback(() => {
    if (open) closePanel()
    else {
      if (closeTimer.current) { clearTimeout(closeTimer.current); closeTimer.current = null }
      setClosing(false)
      setOpen(true)
    }
  }, [open, closePanel])

  useEffect(() => () => { if (closeTimer.current) clearTimeout(closeTimer.current) }, [])

  useEffect(() => {
    if (open && status === null) {
      api.get('/catai/status').then(setStatus).catch(() => setStatus({ configured: false }))
    }
  }, [open, status])

  useEffect(() => {
    if (!open) return
    function onKeyDown(e) {
      if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return
      const el = document.activeElement
      const alreadyTyping = el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)
      if (alreadyTyping && el !== inputRef.current) return
      if (el === inputRef.current) return
      e.preventDefault()
      inputRef.current?.focus()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open])

  useEffect(() => {
    const onResize = () => {
      setPos(p => clampPos(p))
      setPanelPos(p => {
        if (!p) return p
        const rect = panelRef.current?.getBoundingClientRect()
        return clampPanelPos(p, rect?.width || PANEL_BASE_W, rect?.height || PANEL_BASE_H)
      })
    }
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  function onPointerDown(e) {
    const d = dragRef.current
    d.dragging = true
    d.moved = false
    d.startX = e.clientX
    d.startY = e.clientY
    d.origX = pos.x
    d.origY = pos.y
    e.currentTarget.setPointerCapture(e.pointerId)
  }
  function onPointerMove(e) {
    const d = dragRef.current
    if (!d.dragging) return
    const dx = e.clientX - d.startX
    const dy = e.clientY - d.startY
    if (Math.abs(dx) > 4 || Math.abs(dy) > 4) d.moved = true
    if (d.moved) setPos(clampPos({ x: d.origX + dx, y: d.origY + dy }))
  }
  function onPointerUp() {
    const d = dragRef.current
    d.dragging = false
    if (d.moved) {
      setPos(p => { try { localStorage.setItem(POS_KEY, JSON.stringify(p)) } catch {} ; return p })
    } else {
      togglePanel()
    }
  }

  // Dragging from the panel's own outline (header bar or footer strip),
  // not just the round toggle button. Ignores drags that start on an
  // actual control (close button etc.) so those keep working normally.
  function onPanelDragStart(e) {
    if (e.target.closest('button, input, textarea, a')) return
    const rect = panelRef.current.getBoundingClientRect()
    const d = panelDragRef.current
    d.dragging = true
    d.moved = false
    d.startX = e.clientX
    d.startY = e.clientY
    d.origX = rect.left
    d.origY = rect.top
    d.w = rect.width
    d.h = rect.height
    e.currentTarget.setPointerCapture(e.pointerId)
  }
  function onPanelDragMove(e) {
    const d = panelDragRef.current
    if (!d.dragging) return
    const dx = e.clientX - d.startX
    const dy = e.clientY - d.startY
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) d.moved = true
    if (d.moved) setPanelPos(clampPanelPos({ x: d.origX + dx, y: d.origY + dy }, d.w, d.h))
  }
  function onPanelDragEnd() {
    const d = panelDragRef.current
    d.dragging = false
    if (d.moved) {
      setPanelPos(p => { try { localStorage.setItem(PANEL_POS_KEY, JSON.stringify(p)) } catch {} ; return p })
    }
  }

  const openUp = pos.y > window.innerHeight / 2
  const openLeft = pos.x > window.innerWidth / 2
  const panelStyle = panelPos
    ? { top: panelPos.y, left: panelPos.x, right: 'auto', bottom: 'auto', transformOrigin: 'center center' }
    : {
      top: openUp ? 'auto' : pos.y + BUTTON_SIZE + 12,
      bottom: openUp ? window.innerHeight - pos.y + 12 : 'auto',
      left: openLeft ? 'auto' : pos.x,
      right: openLeft ? window.innerWidth - pos.x - BUTTON_SIZE : 'auto',
      transformOrigin: `${openLeft ? 'right' : 'left'} ${openUp ? 'bottom' : 'top'}`,
    }

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages, trail])

  async function send() {
    const text = input.trim()
    if (!text || sending) return
    setInput('')
    setSending(true)
    setMascotState('thinking')
    setTrail([])
    setMessages(m => [...m, { role: 'user', text }])

    setMessages(m => [...m, { role: 'assistant', text: '', sources: [], action: null, streaming: true }])

    let full = ''
    let action = null
    let correction = null

    try {
      await postStream('/catai/chat', { message: text }, (frame) => {
        if (frame.t === 'status') {
          if (frame.v === 'acted') setMascotState('acted')
          else if (frame.v === 'nomatch') setMascotState('idle')
          if (frame.detail) setTrail(t => (t.includes(frame.detail) ? t : [...t, frame.detail]))
        } else if (frame.t === 'token') {
          full += frame.v
          setMascotState(s => (s === 'acted' ? s : 'talking'))
          setMessages(m => updateLast(m, { text: full }))
        } else if (frame.t === 'correction') {
          correction = frame.v
        } else if (frame.t === 'action') {
          action = frame.v
        } else if (frame.t === 'error') {
          setMessages(m => updateLast(m, { text: frame.detail || 'Something went wrong.', error: true }))
        } else if (frame.t === 'done') {
          setMessages(m => updateLast(m, {
            text: correction || full,
            sources: frame.v?.sources || [],
            action,
            streaming: false,
          }))
        }
      })
    } catch (e) {
      setMessages(m => updateLast(m, { text: e.message || 'Something went wrong.', error: true, streaming: false }))
    } finally {
      setSending(false)
      setMascotState('idle')
    }
  }

  function updateLast(list, patch) {
    const next = list.slice()
    next[next.length - 1] = { ...next[next.length - 1], ...patch }
    return next
  }

  const disabled = status && status.configured === false

  return (
    <>
      <button
        className={`catai-dock-button ${closing ? 'closing' : ''}`}
        style={{ left: pos.x, top: pos.y, right: 'auto', bottom: 'auto' }}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        aria-label={open ? 'Close CatAI' : 'Open CatAI (drag to move)'}
        aria-expanded={open}
        title="CatAI assistant — drag to move"
      >
        <span className="catai-dock-icon" key={open && !closing ? 'x' : 'cat'}>
          {open && !closing ? <X size={18} /> : <Mascot state={mascotState} size={28} />}
        </span>
      </button>

      {open && (
        <div className={`catai-panel ${closing ? 'catai-panel-closing' : ''}`} style={panelStyle} ref={panelRef}>
          <div
            className="catai-panel-header catai-panel-drag"
            onPointerDown={onPanelDragStart}
            onPointerMove={onPanelDragMove}
            onPointerUp={onPanelDragEnd}
            title="Drag to move"
          >
            <Mascot state={mascotState} size={22} />
            <span>CatAI</span>
            <button className="catai-panel-close" onClick={closePanel}><X size={16} /></button>
          </div>

          <div className="catai-panel-body" ref={listRef}>
            {disabled && (
              <div className="catai-disabled-notice">
                <MessageCircle size={16} />
                <div>
                  <strong>CatAI isn't set up yet.</strong>
                  <p>{status?.detail || 'Run `catwaf --setup` and choose to install CatAI, or set CATAI_ENABLED=true once a model is pulled.'}</p>
                </div>
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={`catai-msg catai-msg-${m.role}`}>
                {m.role === 'assistant' && (m.text || m.streaming) && <Markdown text={m.text} />}
                {m.role === 'user' && <div className="catai-user-bubble">{m.text}</div>}
                {m.error && <div className="catai-msg-error">{m.text}</div>}
                {i === messages.length - 1 && m.streaming && <ActivityTrail entries={trail} done={false} />}
                {m.action && <ActionCard action={m.action} />}
                {m.sources && m.sources.length > 0 && (
                  <div className="catai-sources">Sources: {m.sources.join(', ')}</div>
                )}
              </div>
            ))}
            {sending && !messages[messages.length - 1]?.text && <ActivityTrail entries={trail} done={false} />}
          </div>

          <div
            className="catai-disclaimer catai-panel-drag"
            onPointerDown={onPanelDragStart}
            onPointerMove={onPanelDragMove}
            onPointerUp={onPanelDragEnd}
            title="Drag to move"
          >
            CatAI can be wrong — verify before applying.
          </div>

          <div className="catai-panel-input">
            <input
              ref={inputRef}
              className="input"
              placeholder={disabled ? 'CatAI is not available' : 'Ask CatAI…  (press / to focus)'}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !e.shiftKey && send()}
              disabled={disabled || sending}
            />
            <button className="btn btn-primary catai-send" onClick={send} disabled={disabled || sending || !input.trim()}>
              <Send size={14} />
            </button>
          </div>
        </div>
      )}
    </>
  )
}
