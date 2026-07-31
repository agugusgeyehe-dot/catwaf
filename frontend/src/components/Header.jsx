import React, { useEffect, useState, useCallback } from 'react'
import { useLocation } from 'react-router-dom'
import { Menu, RefreshCw, Search, Bell, HelpCircle, LogOut, ChevronRight } from 'lucide-react'
import { useAuth } from '../auth/AuthContext.jsx'
import { StatusPill } from './ui.jsx'
import { api } from '../utils/api.js'
import { NAV } from './Sidebar.jsx'
import CommandPalette from './CommandPalette.jsx'
import { severityMeta } from '../utils/severity.js'

const FLAT_ITEMS = NAV.flatMap(g => g.items.map(i => ({ ...i, group: g.group })))

function useBreadcrumb() {
  const { pathname } = useLocation()
  const match = FLAT_ITEMS.find(i => i.path === pathname)
    || FLAT_ITEMS.filter(i => pathname.startsWith(i.path) && i.path !== '/').sort((a, b) => b.path.length - a.path.length)[0]
  if (!match) return { group: null, label: pathname === '/' ? 'Dashboard' : pathname }
  return { group: match.group, label: match.label }
}

export default function Header({ onMenuClick }) {
  const { user, logout } = useAuth()
  const [engineMode, setEngineMode] = useState('On')
  const [spinning, setSpinning] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [notifOpen, setNotifOpen] = useState(false)
  const [notifications, setNotifications] = useState([])
  const crumb = useBreadcrumb()

  useEffect(() => {
    api.get('/waf/engine').then(d => setEngineMode(d.mode)).catch(() => {})
    const iv = setInterval(() => api.get('/waf/engine').then(d => setEngineMode(d.mode)).catch(() => {}), 10000)
    return () => clearInterval(iv)
  }, [])

  useEffect(() => {
    const load = () => api.get('/audit/summary?last=1h&limit=8').then(d => setNotifications(d.recent_attacks || [])).catch(() => {})
    load()
    const iv = setInterval(load, 30000)
    return () => clearInterval(iv)
  }, [])

  const openPalette = useCallback(() => setPaletteOpen(true), [])

  useEffect(() => {
    function onKey(e) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        openPalette()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [openPalette])

  const refresh = () => {
    setSpinning(true)
    setTimeout(() => { setSpinning(false); window.location.reload() }, 400)
  }

  return (
    <>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
      {notifOpen && <div style={{ position: 'fixed', inset: 0, zIndex: 998 }} onClick={() => setNotifOpen(false)} />}

      <header style={{
        height: 48,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 16px',
        borderBottom: '1px solid var(--cat-border)',
        background: 'var(--cat-surface-final, var(--cat-surface))',
        flexShrink: 0,
        position: 'relative',
        transition: 'background 0.3s ease, border-color 0.3s ease',
        gap: 12,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
          <button className="btn btn-ghost btn-sm" onClick={onMenuClick} style={{ padding: '6px 8px' }} aria-label="Toggle sidebar">
            <Menu size={17} />
          </button>
          <div className="hide-mobile" style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--cat-sub)', minWidth: 0, whiteSpace: 'nowrap' }}>
            <span>CatWAF</span>
            {crumb.group && <><ChevronRight size={12} /><span>{crumb.group}</span></>}
            <ChevronRight size={12} />
            <span style={{ color: 'var(--cat-text)', fontWeight: 600 }}>{crumb.label}</span>
          </div>
        </div>

        <button
          onClick={openPalette}
          className="hide-mobile"
          style={{
            display: 'flex', alignItems: 'center', gap: 8, flex: 1, maxWidth: 360,
            background: 'var(--cat-surface-final, var(--cat-surface))', border: '1px solid var(--cat-border)',
            borderRadius: 8, padding: '5px 10px', color: 'var(--cat-sub)', cursor: 'pointer', fontSize: 12,
          }}
        >
          <Search size={13} />
          <span style={{ flex: 1, textAlign: 'left' }}>Search…</span>
          <kbd style={{ fontSize: 9.5, border: '1px solid var(--cat-border)', borderRadius: 4, padding: '1px 5px' }}>⌘K</kbd>
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <button className="btn btn-ghost btn-sm hide-mobile" onClick={openPalette} title="Search (Cmd/Ctrl+K)" aria-label="Open command palette">
            <Search size={14} />
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="dot-green" />
            <span className="hide-mobile" style={{ fontSize: 11, color: 'var(--cat-sub)' }}>WAF</span>
            <StatusPill mode={engineMode} />
          </div>

          <button className="btn btn-ghost btn-sm" onClick={refresh} title="Refresh">
            <RefreshCw size={14} className={spinning ? 'spin' : ''} />
          </button>

          <div style={{ position: 'relative' }}>
            <button className="btn btn-ghost btn-sm" onClick={() => setNotifOpen(o => !o)} title="Recent security events" style={{ position: 'relative' }}>
              <Bell size={14} />
              {notifications.length > 0 && (
                <span style={{ position: 'absolute', top: 2, right: 2, width: 6, height: 6, borderRadius: '50%', background: '#f25c5c' }} />
              )}
            </button>
            {notifOpen && (
              <div role="region" aria-label="Recent blocked requests" style={{
                position: 'absolute', top: 'calc(100% + 6px)', right: 0, zIndex: 999,
                width: 300, background: 'var(--cat-card-final, var(--cat-card))', border: '1px solid var(--cat-border)',
                borderRadius: 10, boxShadow: '0 12px 40px rgba(0,0,0,0.5)', overflow: 'hidden',
                animation: 'cardIn 0.18s cubic-bezier(0.16,1,0.3,1) both',
              }}>
                <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--cat-border)', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--cat-sub)' }}>
                  Recent Blocked Requests
                </div>
                <div style={{ maxHeight: 280, overflowY: 'auto' }}>
                  {notifications.length === 0 ? (
                    <div style={{ padding: 16, fontSize: 12, color: 'var(--cat-sub)', textAlign: 'center' }}>No blocked requests in the last hour.</div>
                  ) : notifications.map(n => {
                    const meta = severityMeta(n.severity)
                    return (
                      <div key={n.id} style={{ display: 'flex', gap: 8, padding: '9px 12px', borderBottom: '1px solid var(--cat-border)' }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: meta.color, marginTop: 5, flexShrink: 0 }} />
                        <div style={{ minWidth: 0 }}>
                          <div style={{ fontSize: 12, color: 'var(--cat-text)', fontWeight: 600 }}>{n.attack_type || 'Anomaly'} blocked</div>
                          <div style={{ fontSize: 10.5, color: 'var(--cat-sub)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.client_ip || 'unknown'} · {new Date(n.timestamp).toLocaleTimeString()}</div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </div>

          <button className="btn btn-ghost btn-sm hide-mobile" title="Replay the welcome tour" aria-label="Help" onClick={() => window.dispatchEvent(new CustomEvent('catwaf-open-tour'))}>
            <HelpCircle size={14} />
          </button>

          <div style={{ width: 1, height: 20, background: 'var(--cat-border)', margin: '0 2px' }} />

          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <div style={{
              width: 26, height: 26, borderRadius: 8,
              background: 'color-mix(in srgb, var(--cat-accent) 20%, transparent)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 12, fontWeight: 700, color: 'var(--cat-accent)',
              flexShrink: 0,
            }}>
              {user?.username?.[0]?.toUpperCase() || '?'}
            </div>
            <span className="hide-mobile" style={{ fontSize: 12, color: 'var(--cat-sub)' }}>
              {user?.username}
            </span>
            <button className="btn btn-ghost btn-sm" onClick={logout} title="Sign out" style={{ padding: '5px 6px' }} aria-label="Sign out">
              <LogOut size={14} />
            </button>
          </div>

        </div>
      </header>
    </>
  )
}
