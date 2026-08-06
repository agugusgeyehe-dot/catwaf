import { createContext, useContext, useEffect, useState, useCallback } from 'react'

const DEFAULTS = {
  theme: 'black',
  motion: 'full',
  mapProjection: '2d',
  mapAutoRotate: 'on',
  mapPerformance: 'balanced',
  dashboardAttackTypes: 'on',
  dashboardRecentRequests: 'on',
  dashboardTopTargets: 'on',
  accentCustom: '',
}

const KEYS = {
  theme: 'catwaf-theme',
  motion: 'catwaf-motion',
  mapProjection: 'catwaf-map-projection',
  mapAutoRotate: 'catwaf-map-autorotate',
  mapPerformance: 'catwaf-map-performance',
  dashboardAttackTypes: 'catwaf-dash-attacktypes',
  dashboardRecentRequests: 'catwaf-dash-recentreq',
  dashboardTopTargets: 'catwaf-dash-toptargets',
  accentCustom: 'catwaf-accent-custom',
}

const ATTR = {
  theme: 'data-theme',
  motion: 'data-motion',
}

const ALLOWED = {
  theme: ['dark', 'black', 'white', 'midnight'],
  motion: ['full', 'reduced', 'minimal', 'off'],
  mapProjection: ['2d', '3d'],
  mapAutoRotate: ['on', 'off'],
  mapPerformance: ['low', 'balanced', 'high'],
  dashboardAttackTypes: ['on', 'off'],
  dashboardRecentRequests: ['on', 'off'],
  dashboardTopTargets: ['on', 'off'],
}

const HEX_COLOR = /^#[0-9a-f]{6}$/i

function sanitize(field, value) {
  if (typeof value !== 'string') return null
  if (field === 'accentCustom') return value === '' || HEX_COLOR.test(value) ? value : null
  return ALLOWED[field]?.includes(value) ? value : null
}

function safeGet(key) {
  try { return localStorage.getItem(key) } catch { return null }
}
function safeSet(key, value) {
  try { localStorage.setItem(key, value) } catch {  }
}

function readInitial() {
  const prefersReducedMotion = typeof window !== 'undefined'
    && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
  const out = { ...DEFAULTS }
  for (const [field, storageKey] of Object.entries(KEYS)) {
    const clean = sanitize(field, safeGet(storageKey))
    if (clean !== null) out[field] = clean
  }
  if (!safeGet(KEYS.motion) && prefersReducedMotion) out.motion = 'reduced'
  return out
}

const PreferencesContext = createContext(null)

export function PreferencesProvider({ children }) {
  const [prefs, setPrefs] = useState(readInitial)

  useEffect(() => {
    const root = document.documentElement
    for (const [field, attr] of Object.entries(ATTR)) {
      root.setAttribute(attr, prefs[field])
    }
    for (const [field, storageKey] of Object.entries(KEYS)) {
      safeSet(storageKey, prefs[field])
    }
    const accent = sanitize('accentCustom', prefs.accentCustom)
    if (accent) root.style.setProperty('--cat-accent-custom', sanitize('accentCustom', accent))
    else root.style.removeProperty('--cat-accent-custom')
  }, [prefs])

  const set = useCallback((field, value) => {
    const clean = sanitize(field, value)
    if (clean === null) return
    setPrefs(p => ({ ...p, [field]: clean }))
  }, [])

  const reset = useCallback(() => setPrefs(DEFAULTS), [])

  return (
    <PreferencesContext.Provider value={{ prefs, set, reset, defaults: DEFAULTS }}>
      {children}
    </PreferencesContext.Provider>
  )
}

export function usePreferences() {
  const ctx = useContext(PreferencesContext)
  if (!ctx) throw new Error('usePreferences must be used within PreferencesProvider')
  return ctx
}
