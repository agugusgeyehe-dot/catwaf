import { useEffect, useState, useCallback, useMemo } from 'react'
import { Globe2, RotateCcw, Pause, Play, AlertTriangle, ShieldAlert, ChevronRight, Box, Square, X } from 'lucide-react'
import { api } from '../utils/api.js'
import { usePreferences } from '../utils/preferences.jsx'
import { getLandDotGrid } from '../utils/worldLandmask.js'
import { Skeleton, EmptyState } from '../components/ui.jsx'
import AttackGlobeCanvas from '../components/attackmap/AttackGlobeCanvas.jsx'
import { severityMeta } from '../utils/severity.js'

const WINDOW_OPTIONS = [
  { id: '1h',  label: '1h' },
  { id: '24h', label: '24h' },
  { id: '7d',  label: '7d' },
]

const PERFORMANCE_LAND_STEP = { low: 4, balanced: 2.2, high: 1.4 }
const PERFORMANCE_MARKER_CAP = { low: 100, balanced: 300, high: 600 }

export default function AttackMap() {
  const { prefs, set: setPref } = usePreferences()
  const motionOff = prefs.motion === 'off'
  const motionLevel = prefs.motion

  const [points, setPoints] = useState(null)
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [windowSpec, setWindowSpec] = useState('24h')
  const [selectedType, setSelectedType] = useState('all')
  const [selected, setSelected] = useState(null)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [resetSignal, setResetSignal] = useState(0)

  const mode = prefs.mapProjection
  const setMode = v => setPref('mapProjection', v)
  const autoRotate = prefs.mapAutoRotate === 'on'
  const setAutoRotate = fn => setPref('mapAutoRotate', (typeof fn === 'function' ? fn(autoRotate) : fn) ? 'on' : 'off')

  const landDots = useMemo(() => getLandDotGrid(PERFORMANCE_LAND_STEP[prefs.mapPerformance] || 2.2), [prefs.mapPerformance])
  const markerCap = PERFORMANCE_MARKER_CAP[prefs.mapPerformance] || 300

  const fetchData = useCallback(async () => {
    try {
      const [mapRes, summaryRes] = await Promise.all([
        api.get(`/attack-map?window=${windowSpec}`),
        api.get(`/audit/summary?last=${windowSpec}&limit=25`),
      ])
      setPoints(mapRes.points || [])
      setEvents(summaryRes.recent_attacks || [])
      setError(null)
    } catch (e) {
      setError(e.message || 'Failed to load attack map data')
    } finally {
      setLoading(false)
    }
  }, [windowSpec])

  useEffect(() => {
    setLoading(true)
    fetchData()
    if (!autoRefresh) return
    const id = setInterval(fetchData, 15000)
    return () => clearInterval(id)
  }, [fetchData, autoRefresh])

  const attackTypes = useMemo(() => {
    if (!points) return []
    const set = new Set()
    points.forEach(p => Object.keys(p.attack_types || {}).forEach(t => set.add(t)))
    return [...set].sort()
  }, [points])

  const visiblePoints = useMemo(() => {
    if (!points) return []
    if (selectedType === 'all') return points
    return points.filter(p => (p.attack_types || {})[selectedType])
  }, [points, selectedType])

  const activity = points ? points.reduce((s, p) => s + p.count, 0) : 0

  return (
    <div className="p-6 space-y-4 page-enter" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--cat-text)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Globe2 size={18} style={{ opacity: 0.8 }} /> Attack Map
          </div>
          <div style={{ fontSize: 12, color: 'var(--cat-sub)', marginTop: 2 }}>
            {loading ? 'Loading real attack telemetry…' : points?.length
              ? `${activity.toLocaleString()} blocked requests across ${points.length} location${points.length === 1 ? '' : 's'}`
              : 'No geolocated attack traffic in this window'}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: 2, background: 'var(--cat-surface)', border: '1px solid var(--cat-border)', borderRadius: 8, padding: 2 }}>
            <button className={`btn btn-sm ${mode === '2d' ? 'btn-primary' : 'btn-ghost'}`} onClick={() => setMode('2d')} title="2D map">
              <Square size={12} /> 2D
            </button>
            <button className={`btn btn-sm ${mode === '3d' ? 'btn-primary' : 'btn-ghost'}`} onClick={() => setMode('3d')} title="3D planet">
              <Box size={12} /> 3D
            </button>
          </div>
          {WINDOW_OPTIONS.map(w => (
            <button key={w.id} className={`btn btn-sm ${windowSpec === w.id ? 'btn-primary' : 'btn-ghost'}`} onClick={() => setWindowSpec(w.id)}>
              {w.label}
            </button>
          ))}
          {mode === '3d' && (
            <button className={`btn btn-sm ${autoRotate ? 'btn-primary' : 'btn-ghost'}`} onClick={() => setAutoRotate(a => !a)} title="Toggle auto-rotate">
              Auto-rotate
            </button>
          )}
          {mode === '3d' && (
            <button className="btn btn-sm btn-ghost" onClick={() => setResetSignal(s => s + 1)} title="Reset camera">
              Reset view
            </button>
          )}
          <button className="btn btn-sm btn-ghost" onClick={() => setAutoRefresh(a => !a)} title={autoRefresh ? 'Pause live updates' : 'Resume live updates'}>
            {autoRefresh ? <Pause size={13} /> : <Play size={13} />}
          </button>
          <button className="btn btn-sm btn-ghost" onClick={fetchData} title="Refresh now">
            <RotateCcw size={13} />
          </button>
        </div>
      </div>

      {attackTypes.length > 0 && (
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <button className={`btn btn-sm ${selectedType === 'all' ? 'btn-primary' : 'btn-ghost'}`} onClick={() => setSelectedType('all')}>
            All types
          </button>
          {attackTypes.map(t => (
            <button key={t} className={`btn btn-sm ${selectedType === t ? 'btn-primary' : 'btn-ghost'}`} onClick={() => setSelectedType(t)}>
              {t}
            </button>
          ))}
        </div>
      )}

      <div className="attack-map-layout" style={{ display: 'flex', gap: 16, flex: 1, minHeight: 0 }}>
        <div className="card" style={{ flex: 1, minWidth: 0, minHeight: 320, position: 'relative', padding: 0, overflow: 'hidden' }}>
          {loading && !points ? (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Skeleton h="h-full" className="w-full" />
            </div>
          ) : error ? (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <EmptyState icon={AlertTriangle} title="Could not load the Attack Map" desc={error} />
            </div>
          ) : (
            <>
              <AttackGlobeCanvas
                landDots={landDots}
                points={visiblePoints}
                markerCap={markerCap}
                selected={selected}
                onSelect={setSelected}
                mode={mode}
                autoRotate={autoRotate}
                motionOff={motionOff}
                resetSignal={resetSignal}
              />
              {points && points.length === 0 && (
                <div style={{
                  position: 'absolute', bottom: 16, left: '50%', transform: 'translateX(-50%)',
                  display: 'flex', alignItems: 'center', gap: 8, padding: '8px 14px',
                  background: 'var(--cat-card-final, var(--cat-card))', border: '1px solid var(--cat-border)',
                  borderRadius: 999, fontSize: 11.5, color: 'var(--cat-sub)', pointerEvents: 'none',
                }}>
                  <Globe2 size={13} /> No attack activity in this window — once CatWAF blocks requests with resolvable public IPs, they'll appear here live.
                </div>
              )}
            </>
          )}

          {selected && (
            <div style={{
              position: 'absolute', bottom: 14, left: 14, background: 'var(--cat-card-final, var(--cat-card))',
              border: '1px solid var(--cat-border)', borderRadius: 10, padding: '10px 14px', minWidth: 200,
              boxShadow: '0 8px 24px rgba(0,0,0,0.35)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
                <div style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--cat-text)' }}>
                  {selected.city ? `${selected.city}, ` : ''}{selected.country_code || 'Unknown'}
                </div>
                <button onClick={() => setSelected(null)} aria-label="Close" style={{ background: 'none', border: 'none', color: 'var(--cat-sub)', cursor: 'pointer', display: 'flex' }}><X size={13} /></button>
              </div>
              <div style={{ fontSize: 11, color: 'var(--cat-sub)', marginTop: 4 }}>{selected.count} blocked request{selected.count === 1 ? '' : 's'}</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6 }}>
                {Object.entries(selected.attack_types || {}).map(([t, n]) => (
                  <span key={t} className="badge badge-muted">{t} · {n}</span>
                ))}
              </div>
            </div>
          )}

          <div style={{ position: 'absolute', top: 12, right: 12, display: 'flex', gap: 8, fontSize: 10, color: 'var(--cat-sub)' }}>
            {Object.entries({ Critical: '#f25c5c', High: '#f59e0b', Medium: '#eab308', Low: '#7c8db0' }).map(([label, color]) => (
              <span key={label} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: color }} /> {label}
              </span>
            ))}
          </div>
        </div>

        <div className="card attack-map-events" style={{ width: 300, flexShrink: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
          <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--cat-border)', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--cat-sub)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <ShieldAlert size={13} /> Live Events
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: 8 }}>
            {events.length === 0 && !loading && (
              <div style={{ padding: 16, textAlign: 'center', fontSize: 11.5, color: 'var(--cat-sub)' }}>No blocked requests in this window.</div>
            )}
            {events.map((e, i) => {
              const meta = severityMeta(e.severity)
              return (
                <button
                  key={e.id}
                  onClick={() => e.lat != null && setSelected({ lat: e.lat, lon: e.lon, country_code: e.country_code, city: e.city, count: 1, attack_types: e.attack_type ? { [e.attack_type]: 1 } : {} })}
                  className={motionOff ? '' : 'animate-slide-in'}
                  style={{
                    width: '100%', display: 'flex', flexDirection: 'column', gap: 3, textAlign: 'left',
                    background: 'transparent', border: 'none', borderBottom: '1px solid var(--cat-border)',
                    padding: '9px 6px', cursor: e.lat != null ? 'pointer' : 'default',
                    animationDelay: motionOff ? undefined : `${Math.min(i, 8) * 30}ms`,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: meta.color, flexShrink: 0 }} />
                    <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--cat-text)' }}>{e.attack_type || 'Anomaly'}</span>
                    <span style={{ marginLeft: 'auto', fontSize: 9.5, color: 'var(--cat-sub)' }}>{meta.label}</span>
                  </div>
                  <div style={{ fontSize: 10.5, color: 'var(--cat-sub)', display: 'flex', alignItems: 'center', gap: 4 }}>
                    {e.client_ip || 'unknown ip'}{e.country_code ? ` · ${e.country_code}` : ''}
                    <ChevronRight size={10} style={{ marginLeft: 'auto', opacity: 0.5 }} />
                  </div>
                </button>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
