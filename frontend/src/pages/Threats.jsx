import React, { useEffect, useState, useCallback, useMemo } from 'react'
import { ShieldAlert, AlertTriangle, X, Filter } from 'lucide-react'
import { api } from '../utils/api.js'
import { EmptyState, Skeleton, SectionTitle } from '../components/ui.jsx'
import { severityMeta } from '../utils/severity.js'

const WINDOW_OPTIONS = [
  { id: '1h', label: '1h' }, { id: '24h', label: '24h' }, { id: '7d', label: '7d' }, { id: '30d', label: '30d' },
]
const SEVERITY_OPTIONS = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug']

export default function ThreatsPage() {
  const [windowSpec, setWindowSpec] = useState('24h')
  const [attackType, setAttackType] = useState('')
  const [severity, setSeverity] = useState('')
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)

  const load = useCallback(() => {
    setLoading(true)
    const params = new URLSearchParams({ last: windowSpec, limit: '100' })
    if (attackType) params.set('attack', attackType)
    if (severity) params.set('severity', severity)
    api.get(`/audit/summary?${params.toString()}`)
      .then(d => { setData(d); setError(null) })
      .catch(e => setError(e.message || 'Failed to load threats'))
      .finally(() => setLoading(false))
  }, [windowSpec, attackType, severity])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    if (!data) return
    const iv = setInterval(load, 20000)
    return () => clearInterval(iv)
  }, [data, load])

  const attackTypeOptions = useMemo(() => {
    if (!data) return []
    return data.top_attack_types.map(t => t.attack_type).filter(Boolean)
  }, [data])

  return (
    <div className="p-6 space-y-4 page-enter">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--cat-text)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldAlert size={18} style={{ opacity: 0.8 }} /> Threats
          </div>
          <div style={{ fontSize: 12, color: 'var(--cat-sub)', marginTop: 2 }}>
            {data ? `${data.blocked_requests.toLocaleString()} blocked of ${data.total_requests.toLocaleString()} requests · ${(data.block_rate * 100).toFixed(1)}% block rate` : 'Loading…'}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {WINDOW_OPTIONS.map(w => (
            <button key={w.id} className={`btn btn-sm ${windowSpec === w.id ? 'btn-primary' : 'btn-ghost'}`} onClick={() => setWindowSpec(w.id)}>{w.label}</button>
          ))}
        </div>
      </div>

      <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', padding: 12 }}>
        <Filter size={14} style={{ color: 'var(--cat-sub)', flexShrink: 0 }} />
        <select className="input select" style={{ width: 'auto' }} value={attackType} onChange={e => setAttackType(e.target.value)}>
          <option value="">All attack types</option>
          {attackTypeOptions.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select className="input select" style={{ width: 'auto' }} value={severity} onChange={e => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          {SEVERITY_OPTIONS.map(s => <option key={s} value={s}>{severityMeta(s).label} ({s})</option>)}
        </select>
        {(attackType || severity) && (
          <button className="btn btn-sm btn-ghost" onClick={() => { setAttackType(''); setSeverity('') }}>Clear filters</button>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="card lg:col-span-1">
          <SectionTitle>Top Attack Types</SectionTitle>
          {!data || data.top_attack_types.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--cat-sub)' }}>No categorized attacks in this window.</div>
          ) : (
            <div className="space-y-2">
              {data.top_attack_types.slice(0, 6).map(t => (
                <div key={t.attack_type} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                  <span style={{ color: 'var(--cat-text)' }}>{t.attack_type}</span>
                  <span style={{ color: 'var(--cat-sub)', fontFamily: 'monospace' }}>{t.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="card lg:col-span-1">
          <SectionTitle>Severity Distribution</SectionTitle>
          {!data || data.severity_distribution.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--cat-sub)' }}>No severity data in this window.</div>
          ) : (
            <div className="space-y-2">
              {data.severity_distribution.map(s => {
                const meta = severityMeta(s.severity)
                return (
                  <div key={s.severity} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: meta.color, flexShrink: 0 }} />
                    <span style={{ color: 'var(--cat-text)', flex: 1 }}>{meta.label}</span>
                    <span style={{ color: 'var(--cat-sub)', fontFamily: 'monospace' }}>{s.count}</span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
        <div className="card lg:col-span-1">
          <SectionTitle>Top Source IPs</SectionTitle>
          {!data || data.top_source_ips.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--cat-sub)' }}>No blocked source IPs in this window.</div>
          ) : (
            <div className="space-y-2">
              {data.top_source_ips.slice(0, 6).map(ip => (
                <div key={ip.ip} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                  <span style={{ color: 'var(--cat-text)', fontFamily: 'monospace' }}>{ip.ip}</span>
                  <span style={{ color: 'var(--cat-sub)', fontFamily: 'monospace' }}>{ip.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <SectionTitle>Threat Feed</SectionTitle>
        {loading && !data ? (
          <Skeleton h="h-64" className="w-full" />
        ) : error ? (
          <EmptyState icon={AlertTriangle} title="Could not load threats" desc={error} />
        ) : !data || data.recent_attacks.length === 0 ? (
          <EmptyState icon={ShieldAlert} title="No threats in this window" desc="Blocked requests matching your filters will appear here." />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th><th>Severity</th><th>Attack Type</th><th>Source</th><th>URI</th><th>Score</th><th>Rules</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_attacks.map(a => {
                const meta = severityMeta(a.severity)
                return (
                  <tr key={a.id} onClick={() => setSelected(a)} style={{ cursor: 'pointer' }}>
                    <td className="text-cat-sub font-mono text-xs">{new Date(a.timestamp).toLocaleString()}</td>
                    <td><span className="badge" style={{ background: `${meta.color}22`, color: meta.color }}>{meta.label}</span></td>
                    <td className="text-xs text-cat-text">{a.attack_type || '—'}</td>
                    <td className="font-mono text-xs text-cat-text">{a.client_ip || '—'}{a.country_code ? ` (${a.country_code})` : ''}</td>
                    <td className="font-mono text-xs text-cat-sub max-w-[220px] truncate">{a.uri}</td>
                    <td className="font-mono text-xs text-cat-text">{a.anomaly_score ?? '—'}</td>
                    <td className="text-xs text-cat-sub">{Array.isArray(a.rule_ids) ? a.rule_ids.length : 0}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {selected && (
        <>
          <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 998 }} onClick={() => setSelected(null)} />
          <div style={{
            position: 'fixed', top: 0, right: 0, bottom: 0, width: 'min(420px, 92vw)', zIndex: 999,
            background: 'var(--cat-card-final, var(--cat-card))', borderLeft: '1px solid var(--cat-border)',
            boxShadow: '-16px 0 40px rgba(0,0,0,0.4)', overflowY: 'auto', padding: 20,
          }} className="animate-slide-in">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--cat-text)' }}>Event Detail</div>
              <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', color: 'var(--cat-sub)', cursor: 'pointer' }} aria-label="Close">
                <X size={16} />
              </button>
            </div>
            <div className="space-y-3">
              {[
                ['Timestamp', new Date(selected.timestamp).toLocaleString()],
                ['Severity', severityMeta(selected.severity).label],
                ['Attack Type', selected.attack_type || '—'],
                ['Source IP', selected.client_ip || '—'],
                ['Location', selected.city ? `${selected.city}, ${selected.country_code}` : (selected.country_code || '—')],
                ['Method', selected.method || '—'],
                ['URI', selected.uri || '—'],
                ['Status', selected.status ?? '—'],
                ['Anomaly Score', selected.anomaly_score ?? '—'],
                ['Rule IDs', Array.isArray(selected.rule_ids) ? selected.rule_ids.join(', ') || '—' : '—'],
              ].map(([k, v]) => (
                <div key={k}>
                  <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--cat-sub)' }}>{k}</div>
                  <div style={{ fontSize: 12.5, color: 'var(--cat-text)', marginTop: 2, wordBreak: 'break-all' }}>{v}</div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
