import { useEffect, useState, useCallback } from 'react'
import { FileText, Search, AlertTriangle, ChevronLeft, ChevronRight } from 'lucide-react'
import { api } from '../utils/api.js'
import { EmptyState, Skeleton } from '../components/ui.jsx'

const WINDOW_OPTIONS = [
  { id: '1h', label: '1h' }, { id: '24h', label: '24h' }, { id: '7d', label: '7d' }, { id: '30d', label: '30d' },
]
const PAGE_SIZE = 50

export default function LogsPage() {
  const [windowSpec, setWindowSpec] = useState('24h')
  const [action, setAction] = useState('')
  const [query, setQuery] = useState('')
  const [debouncedQuery, setDebouncedQuery] = useState('')
  const [page, setPage] = useState(0)
  const [logs, setLogs] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQuery(query), 300)
    return () => clearTimeout(t)
  }, [query])

  useEffect(() => { setPage(0) }, [windowSpec, action, debouncedQuery])

  const load = useCallback(() => {
    setLoading(true)
    const params = new URLSearchParams({ last: windowSpec, limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE) })
    if (action) params.set('action', action)
    if (debouncedQuery) params.set('q', debouncedQuery)
    api.get(`/logs?${params.toString()}`)
      .then(d => { setLogs(d.logs); setError(null) })
      .catch(e => setError(e.message || 'Failed to load logs'))
      .finally(() => setLoading(false))
  }, [windowSpec, action, debouncedQuery, page])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    if (!logs) return
    const iv = setInterval(load, 20000)
    return () => clearInterval(iv)
  }, [logs, load])

  return (
    <div className="p-6 space-y-4 page-enter">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--cat-text)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <FileText size={18} style={{ opacity: 0.8 }} /> Logs
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {WINDOW_OPTIONS.map(w => (
            <button key={w.id} className={`btn btn-sm ${windowSpec === w.id ? 'btn-primary' : 'btn-ghost'}`} onClick={() => setWindowSpec(w.id)}>{w.label}</button>
          ))}
        </div>
      </div>

      <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', padding: 12 }}>
        <div style={{ position: 'relative', flex: 1, minWidth: 220 }}>
          <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--cat-sub)' }} />
          <input className="input" style={{ paddingLeft: 30 }} placeholder="Search by IP, URI, or country…" value={query} onChange={e => setQuery(e.target.value)} />
        </div>
        <select className="input select" style={{ width: 'auto' }} value={action} onChange={e => setAction(e.target.value)}>
          <option value="">All actions</option>
          <option value="block">Blocked only</option>
          <option value="pass">Passed only</option>
        </select>
      </div>

      <div className="card">
        {loading && !logs ? (
          <Skeleton h="h-64" className="w-full" />
        ) : error ? (
          <EmptyState icon={AlertTriangle} title="Could not load logs" desc={error} />
        ) : !logs || logs.length === 0 ? (
          <EmptyState icon={FileText} title="No requests match" desc="Try a different time window, filter, or search term." />
        ) : (
          <>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th><th>IP</th><th>Method</th><th>URI</th><th>Status</th><th>Score</th><th>Action</th><th>Attack</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(l => (
                  <tr key={l.id}>
                    <td className="text-cat-sub font-mono text-xs">{new Date(l.timestamp).toLocaleString()}</td>
                    <td className="font-mono text-xs text-cat-text">{l.ip}{l.country_code ? ` (${l.country_code})` : ''}</td>
                    <td><span className="badge-blue text-[10px]">{l.method}</span></td>
                    <td className="font-mono text-xs text-cat-sub max-w-[220px] truncate">{l.uri}</td>
                    <td className="text-xs text-cat-sub">{l.status ?? '—'}</td>
                    <td className="mono text-cat-text">{l.anomaly_score ?? '—'}</td>
                    <td><span className={`badge ${l.action === 'block' ? 'badge-red' : 'badge-green'}`}>{l.action}</span></td>
                    <td className="text-xs text-cat-sub">{l.attack_type || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 12, marginTop: 4, borderTop: '1px solid var(--cat-border)' }}>
              <span style={{ fontSize: 11, color: 'var(--cat-sub)' }}>Page {page + 1}</span>
              <div style={{ display: 'flex', gap: 6 }}>
                <button className="btn btn-sm btn-ghost" disabled={page === 0} onClick={() => setPage(p => Math.max(0, p - 1))}>
                  <ChevronLeft size={13} /> Prev
                </button>
                <button className="btn btn-sm btn-ghost" disabled={logs.length < PAGE_SIZE} onClick={() => setPage(p => p + 1)}>
                  Next <ChevronRight size={13} />
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
