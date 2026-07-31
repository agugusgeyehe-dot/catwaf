import React, { useEffect, useState, useCallback } from 'react'
import { Wrench, Search, AlertTriangle, Check, X, Ban } from 'lucide-react'
import { api } from '../utils/api.js'
import { EmptyState, Skeleton, SectionTitle } from '../components/ui.jsx'
import { severityMeta } from '../utils/severity.js'

export default function RulesPage() {
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState('')
  const [enabledFilter, setEnabledFilter] = useState('')
  const [rules, setRules] = useState(null)
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [pendingConfirm, setPendingConfirm] = useState(null)
  const [busyId, setBusyId] = useState(null)

  const load = useCallback(() => {
    setLoading(true)
    const req = query.trim()
      ? api.get(`/rules/search?q=${encodeURIComponent(query.trim())}`)
      : api.get(`/rules?${new URLSearchParams({
          ...(category ? { category } : {}),
          ...(enabledFilter ? { enabled: enabledFilter } : {}),
          limit: '200',
        }).toString()}`)
    req.then(d => { setRules(d.rules); setTotal(d.total); setError(null) })
      .catch(e => setError(e.message || 'Failed to load rules'))
      .finally(() => setLoading(false))
  }, [query, category, enabledFilter])

  useEffect(() => { load() }, [load])

  async function toggle(rule) {
    const action = rule.enabled ? 'disable' : 'enable'
    setBusyId(rule.id)
    try {
      await api.post(`/rules/${rule.id}/${action}`)
      setRules(rs => rs.map(r => r.id === rule.id ? { ...r, enabled: !rule.enabled, disabled_by: rule.enabled ? 'rule' : null } : r))
    } catch (e) {
      setError(e.message || 'Failed to update rule')
    } finally {
      setBusyId(null)
      setPendingConfirm(null)
    }
  }

  return (
    <div className="p-6 space-y-4 page-enter">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--cat-text)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Wrench size={18} style={{ opacity: 0.8 }} /> Rules
          </div>
          <div style={{ fontSize: 12, color: 'var(--cat-sub)', marginTop: 2 }}>
            {total ? `${total.toLocaleString()} OWASP CRS rule${total === 1 ? '' : 's'}` : 'CRS rule catalog'}
          </div>
        </div>
      </div>

      <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', padding: 12 }}>
        <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
          <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--cat-sub)' }} />
          <input className="input" style={{ paddingLeft: 30 }} placeholder="Search by rule ID, message, category, or tag…"
            value={query} onChange={e => setQuery(e.target.value)} />
        </div>
        <select className="input select" style={{ width: 'auto' }} value={enabledFilter} onChange={e => setEnabledFilter(e.target.value)}>
          <option value="">All rules</option>
          <option value="true">Enabled only</option>
          <option value="false">Disabled only</option>
        </select>
        <input className="input" style={{ width: 160 }} placeholder="Category filter…" value={category} onChange={e => setCategory(e.target.value)} />
      </div>

      <div className="card">
        {loading && !rules ? (
          <Skeleton h="h-64" className="w-full" />
        ) : error ? (
          <EmptyState icon={AlertTriangle} title="Could not load rules" desc={error} />
        ) : !rules || rules.length === 0 ? (
          <EmptyState icon={Wrench} title="No rules found" desc="Try adjusting your search or filters." />
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th><th>Description</th><th>Category</th><th>Severity</th><th>PL</th><th>Status</th><th></th>
              </tr>
            </thead>
            <tbody>
              {rules.map(r => {
                const meta = r.severity ? severityMeta(r.severity) : null
                return (
                  <tr key={r.id}>
                    <td className="font-mono text-xs text-cat-text">{r.id}</td>
                    <td className="text-xs text-cat-text" style={{ maxWidth: 320 }}>{r.description || <span className="text-cat-sub">Unknown rule (not in loaded metadata)</span>}</td>
                    <td className="text-xs text-cat-sub">{r.category || '—'}</td>
                    <td>{meta ? <span className="badge" style={{ background: `${meta.color}22`, color: meta.color }}>{meta.label}</span> : <span className="text-cat-sub text-xs">—</span>}</td>
                    <td className="text-xs text-cat-sub">{r.paranoia_level ?? '—'}</td>
                    <td>
                      <span className={`badge ${r.enabled ? 'badge-green' : 'badge-muted'}`}>{r.enabled ? 'Enabled' : `Disabled (${r.disabled_by || 'rule'})`}</span>
                    </td>
                    <td>
                      {pendingConfirm === r.id ? (
                        <div style={{ display: 'flex', gap: 4 }}>
                          <button className="btn btn-sm btn-danger" disabled={busyId === r.id} onClick={() => toggle(r)}>
                            <Check size={12} /> Confirm
                          </button>
                          <button className="btn btn-sm btn-ghost" onClick={() => setPendingConfirm(null)}>
                            <X size={12} />
                          </button>
                        </div>
                      ) : (
                        <button
                          className={`btn btn-sm ${r.enabled ? 'btn-ghost' : 'btn-green'}`}
                          disabled={busyId === r.id}
                          onClick={() => r.enabled ? setPendingConfirm(r.id) : toggle(r)}
                        >
                          {r.enabled ? <><Ban size={12} /> Disable</> : <><Check size={12} /> Enable</>}
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
