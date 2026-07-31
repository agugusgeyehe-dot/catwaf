import React, { useEffect, useState } from 'react'
import { AlertCircle, Globe, Check, Trash2, Plus } from 'lucide-react'
import { XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts'
import { Toggle, SectionTitle, ActionBar, Input, Toast, EmptyState } from '../components/ui.jsx'
import { api } from '../utils/api.js'

export function EnginePage() {
  const [mode, setMode] = useState('On')
  const [toast, setToast] = useState(null)

  useEffect(() => { api.get('/waf/engine').then(d => setMode(d.mode)).catch(() => {}) }, [])

  const save = async (m) => {
    try {
      await api.post('/waf/engine', { mode: m })
      setMode(m)
      setToast({ message: `Engine set to ${m}`, type: 'success' })
    } catch (e) { setToast({ message: e.message, type: 'error' }) }
  }

  const modes = [
    { id: 'On', label: 'Blocking', sub: 'Actively blocks requests that exceed the anomaly threshold.', color: 'cat-green', badge: 'badge-green' },
    { id: 'DetectionOnly', label: 'Detection Only', sub: 'Evaluates rules and logs matches but never blocks. Safe for initial deployment.', color: 'cat-orange', badge: 'badge-orange' },
    { id: 'Off', label: 'Disabled', sub: 'WAF engine completely off. No inspection or logging. Use only for debugging.', color: 'cat-red', badge: 'badge-red' },
  ]

  return (
    <div className="p-6 space-y-5 page-enter">
      {toast && <Toast {...toast} onClose={() => setToast(null)} />}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {modes.map(m => (
          <button
            key={m.id}
            onClick={() => save(m.id)}
            className={`card text-left hover:border-cat-accent/40 transition-all duration-200 ${mode === m.id ? 'border-cat-accent/60' : ''}`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className={m.badge}>{m.label}</span>
              {mode === m.id && <Check size={14} className="text-cat-accent" />}
            </div>
            <div className="text-sm text-cat-sub leading-relaxed">{m.sub}</div>
          </button>
        ))}
      </div>
      <div className="card bg-cat-red/5 border-cat-red/20 animate-fade-in">
        <div className="flex gap-3 text-xs text-cat-sub leading-relaxed">
          <AlertCircle size={14} className="text-cat-orange mt-0.5 shrink-0" />
          <span><strong className="text-cat-text">Production tip:</strong> Always start in <em>Detection Only</em> mode. Review logs for false positives, add exclusions, then switch to <em>Blocking</em>. Never go directly to Blocking on a PHP app without reviewing traffic first.</span>
        </div>
      </div>
    </div>
  )
}

export function IPListPage({ listType }) {
  const [ips, setIps] = useState([])
  const [ip, setIp] = useState('')
  const [note, setNote] = useState('')
  const [toast, setToast] = useState(null)

  const load = () => api.get(`/ip/${listType}`).then(setIps).catch(() => {})
  useEffect(() => { load() }, [listType])

  const add = async () => {
    if (!ip) return
    try {
      await api.post('/ip/add', { ip, note, list: listType })
      setIp(''); setNote('')
      load()
      setToast({ message: `${ip} added to ${listType}`, type: 'success' })
    } catch (e) { setToast({ message: e.message, type: 'error' }) }
  }

  const del = async (ipAddr) => {
    try {
      await api.delete(`/ip/${listType}/${ipAddr}`)
      load()
      setToast({ message: `${ipAddr} removed`, type: 'success' })
    } catch (e) { setToast({ message: e.message, type: 'error' }) }
  }

  const color = listType === 'whitelist' ? 'green' : 'red'

  return (
    <div className="p-6 space-y-4 page-enter">
      {toast && <Toast {...toast} onClose={() => setToast(null)} />}
      <div className="card animate-slide-up">
        <SectionTitle>Add IP / CIDR to {listType}</SectionTitle>
        <div className="grid grid-cols-2 gap-3">
          <Input label="IP Address or CIDR" placeholder="e.g. 192.168.1.1 or 10.0.0.0/8" value={ip} onChange={e => setIp(e.target.value)} />
          <Input label="Note (optional)" placeholder="Reason or identifier" value={note} onChange={e => setNote(e.target.value)} />
        </div>
        <ActionBar>
          <button className={`btn-${color} btn btn-sm`} onClick={add}>
            <Plus size={13} /> Add to {listType}
          </button>
        </ActionBar>
      </div>

      <div className="card animate-slide-up">
        <SectionTitle>{listType} — {ips.length} entries</SectionTitle>
        {ips.length === 0 ? (
          <EmptyState icon={Globe} title={`${listType} is empty`} desc="Add IPs or CIDR ranges above." />
        ) : (
          <table className="data-table">
            <thead><tr><th>IP / CIDR</th><th>Note</th><th>Added</th><th></th></tr></thead>
            <tbody>
              {ips.map((e, i) => (
                <tr key={i}>
                  <td className="font-mono text-sm text-cat-text">{e.ip}</td>
                  <td className="text-xs text-cat-sub">{e.note || '—'}</td>
                  <td className="text-xs text-cat-sub">{new Date(e.added_at).toLocaleDateString()}</td>
                  <td><button onClick={() => del(e.ip)} className="btn-danger btn btn-sm"><Trash2 size={11} /></button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

export function GeoPage() {
  const [blocked, setBlocked] = useState([])
  const [toast, setToast] = useState(null)

  const load = () => api.get('/geo').then(d => setBlocked(d.blocked_countries)).catch(() => {})
  useEffect(() => { load() }, [])

  const toggle = async (cc) => {
    try {
      const r = await api.post(`/geo/${cc}`)
      setBlocked(r.blocked_countries)
      setToast({ message: r.message, type: 'success' })
    } catch (e) { setToast({ message: e.message, type: 'error' }) }
  }

  const countries = [
    { code: 'CN', name: 'China' }, { code: 'RU', name: 'Russia' },
    { code: 'KP', name: 'North Korea' }, { code: 'IR', name: 'Iran' },
    { code: 'UA', name: 'Ukraine' }, { code: 'BR', name: 'Brazil' },
    { code: 'IN', name: 'India' }, { code: 'NG', name: 'Nigeria' },
    { code: 'RO', name: 'Romania' }, { code: 'VN', name: 'Vietnam' },
    { code: 'PK', name: 'Pakistan' }, { code: 'BD', name: 'Bangladesh' },
  ]

  return (
    <div className="p-6 space-y-4 page-enter">
      {toast && <Toast {...toast} onClose={() => setToast(null)} />}
      <div className="card bg-cat-orange/5 border-cat-orange/20 text-xs text-cat-sub animate-fade-in">
        <AlertCircle size={13} className="text-cat-orange inline mr-2" />
        Geo-blocking uses GeoIP. It is approximate and can affect legitimate users. Use as a supplementary control, not primary defence.
      </div>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
        {countries.map(c => {
          const isBlocked = blocked.includes(c.code)
          return (
            <div
              key={c.code}
              role="button"
              tabIndex={0}
              aria-pressed={isBlocked}
              onClick={() => toggle(c.code)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(c.code) } }}
              className={`card flex items-center justify-between transition-all duration-200 cursor-pointer ${isBlocked ? 'border-cat-red/40 bg-cat-red/5' : 'hover:border-cat-border'}`}
            >
              <div>
                <div className="text-sm font-medium text-cat-text">{c.name}</div>
                <div className="font-mono text-xs text-cat-sub">{c.code}</div>
              </div>
              <Toggle on={isBlocked} onChange={() => toggle(c.code)} />
            </div>
          )
        })}
      </div>
    </div>
  )
}

const ANALYTICS_WINDOWS = [
  { id: '1h', label: '1h' }, { id: '24h', label: '24h' }, { id: '7d', label: '7d' }, { id: '30d', label: '30d' },
]

export function AnalyticsPage() {
  const [chart, setChart] = useState([])
  const [attacks, setAttacks] = useState([])
  const [summary, setSummary] = useState(null)
  const [windowSpec, setWindowSpec] = useState('24h')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/traffic/chart').then(setChart).catch(() => {})
    api.get('/traffic/attacks').then(setAttacks).catch(() => {})
  }, [])

  useEffect(() => {
    setLoading(true)
    api.get(`/audit/summary?last=${windowSpec}`)
      .then(setSummary)
      .catch(() => setSummary(null))
      .finally(() => setLoading(false))
  }, [windowSpec])

  return (
    <div className="p-6 space-y-5 page-enter">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        <SectionTitle>Analytics</SectionTitle>
        <div style={{ display: 'flex', gap: 6 }}>
          {ANALYTICS_WINDOWS.map(w => (
            <button key={w.id} className={`btn btn-sm ${windowSpec === w.id ? 'btn-primary' : 'btn-ghost'}`} onClick={() => setWindowSpec(w.id)}>{w.label}</button>
          ))}
        </div>
      </div>

      {summary && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            ['Total Requests', summary.total_requests.toLocaleString()],
            ['Blocked', summary.blocked_requests.toLocaleString()],
            ['Block Rate', `${(summary.block_rate * 100).toFixed(1)}%`],
            ['Avg Anomaly Score', summary.anomaly_score.average ?? '—'],
          ].map(([label, value]) => (
            <div key={label} className="card">
              <div style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--cat-sub)' }}>{label}</div>
              <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--cat-text)', marginTop: 4 }}>{value}</div>
            </div>
          ))}
        </div>
      )}

      <div className="card animate-slide-up">
        <SectionTitle>Traffic Volume — 24h</SectionTitle>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={chart} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
            <XAxis dataKey="hour" tick={{ fontSize: 10 }} interval={3} />
            <YAxis tick={{ fontSize: 10 }} />
            <Tooltip />
            <Bar dataKey="passed" stackId="a" fill="#4f8ef730" name="Passed" />
            <Bar dataKey="blocked" stackId="a" fill="#f25c5c80" name="Blocked" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="card animate-slide-up">
          <SectionTitle>Attack Distribution (24h)</SectionTitle>
          {attacks.every(a => a.count === 0) ? (
            <EmptyState icon={AlertCircle} title="No attacks detected" desc="Blocked attack categories will appear here." />
          ) : (
            <div className="space-y-3">
              {attacks.map(a => {
                const max = Math.max(...attacks.map(x => x.count), 1)
                return (
                  <div key={a.type} className="flex items-center gap-3">
                    <div className="w-24 text-xs text-cat-sub shrink-0">{a.type}</div>
                    <div className="flex-1 bg-cat-muted rounded-full h-1.5 overflow-hidden">
                      <div className="score-bar h-full" style={{ width: `${(a.count / max) * 100}%`, background: a.color }} />
                    </div>
                    <div className="w-12 text-right font-mono text-xs text-cat-text">{a.count}</div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        <div className="card animate-slide-up">
          <SectionTitle>Top Rules Triggered ({windowSpec})</SectionTitle>
          {!summary || summary.top_rules.length === 0 ? (
            <EmptyState icon={AlertCircle} title="No rule matches" desc="Triggered CRS rule IDs will appear here." />
          ) : (
            <div className="space-y-2">
              {summary.top_rules.slice(0, 8).map(r => (
                <div key={r.rule_id} className="flex items-center justify-between text-xs">
                  <span className="font-mono text-cat-text">Rule {r.rule_id}</span>
                  <span className="text-cat-sub font-mono">{r.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export function AboutPage() {
  const [info, setInfo] = useState(null)
  useEffect(() => { api.get('/diagnostics').then(setInfo).catch(() => setInfo(null)) }, [])

  const rows = [
    ['WAF Engine', 'Coraza'],
    ['Rule Set', 'OWASP CRS'],
    ['Backend', 'Node.js + Express'],
    ['Frontend', 'React + Vite'],
    ['Runtime', info?.node_version || '—'],
    ['Edition', info?.edition ? info.edition[0].toUpperCase() + info.edition.slice(1) : '—'],
  ]

  return (
    <div className="p-6 space-y-4 page-enter">
      <div className="card animate-slide-up text-center py-10">
        <img src="/catwaf-icon-256.png" alt="CatWAF" className="mb-4 mx-auto" style={{ width: 48, height: 48, objectFit: 'contain' }} />
        <div className="text-xl font-bold text-cat-text mb-1">CatWAF</div>
        <div className="text-xs text-cat-sub mb-6">Control Panel {info?.catwaf_version ? `v${info.catwaf_version}` : ''}</div>
        <div className="grid grid-cols-2 gap-3 max-w-xs mx-auto text-left">
          {rows.map(([k, v]) => (
            <div key={k} className="bg-cat-bg rounded-lg p-3">
              <div className="text-[10px] text-cat-sub">{k}</div>
              <div className="text-sm font-mono text-cat-text mt-0.5">{v}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
