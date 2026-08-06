import { useState, useEffect } from 'react'
import { SectionTitle } from '../components/ui.jsx'
import { ShieldAlert, Search, Ban, Eye, RefreshCw, FolderOpen, File, Lock, CheckCircle, Shield, ShieldCheck, ShieldX, CircleSlash } from 'lucide-react'
import { api } from '../utils/api.js'

const SFL_META = [
  { level: 1, name: 'Basic',    color: '#22d3a0', icon: Shield,      desc: 'Blocks obviously dangerous exposed files — config files, secrets, version control.' },
  { level: 2, name: 'Elevated', color: '#4f8ef7', icon: ShieldCheck, desc: 'Adds upload endpoints, shell files, and common exploit entry points.' },
  { level: 3, name: 'Strict',   color: '#f59e0b', icon: ShieldAlert, desc: 'Blocks admin panels, database managers, and framework-specific sensitive paths.' },
  { level: 4, name: 'Maximum',  color: '#f25c5c', icon: ShieldX,     desc: 'Catches paths at ANY depth via regex — /en/upload.php, /v2/admin/shell.php all blocked.' },
]

const FILE_CATS = [
  { key: 'php',    label: 'PHP Files',    color: '#a78bfa' },
  { key: 'config', label: 'Config Files', color: '#f25c5c' },
  { key: 'backup', label: 'Backups',      color: '#f59e0b' },
  { key: 'html',   label: 'HTML Files',   color: '#4f8ef7' },
]

const RISK_BADGE = {
  critical: { label: 'Critical', color: '#f25c5c', bg: 'rgba(242,92,92,0.1)' },
  high:     { label: 'High',     color: '#f59e0b', bg: 'rgba(245,158,11,0.1)' },
  medium:   { label: 'Medium',   color: '#4f8ef7', bg: 'rgba(79,142,247,0.1)' },
  low:      { label: 'Low',      color: '#22d3a0', bg: 'rgba(34,211,160,0.1)' },
}

export default function SensitiveFiles() {
  const [activeTab, setActiveTab]   = useState('paranoia')
  const [sflLevel, setSflLevel]     = useState(0)
  const [patterns, setPatterns]     = useState([])
  const [loadingPL, setLoadingPL]   = useState(false)
  const [blocked, setBlocked]       = useState(new Set())
  const [files, setFiles]           = useState([])
  const [scanning, setScanning]     = useState(false)
  const [scanned, setScanned]       = useState(false)
  const [search, setSearch]         = useState('')
  const [filterCat, setFilterCat]   = useState('all')
  const [saving, setSaving]         = useState(false)
  const [saved, setSaved]           = useState(false)
  const [scanNotice, setScanNotice] = useState(null)
  const [scanError, setScanError]   = useState(null)

  useEffect(() => {
    api.get('/sensitive/state').then(s => {
      setSflLevel(s.sfl_level)
      if (s.sfl_level > 0) fetchPatterns(s.sfl_level)
    }).catch(() => {})
    api.get('/sensitive/blocked').then(s => {
      setBlocked(new Set(s.blocked))
    }).catch(() => {})
  }, [])

  const fetchPatterns = async (level) => {
    setLoadingPL(true)
    try {
      const res = await fetch(`/wordlists/sfl${level}.txt`)
      const text = await res.text()
      const lines = text.split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'))
      setPatterns(lines)
    } catch {}
    setLoadingPL(false)
  }

  const selectLevel = async (level) => {
    setSflLevel(level)
    if (level > 0) fetchPatterns(level)
    else setPatterns([])
  }

  const applyLevel = async () => {
    setSaving(true)
    try {
      await api.post('/sensitive/level', { level: sflLevel })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch {}
    setSaving(false)
  }

  const scan = async () => {
    setScanning(true)
    setScanned(false)
    setScanNotice(null)
    setScanError(null)
    try {
      const res = await api.get('/sensitive/scan')
      setFiles(res.files || [])
      if (res.configured === false) setScanNotice(res.detail || 'The webroot is not configured yet.')
      setScanned(true)
    } catch (e) {
      setScanError(e.message || 'Scan failed.')
    }
    setScanning(false)
  }

  const toggleBlock = async (path) => {
    const isBlocked = blocked.has(path)
    try {
      if (isBlocked) {
        await api.delete(`/sensitive/block/${encodeURIComponent(path)}`)
      } else {
        await api.post('/sensitive/block', { path })
      }
      setBlocked(prev => {
        const next = new Set(prev)
        isBlocked ? next.delete(path) : next.add(path)
        return next
      })
    } catch {}
  }

  const cur = SFL_META.find(s => s.level === sflLevel)
  const filtered = files.filter(f => {
    const matchSearch = f.path.toLowerCase().includes(search.toLowerCase())
    const matchCat = filterCat === 'all' || f.cat === filterCat
    return matchSearch && matchCat
  })

  return (
    <div className="p-6 space-y-5 page-enter">
      <div className="flex items-center justify-between">
        <div>
          <h1 style={{ fontSize: 18, fontWeight: 700, color: 'var(--cat-text)' }}>Sensitive Files Protection</h1>
          <p style={{ fontSize: 12, color: 'var(--cat-sub)', marginTop: 3 }}>
            Block access to sensitive paths and scan your public webroot for exposed files.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {['paranoia', 'scanner'].map(t => (
            <button key={t} onClick={() => setActiveTab(t)} style={{
              padding: '7px 16px', borderRadius: 8, fontSize: 12, fontWeight: 500,
              cursor: 'pointer', border: 'none',
              background: activeTab === t ? 'var(--cat-accent)' : 'var(--cat-muted)',
              color: activeTab === t ? 'var(--cat-accent-ink)' : 'var(--cat-sub)',
              transition: 'all 0.15s ease',
            }}>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                {t === 'paranoia' ? <><Lock size={13} /> Sensitive File Levels</> : <><Search size={13} /> Public File Scanner</>}
              </span>
            </button>
          ))}
        </div>
      </div>

      {activeTab === 'paranoia' && (
        <div className="space-y-4">
          <div className="card">
            <SectionTitle>Sensitive File Paranoia Level (SFL)</SectionTitle>
            <p style={{ fontSize: 12, color: 'var(--cat-sub)', marginBottom: 20 }}>
              Powered by SecLists — curated paths from <code style={{ color: 'var(--cat-accent)' }}>raft-large-files.txt</code> and <code style={{ color: 'var(--cat-accent)' }}>common.txt</code>.
              Higher levels catch paths at any depth — <code style={{ color: 'var(--cat-accent)' }}>/en/upload.php</code> blocked at SFL4.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10 }}>
              <div onClick={() => selectLevel(0)} style={{
                border: `2px solid ${sflLevel === 0 ? 'var(--cat-accent)' : 'var(--cat-border)'}`,
                borderRadius: 12, padding: '16px 12px', cursor: 'pointer', textAlign: 'center',
                background: sflLevel === 0 ? 'color-mix(in srgb, var(--cat-accent) 8%, transparent)' : 'transparent',
                transition: 'all 0.15s ease',
              }}>
                <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 6, color: 'var(--cat-sub)' }}><CircleSlash size={20} /></div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--cat-sub)' }}>Off</div>
                <div style={{ fontSize: 10, color: 'var(--cat-sub)', opacity: 0.5, marginTop: 4 }}>Disabled</div>
              </div>
              {SFL_META.map(s => (
                <div key={s.level} onClick={() => selectLevel(s.level)} style={{
                  border: `2px solid ${sflLevel === s.level ? s.color : 'var(--cat-border)'}`,
                  borderRadius: 12, padding: '16px 12px', cursor: 'pointer', textAlign: 'center',
                  background: sflLevel === s.level ? `color-mix(in srgb, ${s.color} 8%, transparent)` : 'transparent',
                  boxShadow: sflLevel === s.level ? `0 0 20px color-mix(in srgb, ${s.color} 20%, transparent)` : 'none',
                  transition: 'all 0.15s ease',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 6, color: s.color }}><s.icon size={20} /></div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: s.color }}>SFL{s.level}</div>
                  <div style={{ fontSize: 10, color: 'var(--cat-sub)', marginTop: 4 }}>{s.name}</div>
                </div>
              ))}
            </div>
          </div>

          {sflLevel > 0 && cur && (
            <div className="card animate-slide-up">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                <div style={{
                  width: 44, height: 44, borderRadius: 12, color: cur.color,
                  background: `color-mix(in srgb, ${cur.color} 12%, transparent)`,
                  border: `1px solid color-mix(in srgb, ${cur.color} 25%, transparent)`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  boxShadow: `0 0 20px color-mix(in srgb, ${cur.color} 20%, transparent)`,
                }}><cur.icon size={22} /></div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--cat-text)' }}>SFL{cur.level} — {cur.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--cat-sub)', marginTop: 2 }}>{cur.desc}</div>
                </div>
                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
                  {loadingPL ? (
                    <span style={{ fontSize: 11, color: 'var(--cat-sub)' }}>Loading...</span>
                  ) : (
                    <span style={{
                      background: `color-mix(in srgb, ${cur.color} 12%, transparent)`,
                      color: cur.color, borderRadius: 999, padding: '3px 10px', fontSize: 11, fontWeight: 600,
                    }}>{patterns.length} patterns</span>
                  )}
                </div>
              </div>

              {!loadingPL && patterns.length > 0 && (
                <div style={{
                  maxHeight: 180, overflowY: 'auto',
                  background: 'var(--cat-surface)', border: '1px solid var(--cat-border)',
                  borderRadius: 8, padding: '10px 12px', marginBottom: 16,
                  display: 'flex', flexWrap: 'wrap', gap: 5,
                }}>
                  {patterns.slice(0, 80).map((p, i) => (
                    <code key={i} style={{
                      background: 'var(--cat-muted)', borderRadius: 5,
                      padding: '2px 7px', fontSize: 10,
                      color: p.startsWith('REGEX:') ? cur.color : 'var(--cat-text)',
                      fontFamily: 'monospace',
                    }}>{p}</code>
                  ))}
                  {patterns.length > 80 && (
                    <span style={{ fontSize: 10, color: 'var(--cat-sub)', padding: '2px 7px' }}>
                      +{patterns.length - 80} more...
                    </span>
                  )}
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button onClick={applyLevel} disabled={saving} style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '9px 20px', borderRadius: 9, fontSize: 12, fontWeight: 600,
                  background: saved ? '#22d3a0' : cur.color, border: 'none',
                  color: '#fff', cursor: 'pointer', opacity: saving ? 0.6 : 1,
                  boxShadow: `0 4px 16px color-mix(in srgb, ${cur.color} 30%, transparent)`,
                  transition: 'background 0.2s ease',
                }}>
                  {saved ? <><CheckCircle size={13} /> Applied!</> : saving ? 'Applying...' : `Apply SFL${cur.level}`}
                </button>
              </div>
            </div>
          )}

          <div className="card">
            <SectionTitle>All Levels Overview</SectionTitle>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              {SFL_META.map(s => (
                <div key={s.level} onClick={() => selectLevel(s.level)} style={{
                  border: `1px solid ${sflLevel === s.level ? s.color : 'var(--cat-border)'}`,
                  borderRadius: 10, padding: '14px 16px', cursor: 'pointer',
                  background: sflLevel === s.level ? `color-mix(in srgb, ${s.color} 5%, transparent)` : 'transparent',
                  transition: 'all 0.15s ease',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <span style={{ color: s.color, fontWeight: 700, fontSize: 13 }}>SFL{s.level}</span>
                    <span style={{ color: 'var(--cat-sub)', fontSize: 12 }}>{s.name}</span>
                  </div>
                  <p style={{ fontSize: 11, color: 'var(--cat-sub)', lineHeight: 1.5 }}>{s.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'scanner' && (
        <div className="space-y-4">
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <div>
                <SectionTitle>Public Webroot Scanner</SectionTitle>
                <p style={{ fontSize: 12, color: 'var(--cat-sub)' }}>
                  Scans your public webroot and lists all accessible files. Click any file to instantly block it.
                </p>
              </div>
              <button onClick={scan} disabled={scanning} style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '8px 16px', borderRadius: 8, fontSize: 12, fontWeight: 600,
                background: 'var(--cat-accent)', border: 'none', color: 'var(--cat-accent-ink)', cursor: 'pointer',
                opacity: scanning ? 0.6 : 1,
              }}>
                <RefreshCw size={13} style={{ animation: scanning ? 'spin 1s linear infinite' : 'none' }} />
                {scanning ? 'Scanning...' : 'Scan Webroot'}
              </button>
            </div>

            {scanError && (
              <div style={{ padding: '14px 16px', borderRadius: 8, marginBottom: 16, background: 'rgba(242,92,92,0.08)', border: '1px solid rgba(242,92,92,0.25)', fontSize: 12, color: '#f25c5c' }}>
                <strong>Scan failed.</strong> {scanError}
              </div>
            )}

            {scanNotice && (
              <div style={{ padding: '16px 18px', borderRadius: 8, marginBottom: 16, background: 'rgba(245,158,11,0.07)', border: '1px solid rgba(245,158,11,0.25)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 13, fontWeight: 600, color: '#f59e0b', marginBottom: 6 }}>
                  <FolderOpen size={14} /> Webroot not configured
                </div>
                <p style={{ fontSize: 12, color: 'var(--cat-sub)', lineHeight: 1.6, margin: 0 }}>{scanNotice}</p>
                <p style={{ fontSize: 12, color: 'var(--cat-sub)', lineHeight: 1.6, margin: '10px 0 0' }}>
                  Add this to your <code>.env</code> file, then restart CatWAF:
                </p>
                <pre style={{ margin: '8px 0 0', padding: '9px 12px', borderRadius: 6, background: 'var(--cat-bg)', border: '1px solid var(--cat-border)', fontSize: 11.5, color: 'var(--cat-text)', overflowX: 'auto' }}>WEBROOT_PATH=/var/www/html</pre>
              </div>
            )}

            {scanned && !scanNotice && files.length === 0 && (
              <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--cat-sub)' }}>
                <CheckCircle size={30} style={{ margin: '0 auto 12px', opacity: 0.4, display: 'block', color: '#22d3a0' }} />
                <div style={{ fontSize: 13 }}>Scan complete — no files found in your webroot.</div>
                <div style={{ fontSize: 11, marginTop: 6, opacity: 0.7 }}>This is a real result from the configured directory, not a placeholder.</div>
              </div>
            )}

            {scanned && files.length > 0 && (
              <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
                <div style={{ position: 'relative', flex: 1, minWidth: 160 }}>
                  <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--cat-sub)' }} />
                  <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter paths..." className="input" style={{ paddingLeft: 30, fontSize: 12 }} />
                </div>
                {['all', ...FILE_CATS.map(c => c.key)].map(cat => (
                  <button key={cat} onClick={() => setFilterCat(cat)} style={{
                    padding: '6px 12px', borderRadius: 7, fontSize: 11, fontWeight: 500,
                    border: '1px solid var(--cat-border)', cursor: 'pointer',
                    background: filterCat === cat ? 'var(--cat-accent)' : 'transparent',
                    color: filterCat === cat ? 'var(--cat-accent-ink)' : 'var(--cat-sub)',
                  }}>
                    {cat === 'all' ? 'All' : FILE_CATS.find(c => c.key === cat)?.label}
                  </button>
                ))}
              </div>
            )}

            {!scanned && !scanning && !scanError && (
              <div style={{ textAlign: 'center', padding: '48px 0', color: 'var(--cat-sub)' }}>
                <FolderOpen size={32} style={{ margin: '0 auto 12px', opacity: 0.3, display: 'block' }} />
                <div style={{ fontSize: 13 }}>Click "Scan Webroot" to discover public files</div>
                <div style={{ fontSize: 11, marginTop: 6, opacity: 0.6 }}>CatWAF will enumerate all publicly accessible files and flag risky ones</div>
              </div>
            )}

            {scanning && (
              <div style={{ textAlign: 'center', padding: '48px 0', color: 'var(--cat-sub)' }}>
                <div style={{ fontSize: 13, marginBottom: 12 }}>Scanning webroot...</div>
                <div style={{ width: 200, height: 3, background: 'var(--cat-muted)', borderRadius: 999, margin: '0 auto', overflow: 'hidden' }}>
                  <div style={{ height: '100%', borderRadius: 999, background: 'var(--cat-accent)', animation: 'scanBar 1.5s ease-in-out forwards' }} />
                </div>
              </div>
            )}

            {scanned && files.length > 0 && (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 16 }}>
                  {[
                    { label: 'Total Files', value: filtered.length, color: 'var(--cat-accent)' },
                    { label: 'Critical',    value: filtered.filter(f => f.risk === 'critical').length, color: '#f25c5c' },
                    { label: 'Blocked',     value: [...blocked].filter(b => filtered.find(f => f.path === b)).length, color: '#22d3a0' },
                    { label: 'At Risk',     value: filtered.filter(f => f.risk !== 'low' && !blocked.has(f.path)).length, color: '#f59e0b' },
                  ].map(s => (
                    <div key={s.label} style={{ background: 'var(--cat-surface)', border: '1px solid var(--cat-border)', borderRadius: 8, padding: '10px 14px', textAlign: 'center' }}>
                      <div style={{ fontSize: 20, fontWeight: 700, color: s.color }}>{s.value}</div>
                      <div style={{ fontSize: 10, color: 'var(--cat-sub)', marginTop: 2 }}>{s.label}</div>
                    </div>
                  ))}
                </div>

                <table className="data-table">
                  <thead>
                    <tr><th>Path</th><th>Type</th><th>Size</th><th>Risk</th><th>Action</th></tr>
                  </thead>
                  <tbody>
                    {filtered.map((f, i) => {
                      const risk = RISK_BADGE[f.risk]
                      const isBlocked = blocked.has(f.path)
                      return (
                        <tr key={i} style={{ opacity: isBlocked ? 0.5 : 1 }}>
                          <td>
                            <code style={{ fontSize: 11, color: isBlocked ? 'var(--cat-sub)' : 'var(--cat-text)', fontFamily: 'monospace' }}>{f.path}</code>
                            {isBlocked && <span style={{ marginLeft: 8, fontSize: 10, color: '#f25c5c', background: 'rgba(242,92,92,0.1)', borderRadius: 4, padding: '1px 6px' }}>blocked</span>}
                          </td>
                          <td><span style={{ fontSize: 11, color: 'var(--cat-sub)' }}>{FILE_CATS.find(c => c.key === f.cat)?.label || f.cat}</span></td>
                          <td style={{ fontSize: 11, color: 'var(--cat-sub)', fontFamily: 'monospace' }}>{f.size}</td>
                          <td><span style={{ background: risk.bg, color: risk.color, borderRadius: 999, padding: '2px 8px', fontSize: 10, fontWeight: 600 }}>{risk.label}</span></td>
                          <td>
                            <button onClick={() => toggleBlock(f.path)} style={{
                              display: 'flex', alignItems: 'center', gap: 4,
                              padding: '4px 10px', borderRadius: 6, fontSize: 11, fontWeight: 500,
                              border: '1px solid', cursor: 'pointer',
                              borderColor: isBlocked ? 'rgba(34,211,160,0.2)' : 'rgba(242,92,92,0.2)',
                              background: isBlocked ? 'rgba(34,211,160,0.08)' : 'rgba(242,92,92,0.08)',
                              color: isBlocked ? '#22d3a0' : '#f25c5c',
                            }}>
                              {isBlocked ? <><Eye size={11} /> Unblock</> : <><Ban size={11} /> Block</>}
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </>
            )}
          </div>
        </div>
      )}

      <style>{`
        @keyframes scanBar { from { width: 0; } to { width: 100%; } }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
