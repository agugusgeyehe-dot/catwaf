import { useEffect, useState } from 'react'
import { api, apiDownload } from '../utils/api.js'
import SettingsForm from '../components/SettingsForm.jsx'
import QRCode from '../components/QRCode.jsx'
import { Toast, Badge, Spinner, EmptyState } from '../components/ui.jsx'
import { PageHeader, useToast, Caveat, KeyValue, relativeTime, bytes } from '../components/pageKit.jsx'
import {
  Clock, Database, LayoutTemplate, FileBarChart, KeyRound, Archive, Send,
  Play, RefreshCw, Trash2, Download, Upload, Eye, CheckCircle, AlertTriangle, Copy,
} from 'lucide-react'

function todayIso(offsetDays = 0) {
  const d = new Date(Date.now() + offsetDays * 86400000)
  return d.toISOString().slice(0, 10)
}

// ─── Scheduled jobs (#44) ───────────────────────────────────────────────

export function JobsPage() {
  const { toast, show, hide } = useToast()
  const [data, setData] = useState(null)
  const [running, setRunning] = useState('')

  const load = () => api.get('/jobs').then(setData).catch(e => show(e.message, 'error'))
  useEffect(() => { load() }, [])

  const runNow = async (name) => {
    setRunning(name)
    try {
      const r = await api.post(`/jobs/${encodeURIComponent(name)}/run`, {})
      show(r.ok ? `${name} finished` : `${name} failed: ${r.error || 'unknown error'}`, r.ok ? 'success' : 'error')
      await load()
    } catch (e) { show(e.message, 'error') }
    finally { setRunning('') }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader icon={Clock} color="blue" title="Scheduled jobs" subtitle="Everything CatWAF does on a timer, in one schedule" />

      <Caveat tone="info" title="One scheduler, not one timer per feature">
        <p>
          List refreshes, ban expiry, backups, certificate checks and telemetry all run from the same loop. A job whose feature is
          switched off is listed but never scheduled, so this page is also the answer to "is that actually running?".
        </p>
      </Caveat>

      <div className="card">
        <div className="flex items-center justify-between mb-2">
          <div className="section-title" style={{ marginBottom: 0 }}>Jobs</div>
          <button className="btn btn-sm btn-ghost" onClick={load}><RefreshCw size={13} /> Refresh</button>
        </div>
        {!data ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 28 }}><Spinner label="Loading jobs" /></div>
        ) : (
          <div className="space-y-2">
            {data.jobs.map(job => {
              const last = job.last_run
              return (
                <div key={job.name} style={{ padding: 10, borderRadius: 8, border: '1px solid var(--cat-border)' }}>
                  <div className="flex items-start justify-between gap-3">
                    <div style={{ minWidth: 0 }}>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs text-cat-text font-medium">{job.label}</span>
                        {job.disabled
                          ? <Badge color="muted">disabled</Badge>
                          : !job.feature_enabled
                            ? <Badge color="muted">feature off</Badge>
                            : <Badge color="green">scheduled</Badge>}
                        {job.running && <Badge color="blue">running</Badge>}
                      </div>
                      <div className="text-[11.5px] text-cat-sub mt-1">{job.description}</div>
                      <div className="text-[10.5px] text-cat-sub mt-1" style={{ opacity: 0.75 }}>
                        every {job.interval_sec}s
                        {job.next_run_at ? ` · next ${relativeTime(job.next_run_at)}` : ' · not scheduled'}
                        {last ? ` · last ${relativeTime(last.at)}${last.ok === false ? ' (failed)' : ''}` : ' · never run'}
                      </div>
                      {last?.error && (
                        <div className="text-[10.5px] mt-1" style={{ color: '#f87171' }}>{last.error}</div>
                      )}
                    </div>
                    <button className="btn btn-sm btn-ghost flex-shrink-0" disabled={!!running} onClick={() => runNow(job.name)}>
                      {running === job.name ? <Spinner size={13} /> : <Play size={13} />} Run now
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      <SettingsForm group="jobs" onSaved={() => { show('Applied'); load() }} onError={m => show(m, 'error')} />
    </div>
  )
}

// ─── Caches (#63) ───────────────────────────────────────────────────────

export function CachesPage() {
  const { toast, show, hide } = useToast()
  const [data, setData] = useState(null)
  const [busy, setBusy] = useState('')

  const load = () => api.get('/caches').then(setData).catch(e => show(e.message, 'error'))
  useEffect(() => { load() }, [])

  const act = async (id, what) => {
    setBusy(id + what)
    try {
      await api.post(`/caches/${encodeURIComponent(id)}/${what}`, {})
      show(what === 'clear' ? 'Cleared' : 'Refreshed')
      await load()
    } catch (e) { show(e.message, 'error') }
    finally { setBusy('') }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader icon={Database} color="purple" title="Caches" subtitle="What CatWAF is holding on to, and how to make it forget" />

      <Caveat tone="info" title="Clearing a cache is safe, but not free">
        <p>
          Every namespace here is rebuildable — nothing is lost by clearing it. The cost is that the next request needing that
          data pays for the lookup again, which for DNS-based checks means a visible pause on the first request from an address.
        </p>
      </Caveat>

      {!data ? (
        <div className="card" style={{ display: 'flex', justifyContent: 'center', padding: 32 }}><Spinner label="Loading caches" /></div>
      ) : (
        <>
          <div className="card">
            <div className="flex items-center justify-between mb-2">
              <div className="section-title" style={{ marginBottom: 0 }}>
                {data.total_entries} entries · {bytes(data.total_bytes)}
              </div>
              <div className="flex gap-2">
                <button className="btn btn-sm btn-ghost" onClick={load}><RefreshCw size={13} /> Refresh</button>
                <button className="btn btn-sm btn-ghost" disabled={busy === 'allclear'} onClick={() => act('all', 'clear')}>
                  <Trash2 size={13} /> Clear everything
                </button>
              </div>
            </div>
            <div className="space-y-2">
              {data.namespaces.map(ns => (
                <div key={ns.id} className="flex items-start justify-between gap-3" style={{ padding: 10, borderRadius: 8, border: '1px solid var(--cat-border)' }}>
                  <div style={{ minWidth: 0 }}>
                    <div className="text-xs text-cat-text font-medium">{ns.label}</div>
                    <div className="text-[11.5px] text-cat-sub mt-0.5">{ns.description}</div>
                    <div className="text-[10.5px] text-cat-sub mt-1" style={{ opacity: 0.75 }}>
                      {ns.entries ?? '—'} entries
                      {ns.bytes !== null ? ` · ${bytes(ns.bytes)}` : ''}
                      {ns.last_refresh ? ` · refreshed ${relativeTime(ns.last_refresh)}` : ''}
                      {ns.detail ? ` · ${ns.detail}` : ''}
                    </div>
                    {ns.error && <div className="text-[10.5px] mt-1" style={{ color: '#f87171' }}>{ns.error}</div>}
                  </div>
                  <div className="flex gap-2 flex-shrink-0">
                    {ns.can_refresh && (
                      <button className="btn btn-sm btn-ghost" disabled={busy === ns.id + 'refresh'} onClick={() => act(ns.id, 'refresh')}>
                        Refresh
                      </button>
                    )}
                    <button className="btn btn-sm btn-ghost" disabled={busy === ns.id + 'clear'} onClick={() => act(ns.id, 'clear')}>
                      Clear
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {data.geoip && (
            <div className="card">
              <div className="section-title">GeoIP database</div>
              <KeyValue rows={Object.entries(data.geoip).map(([k, v]) => [
                k.replace(/_/g, ' '), typeof v === 'boolean' ? (v ? 'yes' : 'no') : String(v ?? '—'),
              ])} />
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ─── Templates (#64) ────────────────────────────────────────────────────

export function TemplatesPage() {
  const { toast, show, hide } = useToast()
  const [templates, setTemplates] = useState(null)
  const [dryRun, setDryRun] = useState(null)
  const [saveName, setSaveName] = useState('')
  const [importText, setImportText] = useState('')
  const [busy, setBusy] = useState(false)

  const load = () => api.get('/templates').then(d => setTemplates(d.templates)).catch(e => show(e.message, 'error'))
  useEffect(() => { load() }, [])

  // Always preview first. Applying a template rewrites several settings
  // groups at once, which is exactly the change you want to read before it
  // happens rather than after.
  const preview = async (id) => {
    setBusy(true)
    try { setDryRun({ id, ...(await api.post(`/templates/${encodeURIComponent(id)}/apply`, { dry_run: true })) }) }
    catch (e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  const confirmApply = async () => {
    setBusy(true)
    try {
      const r = await api.post(`/templates/${encodeURIComponent(dryRun.id)}/apply`, { dry_run: false })
      show(`Applied — ${r.changes?.length || 0} setting(s) changed`)
      setDryRun(null)
    } catch (e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader icon={LayoutTemplate} color="blue" title="Configuration templates" subtitle="Save a working setup, or start from a known-good one" />

      <div className="card">
        <div className="section-title">Available templates</div>
        {!templates ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 24 }}><Spinner label="Loading" /></div>
        ) : (
          <div className="space-y-2">
            {templates.map(t => (
              <div key={t.id} className="flex items-start justify-between gap-3" style={{ padding: 10, borderRadius: 8, border: '1px solid var(--cat-border)' }}>
                <div style={{ minWidth: 0 }}>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs text-cat-text font-medium">{t.label}</span>
                    {t.built_in && <Badge>built-in</Badge>}
                    {t.includes_waf && <Badge color="orange">changes WAF mode</Badge>}
                  </div>
                  {t.description && <div className="text-[11.5px] text-cat-sub mt-0.5">{t.description}</div>}
                  <div className="text-[10.5px] text-cat-sub mt-1" style={{ opacity: 0.75 }}>
                    {(t.groups || []).join(', ') || 'no settings groups'}
                  </div>
                </div>
                <div className="flex gap-2 flex-shrink-0">
                  <button className="btn btn-sm btn-ghost" disabled={busy} onClick={() => preview(t.id)}><Eye size={13} /> Preview</button>
                  <button className="btn btn-sm btn-ghost" onClick={() => apiDownload(`/templates/${encodeURIComponent(t.id)}/export`, `${t.id}.json`).catch(e => show(e.message, 'error'))}>
                    <Download size={13} />
                  </button>
                  {!t.built_in && (
                    <button className="btn btn-sm btn-ghost" disabled={busy} onClick={async () => {
                      try { await api.delete(`/templates/${encodeURIComponent(t.id)}`); show('Removed'); load() }
                      catch (e) { show(e.message, 'error') }
                    }}><Trash2 size={13} /></button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {dryRun && (
        <div className="card" style={{ borderColor: 'rgba(79,142,247,.4)' }}>
          <div className="section-title">What "{dryRun.template}" would change</div>
          {dryRun.changes?.length === 0 ? (
            <p className="text-xs text-cat-sub">Nothing — your configuration already matches this template.</p>
          ) : (
            <div style={{ maxHeight: 300, overflow: 'auto', border: '1px solid var(--cat-border)', borderRadius: 8 }}>
              {dryRun.changes.map((c, i) => (
                <div key={i} style={{ padding: '7px 10px', borderBottom: '1px solid var(--cat-border)' }}>
                  <div className="text-[11px] text-cat-sub" style={{ fontFamily: 'monospace' }}>{c.group}.{c.field}</div>
                  <div className="text-[11.5px]" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <span style={{ color: '#f87171' }}>{JSON.stringify(c.from)}</span>
                    <span className="text-cat-sub">→</span>
                    <span style={{ color: '#4ade80' }}>{JSON.stringify(c.to)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
          <div className="flex gap-2 mt-3">
            <button className="btn btn-sm btn-primary" disabled={busy || !dryRun.changes?.length} onClick={confirmApply}>Apply this template</button>
            <button className="btn btn-sm btn-ghost" onClick={() => setDryRun(null)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="card">
        <div className="section-title">Save your current configuration as a template</div>
        <div className="flex gap-2">
          <input className="input flex-1" placeholder="Template name" value={saveName} onChange={e => setSaveName(e.target.value)} />
          <button className="btn btn-sm btn-ghost" disabled={busy || !saveName.trim()} onClick={async () => {
            try { await api.post('/templates', { name: saveName.trim() }); setSaveName(''); show('Template saved'); load() }
            catch (e) { show(e.message, 'error') }
          }}>Save</button>
        </div>
      </div>

      <div className="card">
        <div className="section-title">Import a template</div>
        <textarea className="input" rows={4} style={{ fontFamily: 'monospace', fontSize: 11 }}
          placeholder='{"catwaf_template": 1, "id": "…", "label": "…", "settings": {…}}'
          value={importText} onChange={e => setImportText(e.target.value)} />
        <button className="btn btn-sm btn-ghost" style={{ marginTop: 8 }} disabled={busy || !importText.trim()} onClick={async () => {
          try {
            await api.post('/templates/import', JSON.parse(importText))
            setImportText(''); show('Template imported'); load()
          } catch (e) { show(e.message, 'error') }
        }}>
          <Upload size={13} /> Import
        </button>
      </div>
    </div>
  )
}

// ─── Reports (#51) ──────────────────────────────────────────────────────

export function ReportsPage() {
  const { toast, show, hide } = useToast()
  const [from, setFrom] = useState(todayIso(-30))
  const [to, setTo] = useState(todayIso())
  const [report, setReport] = useState(null)
  const [busy, setBusy] = useState(false)

  const range = () => `?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`

  const load = async () => {
    setBusy(true)
    try { setReport(await api.get(`/reports${range()}`)) }
    catch (e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }
  useEffect(() => { load() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const download = async (format) => {
    try { await apiDownload(`/reports${range()}&format=${format}`, `catwaf-report.${format === 'html' ? 'html' : 'csv'}`) }
    catch (e) { show(e.message, 'error') }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader icon={FileBarChart} color="green" title="Reports" subtitle="Export what happened over a date range" />

      <div className="card">
        <div className="flex flex-wrap gap-2 items-end">
          <div style={{ flex: '1 1 140px' }}>
            <label className="text-[10px] text-cat-sub uppercase tracking-wide block mb-1">From</label>
            <input className="input" type="date" value={from} onChange={e => setFrom(e.target.value)} />
          </div>
          <div style={{ flex: '1 1 140px' }}>
            <label className="text-[10px] text-cat-sub uppercase tracking-wide block mb-1">To</label>
            <input className="input" type="date" value={to} onChange={e => setTo(e.target.value)} />
          </div>
          <button className="btn btn-sm btn-ghost" onClick={load} disabled={busy}>
            {busy ? <Spinner size={13} /> : <RefreshCw size={13} />} Preview
          </button>
        </div>
        <div className="flex flex-wrap gap-2 mt-3 pt-3" style={{ borderTop: '1px solid var(--cat-border)' }}>
          <button className="btn btn-sm btn-ghost" onClick={() => download('csv')}><Download size={13} /> Summary CSV</button>
          <button className="btn btn-sm btn-ghost" onClick={() => download('events-csv')}><Download size={13} /> Every event CSV</button>
          <button className="btn btn-sm btn-ghost" onClick={() => download('html')}><Download size={13} /> Printable HTML</button>
        </div>
      </div>

      {report && (
        <>
          <div className="card">
            <div className="section-title">
              {String(report.range?.start).slice(0, 10)} → {String(report.range?.end).slice(0, 10)}
            </div>
            <div className="flex flex-wrap gap-5">
              {[
                ['Requests', report.totals.requests],
                ['Blocked', report.totals.blocked],
                ['Block rate', `${report.totals.block_rate}%`],
                ['Unique addresses', report.totals.unique_ips],
              ].map(([k, v]) => (
                <div key={k}>
                  <div className="text-lg font-bold text-cat-text">{typeof v === 'number' ? v.toLocaleString() : v}</div>
                  <div className="text-[11px] text-cat-sub uppercase tracking-wide">{k}</div>
                </div>
              ))}
            </div>
          </div>

          {report.totals.requests === 0 ? (
            <div className="card">
              <EmptyState icon={FileBarChart} title="No traffic in this range" desc="Nothing was logged between these dates." />
            </div>
          ) : (
            <div className="card">
              <div className="section-title">Top blocked categories</div>
              {report.by_category.length === 0 ? (
                <p className="text-xs text-cat-sub">Nothing was blocked in this range.</p>
              ) : (
                <div className="space-y-1">
                  {report.by_category.slice(0, 12).map(c => (
                    <div key={c.category} className="flex items-center justify-between" style={{ padding: '5px 0', borderBottom: '1px solid var(--cat-border)' }}>
                      <span className="text-xs text-cat-text">{c.category}</span>
                      <span className="text-xs text-cat-sub">{c.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ─── Two-factor login (#49) ─────────────────────────────────────────────

function RecoveryCodes({ codes, onDone }) {
  return (
    <div className="card" style={{ borderColor: 'rgba(251,191,36,.4)' }}>
      <div className="section-title" style={{ color: '#fbbf24' }}>
        <AlertTriangle size={13} style={{ display: 'inline', verticalAlign: -2, marginRight: 6 }} />
        Recovery codes — shown once
      </div>
      <p className="text-xs text-cat-sub mb-3">
        Store these somewhere that is not the device running your authenticator. Each works once, and they are the only way back
        in if you lose the app.
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(130px, 1fr))', gap: 6 }}>
        {codes.map(c => (
          <code key={c} style={{ padding: '6px 8px', background: 'var(--cat-bg)', border: '1px solid var(--cat-border)', borderRadius: 6, fontSize: 12, textAlign: 'center' }}>
            {c}
          </code>
        ))}
      </div>
      <div className="flex gap-2 mt-3">
        <button className="btn btn-sm btn-ghost" onClick={() => navigator.clipboard?.writeText(codes.join('\n'))}>
          <Copy size={13} /> Copy all
        </button>
        <button className="btn btn-sm btn-primary" onClick={onDone}>I have saved them</button>
      </div>
    </div>
  )
}

export function TwoFactorPage() {
  const { toast, show, hide } = useToast()
  const [status, setStatus] = useState(null)
  const [enrollment, setEnrollment] = useState(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [recovery, setRecovery] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = () => api.get('/auth/2fa').then(setStatus).catch(e => show(e.message, 'error'))
  useEffect(() => { load() }, [])

  const begin = async () => {
    setBusy(true)
    try { setEnrollment(await api.post('/auth/2fa/enroll', {})) }
    catch (e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  const confirm = async () => {
    setBusy(true)
    try {
      const r = await api.post('/auth/2fa/confirm', { code: code.trim() })
      setEnrollment(null); setCode('')
      setRecovery(r.recovery_codes || [])
      show('Two-factor login is now required for this account')
      await load()
    } catch (e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  const disable = async () => {
    setBusy(true)
    try {
      await api.post('/auth/2fa/disable', { password })
      setPassword(''); show('Two-factor authentication disabled')
      await load()
    } catch (e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  const regenerate = async () => {
    setBusy(true)
    try {
      const r = await api.post('/auth/2fa/recovery-codes', { password })
      setPassword(''); setRecovery(r.recovery_codes || [])
      await load()
    } catch (e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader icon={KeyRound} color="green" title="Two-factor authentication" subtitle="A time-based code on top of your password" />

      {recovery && <RecoveryCodes codes={recovery} onDone={() => setRecovery(null)} />}

      {!status ? (
        <div className="card" style={{ display: 'flex', justifyContent: 'center', padding: 32 }}><Spinner label="Loading" /></div>
      ) : status.enabled ? (
        <>
          <div className="card">
            <div className="section-title">
              <CheckCircle size={13} style={{ display: 'inline', verticalAlign: -2, marginRight: 6, color: '#4ade80' }} />
              Enabled
            </div>
            <KeyValue rows={[
              ['Confirmed', status.confirmed_at ? relativeTime(status.confirmed_at) : '—'],
              ['Recovery codes left', status.recovery_codes_remaining],
            ]} />
          </div>

          <div className="card">
            <div className="section-title">Confirm your password to change this</div>
            <p className="text-xs text-cat-sub mb-3">
              Disabling a second factor is exactly what a stolen session would try, so it asks for your password again.
            </p>
            <input className="input" type="password" placeholder="Current password" value={password} onChange={e => setPassword(e.target.value)} />
            <div className="flex gap-2 mt-3">
              <button className="btn btn-sm btn-ghost" disabled={busy || !password} onClick={regenerate}>New recovery codes</button>
              <button className="btn btn-sm btn-ghost" disabled={busy || !password} onClick={disable}>Disable two-factor</button>
            </div>
          </div>
        </>
      ) : enrollment ? (
        <div className="card">
          <div className="section-title">Scan this, then prove it works</div>
          <p className="text-xs text-cat-sub mb-3">
            Nothing is enforced until you enter a working code below — enrolling without that check is how people lock themselves out.
          </p>
          <div className="flex flex-wrap gap-5 items-start">
            <QRCode text={enrollment.uri} size={192} title="Two-factor enrollment QR code" />
            <div style={{ flex: '1 1 240px', minWidth: 0 }}>
              <div className="text-[11px] text-cat-sub uppercase tracking-wide mb-1">Or type the secret</div>
              <code style={{ display: 'block', padding: 9, background: 'var(--cat-bg)', border: '1px solid var(--cat-border)', borderRadius: 8, fontSize: 12, wordBreak: 'break-all' }}>
                {enrollment.secret}
              </code>
              <button className="btn btn-sm btn-ghost" style={{ marginTop: 6 }} onClick={() => navigator.clipboard?.writeText(enrollment.secret)}>
                <Copy size={13} /> Copy secret
              </button>
              <div className="text-[10.5px] text-cat-sub mt-2" style={{ opacity: 0.75 }}>
                {enrollment.digits} digits, {enrollment.period}s period
              </div>
            </div>
          </div>
          <div className="flex gap-2 mt-4 pt-3" style={{ borderTop: '1px solid var(--cat-border)' }}>
            <input
              className="input" style={{ maxWidth: 160, fontFamily: 'monospace', letterSpacing: '0.2em', textAlign: 'center' }}
              placeholder="000000" inputMode="numeric" value={code} onChange={e => setCode(e.target.value)}
            />
            <button className="btn btn-sm btn-primary" disabled={busy || !code.trim()} onClick={confirm}>Confirm</button>
            <button className="btn btn-sm btn-ghost" disabled={busy} onClick={() => { setEnrollment(null); setCode('') }}>Cancel</button>
          </div>
        </div>
      ) : (
        <div className="card">
          <div className="section-title">Not enabled</div>
          <p className="text-xs text-cat-sub mb-3">
            With two-factor login on, a stolen password on its own is no longer enough to reach this control panel.
          </p>
          <button className="btn btn-sm btn-primary" disabled={busy} onClick={begin}>Set up two-factor</button>
        </div>
      )}

      <SettingsForm group="session" onSaved={() => show('Applied')} onError={m => show(m, 'error')} />
    </div>
  )
}

// ─── Backups (#45) ──────────────────────────────────────────────────────

export function BackupsPage() {
  const { toast, show, hide } = useToast()
  const [data, setData] = useState(null)
  const [verify, setVerify] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = () => api.get('/backups').then(setData).catch(e => show(e.message, 'error'))
  useEffect(() => { load() }, [])

  const run = async (dryRun) => {
    setBusy(true)
    try {
      const r = await api.post('/backups/run', { dry_run: dryRun })
      if (r.skipped === 'disabled') show('Backups are switched off — set a destination below first.', 'info')
      else if (dryRun) show(`Would write ${r.would_write} (${bytes(r.bytes)})`, 'info')
      else { show(`Backup written: ${r.file}`); await load() }
    } catch (e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader icon={Archive} color="blue" title="Backups" subtitle="Snapshots of your configuration and request history" />

      <div className="card">
        <div className="flex items-center justify-between mb-2">
          <div className="section-title" style={{ marginBottom: 0 }}>Stored backups</div>
          <div className="flex gap-2">
            <button className="btn btn-sm btn-ghost" disabled={busy} onClick={async () => {
              setBusy(true)
              try { setVerify(await api.post('/backups/verify', {})) }
              catch (e) { show(e.message, 'error') }
              finally { setBusy(false) }
            }}>Check destination</button>
            <button className="btn btn-sm btn-ghost" disabled={busy} onClick={() => run(true)}><Eye size={13} /> Dry run</button>
            <button className="btn btn-sm btn-primary" disabled={busy} onClick={() => run(false)}><Play size={13} /> Back up now</button>
          </div>
        </div>

        {verify && (
          <div style={{ padding: 9, borderRadius: 8, marginBottom: 10, background: 'var(--cat-bg)', border: `1px solid ${verify.ok ? 'rgba(74,222,128,.3)' : 'rgba(248,113,113,.3)'}` }}>
            <div className="text-xs" style={{ color: verify.ok ? '#4ade80' : '#f87171' }}>
              {verify.ok ? `Writable — ${verify.destination}` : verify.error}
            </div>
          </div>
        )}

        {!data ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 24 }}><Spinner label="Loading" /></div>
        ) : !data.destination ? (
          <EmptyState
            icon={Archive}
            title="No backup destination set"
            desc="Choose a directory below and CatWAF will write snapshots there on the schedule you pick."
          />
        ) : data.backups.length === 0 ? (
          <EmptyState icon={Archive} title="No backups yet" desc={`Destination is ${data.destination}.`} />
        ) : (
          <div className="space-y-1">
            {data.backups.map(b => (
              <div key={b.name} className="flex items-center justify-between" style={{ padding: '7px 0', borderBottom: '1px solid var(--cat-border)' }}>
                <div>
                  <div className="text-xs text-cat-text" style={{ fontFamily: 'monospace' }}>{b.name}</div>
                  <div className="text-[10.5px] text-cat-sub">{relativeTime(b.created_at)} · {bytes(b.size_bytes)}</div>
                </div>
                {b.has_database && <Badge color="green">includes database</Badge>}
              </div>
            ))}
          </div>
        )}
        {data?.retain && <p className="text-[11px] text-cat-sub mt-3">Keeping the newest {data.retain}.</p>}
        {data?.error && <p className="text-[11px] mt-2" style={{ color: '#f87171' }}>{data.error}</p>}
      </div>

      <SettingsForm group="backups" onSaved={() => { show('Applied'); load() }} onError={m => show(m, 'error')} />
    </div>
  )
}

// ─── Telemetry (#47) ────────────────────────────────────────────────────

export function TelemetryPage() {
  const { toast, show, hide } = useToast()
  const [status, setStatus] = useState(null)
  const [busy, setBusy] = useState(false)

  const load = () => api.get('/telemetry').then(setStatus).catch(e => show(e.message, 'error'))
  useEffect(() => { load() }, [])

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader icon={Send} color="purple" title="Telemetry" subtitle="Off by default — and if you turn it on, this is exactly what leaves" />

      <Caveat tone="info" title="Never collected">
        {status?.never_collected?.map((n, i) => <p key={i}>· {n}</p>) || <p>Loading…</p>}
      </Caveat>

      {status && (
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <div className="section-title" style={{ marginBottom: 0 }}>The payload</div>
            <button className="btn btn-sm btn-ghost" disabled={busy} onClick={async () => {
              setBusy(true)
              try {
                const r = await api.post('/telemetry/send', { dry_run: true })
                show(r.sent ? 'Sent' : 'Dry run complete — nothing was transmitted', 'info')
              } catch (e) { show(e.message, 'error') }
              finally { setBusy(false) }
            }}>
              <Eye size={13} /> Dry run
            </button>
          </div>
          <p className="text-xs text-cat-sub mb-3">
            This is the real payload built from your install right now, not an illustration of one.
          </p>
          <pre style={{ margin: 0, padding: 10, fontSize: 11, background: 'var(--cat-bg)', border: '1px solid var(--cat-border)', borderRadius: 8, maxHeight: 320, overflow: 'auto' }}>
            {JSON.stringify(status.payload_preview, null, 2)}
          </pre>
          <div className="mt-3">
            <KeyValue rows={[
              ['Enabled', status.enabled ? 'yes' : 'no'],
              ['Endpoint configured', status.endpoint_configured ? 'yes' : 'no'],
              ['Last sent', status.last_sent ? relativeTime(status.last_sent) : 'never'],
            ]} />
          </div>
        </div>
      )}

      <SettingsForm group="telemetry" onSaved={() => { show('Applied'); load() }} onError={m => show(m, 'error')} />
      <SettingsForm group="metrics" onSaved={() => show('Applied')} onError={m => show(m, 'error')} />
    </div>
  )
}
