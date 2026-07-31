import React, { useEffect, useState } from 'react'
import { api } from '../utils/api.js'
import { Card, SectionTitle, Badge, ActionBar, Spinner, Toast, EmptyState, ProgressBar } from '../components/ui.jsx'
import {
  AlertTriangle, XCircle, CheckCircle, ShieldAlert,
  Gauge, Zap, ShieldCheck, Activity, RefreshCw, Search
} from 'lucide-react'

function useToast() {
  const [toast, setToast] = useState(null)
  const show = (message, type='success') => setToast({ message, type, id: Date.now() })
  return { toast, show, hide: () => setToast(null) }
}

export function OriginScannerPage() {
  const [domain, setDomain] = useState('')
  const [ip, setIp] = useState('')
  const [port, setPort] = useState(8081)
  const [authorized, setAuthorized] = useState(false)
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const { toast, show, hide } = useToast()

  const needsAuthorization = ip.trim().length > 0
  const canScan = !needsAuthorization || authorized

  const scan = async () => {
    setBusy(true); setResult(null)
    try { setResult(await api.post('/scanner/origin-exposure', { domain: domain||undefined, origin_ip: ip||undefined, origin_port: +port, authorized })) }
    catch(e) { show(e.message, 'error') }
    finally { setBusy(false) }
  }

  return (
    <div className="p-6 max-w-2xl mx-auto page-enter">
      {toast && <Toast {...toast} onClose={hide}/>}
      <div className="flex items-center gap-3 mb-6">
        <div className="stat-icon orange"><Search size={18}/></div>
        <div>
          <h1 className="text-lg font-bold text-cat-text">Origin Exposure Scanner</h1>
          <p className="text-xs text-cat-sub">Verify your real server can't be reached bypassing Cloudflare</p>
        </div>
      </div>

      <div className="card mb-4">
        <div className="space-y-3">
          <div>
            <label className="text-xs text-cat-sub font-medium block mb-1.5">Domain (checks it resolves through Cloudflare)</label>
            <input className="input" placeholder="example.com" value={domain} onChange={e=>setDomain(e.target.value)}/>
          </div>
          <div className="flex gap-2">
            <div className="flex-1">
              <label className="text-xs text-cat-sub font-medium block mb-1.5">Origin IP (checks direct reachability)</label>
              <input className="input" placeholder="203.0.113.5" value={ip} onChange={e=>setIp(e.target.value)}/>
            </div>
            <div style={{width:100}}>
              <label className="text-xs text-cat-sub font-medium block mb-1.5">Port</label>
              <input className="input" type="number" value={port} onChange={e=>setPort(e.target.value)}/>
            </div>
          </div>
          {needsAuthorization && (
            <label className="flex items-start gap-2 text-xs text-cat-sub cursor-pointer">
              <input
                type="checkbox"
                checked={authorized}
                onChange={e => setAuthorized(e.target.checked)}
                className="mt-0.5"
                required
              />
              <span>I own this host or am authorized to test it.</span>
            </label>
          )}

          <button className="btn btn-primary w-full justify-center" onClick={scan} disabled={busy || !canScan}>
            {busy ? <><Spinner size={13}/>Scanning...</> : <><Search size={13}/>Run Scan</>}
          </button>
        </div>
      </div>

      {result && (
        <div className="space-y-3 animate-slide-up">
          <div className="card" style={{borderColor: result.exposed ? 'rgba(242,92,92,.3)' : 'rgba(34,211,160,.3)'}}>
            <div className="flex items-center gap-3">
              {result.exposed ? <ShieldAlert size={22} className="text-cat-red"/> : <ShieldCheck size={22} className="text-cat-green"/>}
              <div className={`text-sm font-bold ${result.exposed?'text-cat-red':'text-cat-green'}`}>
                {result.exposed ? 'Origin may be exposed' : 'Origin looks properly locked down'}
              </div>
            </div>
          </div>

          <div className="card">
            <SectionTitle>Checks</SectionTitle>
            <div className="space-y-2">
              {result.checks.map((c,i) => (
                <div key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-cat-surface">
                  {c.pass === true ? <CheckCircle size={13} className="text-cat-green mt-0.5 flex-shrink-0"/> :
                   c.pass === false ? <XCircle size={13} className="text-cat-red mt-0.5 flex-shrink-0"/> :
                   <AlertTriangle size={13} className="text-cat-sub mt-0.5 flex-shrink-0"/>}
                  <div>
                    <div className="text-xs text-cat-text">{c.name}</div>
                    <div className="text-[10px] text-cat-sub mt-0.5">{c.detail}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export function PerformanceModePage() {
  const [data, setData] = useState(null)
  const [busy, setBusy] = useState(false)
  const { toast, show, hide } = useToast()

  const load = () => api.get('/performance-mode').then(setData).catch(()=>{})
  useEffect(() => { load() }, [])

  const apply = async (mode) => {
    setBusy(true)
    try { await api.post('/performance-mode', { mode }); show(`Applied ${mode} mode`); load() }
    catch(e) { show(e.message,'error') }
    finally { setBusy(false) }
  }

  if (!data) return <div className="p-6"><Spinner size={20}/></div>

  const ICONS = { fast: Zap, balanced: Gauge, maximum: ShieldAlert }
  const COLORS = { fast: '#22d3a0', balanced: '#4f8ef7', maximum: '#f25c5c' }

  return (
    <div className="p-6 max-w-2xl mx-auto page-enter">
      {toast && <Toast {...toast} onClose={hide}/>}
      <div className="flex items-center gap-3 mb-6">
        <div className="stat-icon accent"><Gauge size={18}/></div>
        <div>
          <h1 className="text-lg font-bold text-cat-text">Performance Mode</h1>
          <p className="text-xs text-cat-sub">One click to retune paranoia, thresholds, and inspection depth</p>
        </div>
      </div>

      <div className="space-y-3">
        {Object.entries(data.presets).map(([key, preset]) => {
          const Icon = ICONS[key]
          const active = data.current_mode === key
          return (
            <div key={key} className={`card ${active?'card-glow':''}`} style={{borderColor: active ? `color-mix(in srgb, ${COLORS[key]} 40%, var(--cat-border))` : undefined}}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="stat-icon" style={{background:`color-mix(in srgb,${COLORS[key]} 16%,transparent)`,color:COLORS[key]}}><Icon size={16}/></div>
                  <div>
                    <div className="text-sm font-semibold text-cat-text">{preset.label}</div>
                    <div className="text-xs text-cat-sub">PL{preset.paranoia_level}/{preset.executing_paranoia_level} · threshold {preset.inbound_anomaly_threshold} · sampling {preset.sampling_percentage}%</div>
                  </div>
                </div>
                {active ? <Badge color="green">Active</Badge> : (
                  <button className="btn btn-primary btn-sm" onClick={()=>apply(key)} disabled={busy}>Apply</button>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export function DiagnosticsPage() {
  const [data, setData] = useState(null)
  const [busy, setBusy] = useState(true)

  const load = () => { setBusy(true); api.get('/diagnostics').then(setData).catch(()=>{}).finally(()=>setBusy(false)) }
  useEffect(() => { load() }, [])

  if (busy) return <div className="p-6"><Spinner size={20}/></div>

  const LABELS = {
    caddy: 'Caddy', coraza: 'Coraza Module', crs: 'OWASP CRS', caddyfile_valid: 'Caddyfile Syntax',
    cloudflare: 'Cloudflare Origin Lock', tls: 'TLS Certificate', database: 'Database',
  }

  return (
    <div className="p-6 max-w-2xl mx-auto page-enter">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className={`stat-icon ${data?.overall==='healthy'?'green':'red'}`}><Activity size={18}/></div>
          <div>
            <h1 className="text-lg font-bold text-cat-text">Setup Diagnostics</h1>
            <p className="text-xs text-cat-sub">One page — is everything actually working?</p>
          </div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={load}><RefreshCw size={12}/> Re-check</button>
      </div>

      <div className="card">
        <div className="space-y-1">
          {Object.entries(data?.checks||{}).map(([key, check]) => (
            <div key={key} className="flex items-center justify-between p-3 rounded-lg hover:bg-cat-surface transition-colors">
              <span className="text-sm text-cat-text">{LABELS[key]||key}</span>
              {check.ok === true && <Badge color="green"><CheckCircle size={11}/> OK</Badge>}
              {check.ok === false && <Badge color="red"><XCircle size={11}/> Issue</Badge>}
              {check.ok === null && <Badge color="muted">N/A</Badge>}
            </div>
          ))}
        </div>
      </div>
      <div className="mt-3 text-xs text-cat-sub">
        {Object.entries(data?.checks||{}).filter(([,c])=>c.ok===false).map(([k,c]) => (
          <div key={k} className="p-2">→ <span className="text-cat-text">{LABELS[k]||k}:</span> {c.detail}</div>
        ))}
      </div>
    </div>
  )
}
