import { useEffect, useState } from 'react'
import { api } from '../utils/api.js'
import SettingsForm from './SettingsForm.jsx'
import { Toast } from './ui.jsx'
import { AlertTriangle } from 'lucide-react'

// The furniture every settings-driven page shares. It lives here rather than
// in one of the page files because ConfigPages, ProtectionPages and
// OpsExtraPages all need it, and three copies would drift.

export function useToast() {
  const [toast, setToast] = useState(null)
  return {
    toast,
    show: (message, type = 'success') => setToast({ message, type, id: Date.now() }),
    hide: () => setToast(null),
  }
}

export function PageHeader({ icon: Icon, color = 'accent', title, subtitle }) {
  return (
    <div className="flex items-center gap-3 mb-5">
      <div className={`stat-icon ${color}`}><Icon size={18} /></div>
      <div>
        <h1 className="text-lg font-bold text-cat-text">{title}</h1>
        <p className="text-xs text-cat-sub">{subtitle}</p>
      </div>
    </div>
  )
}

// Anything the operator has switched on that could not actually be rendered.
// This is the panel that answers "I enabled it, why is nothing happening?" —
// without it, a missing Caddy module is a silent no-op.
export function RenderReport({ report }) {
  if (!report?.skipped?.length) return null
  return (
    <div className="card" style={{ borderColor: 'rgba(251,191,36,.3)' }}>
      <div className="section-title" style={{ color: '#fbbf24' }}>
        <AlertTriangle size={13} style={{ display: 'inline', verticalAlign: -2, marginRight: 6 }} />
        Not currently in effect
      </div>
      <p className="text-xs text-cat-sub mb-3">
        These settings are switched on but could not be written into the generated configuration. CatWAF skips them rather than
        emitting a directive Caddy would reject, which would take the whole site down.
      </p>
      <div className="space-y-2">
        {report.skipped.map((s, i) => (
          <div key={i} style={{ padding: 9, borderRadius: 8, background: 'var(--cat-bg)', border: '1px solid var(--cat-border)' }}>
            <div className="text-xs font-medium text-cat-text">{s.feature}</div>
            <div className="text-[11.5px] text-cat-sub mt-0.5">{s.reason}</div>
            {s.module && <div className="text-[10.5px] text-cat-sub mt-1" style={{ fontFamily: 'monospace', opacity: 0.7 }}>{s.module}</div>}
          </div>
        ))}
      </div>
    </div>
  )
}

export function useRenderReport(refreshKey) {
  const [report, setReport] = useState(null)
  useEffect(() => {
    api.get('/config/render-report').then(r => setReport(r.report)).catch(() => setReport(null))
  }, [refreshKey])
  return report
}

export function GroupsPage({ icon, color, title, subtitle, groups, children, footer }) {
  const { toast, show, hide } = useToast()
  const [version, setVersion] = useState(0)
  const report = useRenderReport(version)

  const onSaved = res => {
    show(
      res.reloaded === false && res.reload_error ? `Saved, but Caddy did not reload: ${res.reload_error}` : 'Applied',
      res.reload_error ? 'error' : 'success',
    )
    setVersion(v => v + 1)
  }

  return (
    <div className="p-6 max-w-3xl mx-auto page-enter space-y-4">
      {toast && <Toast {...toast} onClose={hide} />}
      <PageHeader icon={icon} color={color} title={title} subtitle={subtitle} />
      {children}
      {groups.map(g => (
        <SettingsForm key={g} group={g} onSaved={onSaved} onError={m => show(m, 'error')} />
      ))}
      {footer}
      <RenderReport report={report} />
    </div>
  )
}

// A note explaining why something is off by default, or what it costs. Used
// wherever a toggle has a real trade-off the operator should read first.
export function Caveat({ title, children, tone = 'warn' }) {
  const border = tone === 'danger' ? 'rgba(248,113,113,.3)' : tone === 'info' ? 'rgba(79,142,247,.3)' : 'rgba(251,191,36,.3)'
  const heading = tone === 'danger' ? '#f87171' : tone === 'info' ? 'var(--cat-text)' : '#fbbf24'
  return (
    <div className="card" style={{ borderColor: border }}>
      {title && <div className="text-xs font-medium mb-1.5" style={{ color: heading }}>{title}</div>}
      <div className="text-[11.5px] text-cat-sub leading-relaxed space-y-1.5">{children}</div>
    </div>
  )
}

export function KeyValue({ rows }) {
  return (
    <div className="space-y-0">
      {rows.filter(Boolean).map(([k, v]) => (
        <div key={k} className="flex items-center justify-between gap-4" style={{ padding: '7px 0', borderBottom: '1px solid var(--cat-border)' }}>
          <span className="text-xs text-cat-sub">{k}</span>
          <span className="text-xs text-cat-text" style={{ textAlign: 'right', wordBreak: 'break-word' }}>{v}</span>
        </div>
      ))}
    </div>
  )
}

export function relativeTime(iso) {
  if (!iso) return 'never'
  const then = new Date(iso).getTime()
  if (!Number.isFinite(then)) return String(iso)
  const delta = Math.round((then - Date.now()) / 1000)
  const abs = Math.abs(delta)
  const units = [[60, 'second'], [60, 'minute'], [24, 'hour'], [7, 'day'], [4.35, 'week'], [12, 'month']]
  let value = abs
  let unit = 'second'
  for (const [step, name] of units) {
    if (value < step) { unit = name; break }
    value = value / step
    unit = name
  }
  const n = Math.round(value)
  const label = `${n} ${unit}${n === 1 ? '' : 's'}`
  return delta < 0 ? `${label} ago` : `in ${label}`
}

export function bytes(n) {
  if (n === null || n === undefined) return '—'
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`
}
