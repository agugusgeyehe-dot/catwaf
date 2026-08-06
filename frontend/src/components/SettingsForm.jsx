import { useEffect, useMemo, useState } from 'react'
import { api } from '../utils/api.js'
import { Toggle, Spinner } from './ui.jsx'
import { Plus, Trash2, Eye, RotateCcw, Save, AlertTriangle, Info } from 'lucide-react'

// A settings group renders itself from the schema the backend publishes at
// /api/settings/schema, so a new setting appears here the moment it is added
// to services/settings/schema.js — no matching UI change required. That also
// means the labels, help text and constraints on screen are the same ones
// the backend validates against, rather than a second copy that can drift.

function FieldLabel({ field }) {
  return (
    <div className="mb-1.5">
      <label className="text-xs text-cat-text font-medium block">{field.label}</label>
      {field.help && <p className="text-[11px] text-cat-sub mt-0.5 leading-snug">{field.help}</p>}
    </div>
  )
}

function ListEditor({ field, value, onChange, disabled }) {
  const [draft, setDraft] = useState('')
  const items = Array.isArray(value) ? value : []

  const add = () => {
    const parts = draft.split(/[\s,]+/).map(s => s.trim()).filter(Boolean)
    if (!parts.length) return
    onChange([...new Set([...items, ...parts])])
    setDraft('')
  }

  return (
    <div>
      <div className="flex gap-2">
        <input
          className="input flex-1" value={draft} disabled={disabled}
          placeholder={`Add ${field.item || 'entry'}… (space or comma separates several)`}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); add() } }}
        />
        <button className="btn btn-sm btn-ghost" onClick={add} disabled={disabled || !draft.trim()}>
          <Plus size={13} />
        </button>
      </div>
      {items.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mt-2">
          {items.map(item => (
            <span key={item} className="badge" style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
              <span style={{ fontFamily: 'var(--cat-mono, monospace)', fontSize: 11 }}>{item}</span>
              <button
                onClick={() => onChange(items.filter(i => i !== item))}
                disabled={disabled}
                aria-label={`Remove ${item}`}
                style={{ background: 'none', border: 0, cursor: 'pointer', color: 'inherit', opacity: 0.6, display: 'flex' }}
              >
                <Trash2 size={11} />
              </button>
            </span>
          ))}
        </div>
      )}
      {items.length === 0 && <p className="text-[11px] text-cat-sub mt-1.5">Empty.</p>}
    </div>
  )
}

function RecordsEditor({ field, value, onChange, disabled }) {
  const rows = Array.isArray(value) ? value : []
  const blank = Object.fromEntries((field.fields || []).map(f => [f.name, f.default]))

  const update = (idx, name, v) => onChange(rows.map((row, i) => (i === idx ? { ...row, [name]: v } : row)))

  return (
    <div className="space-y-2">
      {rows.map((row, idx) => (
        <div key={idx} className="flex flex-wrap gap-2 items-end" style={{ padding: 8, border: '1px solid var(--cat-border)', borderRadius: 8 }}>
          {(field.fields || []).map(sub => (
            <div key={sub.name} style={{ flex: sub.type === 'text' ? '1 1 100%' : '1 1 120px', minWidth: 90 }}>
              <label className="text-[10px] text-cat-sub uppercase tracking-wide block mb-1">{sub.name.replace(/_/g, ' ')}</label>
              {sub.type === 'bool' ? (
                <Toggle on={!!row[sub.name]} onChange={v => update(idx, sub.name, v)} disabled={disabled} />
              ) : sub.values ? (
                <select className="input" value={row[sub.name] ?? ''} disabled={disabled}
                  onChange={e => update(idx, sub.name, sub.type === 'int' || typeof sub.default === 'number' ? Number(e.target.value) : e.target.value)}>
                  {sub.values.map(v => <option key={String(v)} value={v}>{String(v) || '(none)'}</option>)}
                </select>
              ) : sub.type === 'text' ? (
                <textarea className="input" rows={3} value={row[sub.name] ?? ''} disabled={disabled}
                  onChange={e => update(idx, sub.name, e.target.value)} />
              ) : (
                <input className="input" type={sub.type === 'int' ? 'number' : 'text'} value={row[sub.name] ?? ''} disabled={disabled}
                  onChange={e => update(idx, sub.name, sub.type === 'int' ? Number(e.target.value) : e.target.value)} />
              )}
            </div>
          ))}
          <button className="btn btn-sm btn-ghost" disabled={disabled} onClick={() => onChange(rows.filter((_, i) => i !== idx))}>
            <Trash2 size={13} />
          </button>
        </div>
      ))}
      <button className="btn btn-sm btn-ghost" disabled={disabled} onClick={() => onChange([...rows, blank])}>
        <Plus size={13} /> Add
      </button>
    </div>
  )
}

function MapEditor({ field, value, onChange, disabled }) {
  const entries = Object.entries(value || {})
  const [k, setK] = useState('')
  const [v, setV] = useState('')

  return (
    <div className="space-y-2">
      {entries.map(([key, val]) => (
        <div key={key} className="flex gap-2 items-center">
          <span style={{ fontFamily: 'monospace', fontSize: 12, minWidth: 90 }}>{key}</span>
          <input className="input" style={{ maxWidth: 140 }} type="number" value={val} disabled={disabled}
            onChange={e => onChange({ ...value, [key]: Number(e.target.value) })} />
          <button className="btn btn-sm btn-ghost" disabled={disabled}
            onClick={() => { const next = { ...value }; delete next[key]; onChange(next) }}>
            <Trash2 size={13} />
          </button>
        </div>
      ))}
      <div className="flex gap-2">
        <input className="input" style={{ maxWidth: 120 }} placeholder=".css" value={k} onChange={e => setK(e.target.value)} disabled={disabled} />
        <input className="input" style={{ maxWidth: 140 }} type="number" placeholder="seconds" value={v} onChange={e => setV(e.target.value)} disabled={disabled} />
        <button className="btn btn-sm btn-ghost" disabled={disabled || !k.trim() || !v}
          onClick={() => { onChange({ ...value, [k.trim()]: Number(v) }); setK(''); setV('') }}>
          <Plus size={13} />
        </button>
      </div>
    </div>
  )
}

function Field({ field, value, onChange, disabled }) {
  if (field.type === 'bool') {
    return (
      <div className="flex items-start justify-between gap-4" style={{ padding: '9px 0' }}>
        <div style={{ flex: 1 }}><FieldLabel field={field} /></div>
        <Toggle on={!!value} onChange={onChange} disabled={disabled} />
      </div>
    )
  }

  return (
    <div style={{ padding: '9px 0' }}>
      <FieldLabel field={field} />
      {field.write_only ? (
        <input
          className="input" type="password" disabled={disabled}
          placeholder={value === '' && field.name.endsWith('_set') ? 'Set' : 'Leave blank to keep the current value'}
          value={typeof value === 'string' ? value : ''}
          onChange={e => onChange(e.target.value)}
        />
      ) : field.type === 'enum' ? (
        <select className="input" value={value ?? ''} disabled={disabled}
          onChange={e => onChange(typeof field.default === 'number' ? Number(e.target.value) : e.target.value)}>
          {field.values.map(v => <option key={String(v)} value={v}>{String(v) === '' ? '(none)' : String(v)}</option>)}
        </select>
      ) : field.type === 'int' ? (
        <input className="input" type="number" value={value ?? 0} disabled={disabled}
          min={field.min ?? undefined} max={field.max ?? undefined}
          onChange={e => onChange(Number(e.target.value))} />
      ) : field.type === 'text' ? (
        <textarea className="input" rows={field.name.includes('pem') ? 6 : 4} value={value ?? ''} disabled={disabled}
          style={{ fontFamily: 'monospace', fontSize: 11.5 }}
          onChange={e => onChange(e.target.value)} />
      ) : field.type === 'list' ? (
        <ListEditor field={field} value={value} onChange={onChange} disabled={disabled} />
      ) : field.type === 'records' ? (
        <RecordsEditor field={field} value={value} onChange={onChange} disabled={disabled} />
      ) : field.type === 'map' ? (
        <MapEditor field={field} value={value} onChange={onChange} disabled={disabled} />
      ) : (
        <input className="input" value={value ?? ''} disabled={disabled} onChange={e => onChange(e.target.value)} />
      )}
      {field.write_only && value === '' && (
        <p className="text-[11px] text-cat-sub mt-1">Stored securely and never sent back to the browser.</p>
      )}
    </div>
  )
}

function DiffView({ preview }) {
  if (!preview) return null
  if (!preview.changed) {
    return <p className="text-xs text-cat-sub" style={{ padding: '10px 0' }}>These values produce the same configuration — nothing would change.</p>
  }
  return (
    <div style={{ marginTop: 10 }}>
      <div className="text-xs text-cat-sub mb-1.5">
        <span style={{ color: '#4ade80' }}>+{preview.summary.added}</span>{' '}
        <span style={{ color: '#f87171' }}>−{preview.summary.removed}</span> lines in the generated Caddyfile
      </div>
      <div style={{ maxHeight: 320, overflow: 'auto', border: '1px solid var(--cat-border)', borderRadius: 8, background: 'var(--cat-bg)' }}>
        <pre style={{ margin: 0, padding: 10, fontSize: 11, lineHeight: 1.5, fontFamily: 'monospace' }}>
          {preview.hunks.flatMap(h => h.lines).map((line, i) => (
            <div key={i} style={{
              color: line.type === 'add' ? '#4ade80' : line.type === 'remove' ? '#f87171' : 'var(--cat-sub)',
              background: line.type === 'add' ? 'rgba(74,222,128,.07)' : line.type === 'remove' ? 'rgba(248,113,113,.07)' : 'transparent',
              whiteSpace: 'pre-wrap', wordBreak: 'break-all',
            }}>
              {line.type === 'add' ? '+' : line.type === 'remove' ? '-' : ' '}{line.text}
            </div>
          ))}
        </pre>
      </div>
      {preview.render_report?.newly_skipped?.length > 0 && (
        <div className="mt-2" style={{ padding: 9, borderRadius: 8, background: 'rgba(251,191,36,.08)', border: '1px solid rgba(251,191,36,.2)' }}>
          {preview.render_report.newly_skipped.map((s, i) => (
            <div key={i} className="text-[11px]" style={{ color: '#fbbf24', display: 'flex', gap: 6 }}>
              <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: 1 }} />
              <span><strong>{s.feature}</strong> would not take effect: {s.reason}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function SettingsForm({ group, onSaved, onError, extraFooter = null }) {
  const [schema, setSchema] = useState(null)
  const [values, setValues] = useState(null)
  const [draft, setDraft] = useState({})
  const [busy, setBusy] = useState(false)
  const [preview, setPreview] = useState(null)

  const load = async () => {
    const data = await api.get(`/settings/${group}`)
    setSchema(data.schema)
    setValues(data.values)
    setDraft({})
    setPreview(null)
  }

  useEffect(() => { load().catch(e => onError?.(e.message)) /* eslint-disable-next-line */ }, [group])

  const dirty = Object.keys(draft).length > 0
  const current = useMemo(() => ({ ...(values || {}), ...draft }), [values, draft])

  const setField = (name, v) => { setDraft(d => ({ ...d, [name]: v })); setPreview(null) }

  const doPreview = async () => {
    setBusy(true)
    try { setPreview(await api.post(`/settings/${group}/preview`, draft)) }
    catch (e) { onError?.(e.message) }
    finally { setBusy(false) }
  }

  const save = async () => {
    setBusy(true)
    try {
      const res = await api.patch(`/settings/${group}`, draft)
      setValues(res.values); setDraft({}); setPreview(null)
      onSaved?.(res)
    } catch (e) { onError?.(e.message) }
    finally { setBusy(false) }
  }

  const reset = async () => {
    setBusy(true)
    try {
      const res = await api.post(`/settings/${group}/reset`, {})
      setValues(res.values); setDraft({}); setPreview(null)
      onSaved?.(res)
    } catch (e) { onError?.(e.message) }
    finally { setBusy(false) }
  }

  if (!schema || !values) {
    return <div className="card" style={{ display: 'flex', justifyContent: 'center', padding: 32 }}><Spinner label={`Loading ${group}`} /></div>
  }

  return (
    <div className="card">
      <div style={{ marginBottom: 4 }}>
        <div className="section-title" style={{ marginBottom: 2 }}>{schema.label}</div>
        <p className="text-xs text-cat-sub">{schema.summary}</p>
        {schema.idea?.length > 0 && (
          <p className="text-[10.5px] text-cat-sub" style={{ opacity: 0.65, marginTop: 3 }}>
            <Info size={10} style={{ display: 'inline', verticalAlign: -1, marginRight: 3 }} />
            Design brief {schema.idea.map(n => `#${n}`).join(', ')}
          </p>
        )}
      </div>

      <div style={{ borderTop: '1px solid var(--cat-border)', marginTop: 12 }}>
        {schema.fields.filter(f => !f.name.endsWith('_set')).map(field => (
          <Field
            key={field.name}
            field={field}
            value={current[field.name]}
            onChange={v => setField(field.name, v)}
            disabled={busy}
          />
        ))}
      </div>

      <DiffView preview={preview} />

      <div style={{ display: 'flex', gap: 8, marginTop: 14, paddingTop: 12, borderTop: '1px solid var(--cat-border)', flexWrap: 'wrap' }}>
        <button className="btn btn-primary btn-sm" onClick={save} disabled={!dirty || busy}>
          <Save size={13} /> Apply
        </button>
        <button className="btn btn-ghost btn-sm" onClick={doPreview} disabled={!dirty || busy}>
          <Eye size={13} /> Preview change
        </button>
        <button className="btn btn-ghost btn-sm" onClick={() => { setDraft({}); setPreview(null) }} disabled={!dirty || busy}>
          Discard
        </button>
        <button className="btn btn-ghost btn-sm" style={{ marginLeft: 'auto' }} onClick={reset} disabled={busy}>
          <RotateCcw size={13} /> Reset to defaults
        </button>
      </div>
      {extraFooter}
    </div>
  )
}
