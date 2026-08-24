
import { useState } from 'react'
import { Check, Undo2, AlertTriangle, X } from 'lucide-react'
import { api } from '../../utils/api.js'

export function ActionCard({ action, onResolved }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState(action.kind === 'applied' ? { undoId: action.undoId } : null)
  const [undone, setUndone] = useState(false)
  const [dismissed, setDismissed] = useState(false)
  const [inputValue, setInputValue] = useState('')

  if (dismissed) return null

  async function confirm() {
    setBusy(true); setError('')
    try {
      // Clicking Apply is the explicit human confirmation; weakening
      // actions require it server-side as well.
      const res = await api.post('/catai/apply', { actionId: action.actionId, params: action.params, confirm_weaken: true })
      setDone({ undoId: res.undoId })
      onResolved?.()
    } catch (e) {
      setError(e.message)
    }
    setBusy(false)
  }

  async function undo(undoId) {
    setBusy(true); setError('')
    try {
      await api.post('/catai/undo', { undoId })
      setUndone(true)
      onResolved?.()
    } catch (e) {
      setError(e.message)
    }
    setBusy(false)
  }

  async function submitMissing() {
    if (!inputValue.trim()) return
    setBusy(true); setError('')
    try {
      const params = { ...action.params, [missingParamKey(action.missing)]: inputValue.trim() }
      const res = await api.post('/catai/apply', { actionId: action.actionId, params, confirm_weaken: true })
      setDone({ undoId: res.undoId })
      onResolved?.()
    } catch (e) {
      setError(e.message)
    }
    setBusy(false)
  }

  if (action.kind === 'error') {
    return (
      <div className="catai-card catai-card-error">
        <AlertTriangle size={14} />
        <span>{action.error}</span>
      </div>
    )
  }

  if (action.kind === 'incomplete') {
    return (
      <div className="catai-card catai-card-incomplete">
        <div className="catai-card-row">
          <AlertTriangle size={14} />
          <span>I need one more detail: {missingParamLabel(action.missing)}</span>
        </div>
        {!done && (
          <div className="catai-card-row">
            <input
              className="input catai-card-input"
              placeholder={missingParamLabel(action.missing)}
              value={inputValue}
              onChange={e => setInputValue(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && submitMissing()}
              disabled={busy}
            />
            <button className="btn btn-primary btn-sm" onClick={submitMissing} disabled={busy || !inputValue.trim()}>Apply</button>
          </div>
        )}
        {done && <div className="catai-card-row catai-card-done"><Check size={13} /> Done{done.undoId && !undone && (
          <button className="catai-card-undo" onClick={() => undo(done.undoId)} disabled={busy}><Undo2 size={11} /> Undo</button>
        )}</div>}
        {undone && <div className="catai-card-row catai-card-undone">Reverted.</div>}
        {error && <div className="catai-card-row catai-card-error-text">{error}</div>}
      </div>
    )
  }

  if (action.kind === 'offer') {
    if (done) {
      return (
        <div className="catai-card catai-card-done">
          <Check size={14} /><span>{action.label}</span>
          {!undone && done.undoId && <button className="catai-card-undo" onClick={() => undo(done.undoId)} disabled={busy}><Undo2 size={11} /> Undo</button>}
          {undone && <span className="catai-card-undone">Reverted</span>}
        </div>
      )
    }
    return (
      <div className="catai-card catai-card-offer">
        <div className="catai-card-row"><span className="catai-card-label">{action.label}</span></div>
        {action.warn && <div className="catai-card-warn"><AlertTriangle size={12} /> {action.warn}</div>}
        <div className="catai-card-actions">
          <button className="btn btn-ghost btn-sm" onClick={() => setDismissed(true)} disabled={busy}><X size={12} /> Cancel</button>
          <button className="btn btn-primary btn-sm" onClick={confirm} disabled={busy}>{busy ? 'Applying…' : 'Apply'}</button>
        </div>
        {error && <div className="catai-card-row catai-card-error-text">{error}</div>}
      </div>
    )
  }

  return (
    <div className="catai-card catai-card-done">
      <Check size={14} /><span>{action.message}</span>
      {!undone && done?.undoId && <button className="catai-card-undo" onClick={() => undo(done.undoId)} disabled={busy}><Undo2 size={11} /> Undo</button>}
      {undone && <span className="catai-card-undone">Reverted</span>}
      {error && <div className="catai-card-row catai-card-error-text">{error}</div>}
    </div>
  )
}

function missingParamKey(missing) {
  return { ip: 'ip', country: 'cc', level: 'level' }[missing] || missing
}
function missingParamLabel(missing) {
  return { ip: 'an IP address or CIDR, e.g. 203.0.113.9', country: 'a two-letter country code, e.g. CN, RU, BR', level: 'a paranoia level (1-4)' }[missing] || missing
}
