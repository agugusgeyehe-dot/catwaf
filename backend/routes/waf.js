
const express = require('express')
const router = express.Router()
const state = require('../services/state')
const auditSvc = require('../services/audit')
const caddySvc = require('../services/caddy')
const { writeRequired } = require('../middleware/auth')
const { isValidMethodList, isValidUserAgentList } = require('../services/sanitize')

router.get('/api/waf/engine', (req, res) => res.json({ mode: state.WAF.engine }))
router.post('/api/waf/engine', writeRequired, (req, res) => {
  const { mode } = req.body || {}
  if (!['On','DetectionOnly','Off'].includes(mode)) return res.status(400).json({ detail: 'Invalid mode' })
  state.WAF.engine = mode; state.saveWAF(true)
  const caddy = caddySvc.applyToCaddy('engine.set', req)
  res.json({ mode, message: `Engine set to ${mode}`, caddy_reloaded: caddy.reloaded, caddy_error: caddy.error })
})

router.get('/api/waf/paranoia', (req, res) => {
  const pl = state.WAF.paranoia_level
  const desc = {1:'Balanced. Minimal false positives.',2:'Increased detection.',3:'Strict. Needs tuning.',4:'Maximum strictness.'}
  const rc   = {1:185,2:243,3:318,4:369}
  res.json({ blocking_paranoia_level: pl, executing_paranoia_level: state.WAF.executing_paranoia_level, description: desc[pl] || '', active_rules: rc[pl] || 185, false_positive_risk: ['Low','Medium','High','Very High'][pl-1] })
})
router.post('/api/waf/paranoia', writeRequired, (req, res) => {
  const { level, executing_level } = req.body || {}
  if (![1,2,3,4].includes(level)) return res.status(400).json({ detail: 'PL must be 1-4' })
  if (executing_level != null) {
    if (![1,2,3,4].includes(executing_level)) return res.status(400).json({ detail: 'Executing PL must be 1-4' })
    if (executing_level < level) return res.status(400).json({ detail: 'Executing PL must be >= blocking PL' })
  }
  state.WAF.paranoia_level = level
  if (executing_level != null) state.WAF.executing_paranoia_level = executing_level
  state.saveWAF(true)
  const caddy = caddySvc.applyToCaddy('paranoia.set', req)
  res.json({ blocking_paranoia_level: level, executing_paranoia_level: state.WAF.executing_paranoia_level, message: `PL${level}`, caddy_reloaded: caddy.reloaded, caddy_error: caddy.error })
})

router.get('/api/waf/anomaly', (req, res) => res.json({ inbound_threshold: state.WAF.inbound_anomaly_threshold, outbound_threshold: state.WAF.outbound_anomaly_threshold, scoring_breakdown: { critical: 5, error: 4, warning: 3, notice: 2 }, note: 'Requests scoring >= inbound threshold are blocked.' }))
const MAX_ANOMALY_THRESHOLD = 1000
const isThreshold = v => Number.isInteger(v) && v >= 1 && v <= MAX_ANOMALY_THRESHOLD

router.post('/api/waf/anomaly', writeRequired, (req, res) => {
  const { inbound, outbound } = req.body || {}
  if (!isThreshold(inbound) || !isThreshold(outbound)) {
    return res.status(400).json({ detail: `Thresholds must be whole numbers between 1 and ${MAX_ANOMALY_THRESHOLD}` })
  }
  state.WAF.inbound_anomaly_threshold = inbound; state.WAF.outbound_anomaly_threshold = outbound
  state.saveWAF(true)
  const caddy = caddySvc.applyToCaddy('anomaly.set', req)
  res.json({ inbound, outbound, message: 'Thresholds updated', caddy_reloaded: caddy.reloaded })
})


const SETTING_KEYS = ['allowed_methods','allowed_content_types','max_request_body_size','max_file_upload_size','request_body_inspection','response_body_inspection','audit_log','enforce_bodyproc_urlencoded','early_blocking','sampling_percentage','blocked_user_agents','header_rules']

const MIME_TYPE_RE = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$/

function validateSetting(key, value) {
  switch (key) {
    case 'allowed_methods':
      return isValidMethodList(value) ? null : 'allowed_methods must be a non-empty array of valid HTTP methods'
    case 'blocked_user_agents':
      return isValidUserAgentList(value) ? null : 'blocked_user_agents must be an array of strings (max 200 entries, 128 chars each)'
    case 'allowed_content_types':
      return (Array.isArray(value) && value.every(v => typeof v === 'string' && v.length <= 128 && MIME_TYPE_RE.test(v)))
        ? null : 'allowed_content_types must be an array of MIME type strings (e.g. application/json)'
    case 'max_request_body_size':
    case 'max_file_upload_size':
      return (Number.isFinite(value) && value > 0) ? null : `${key} must be a positive number`
    case 'sampling_percentage':
      return (Number.isFinite(value) && value >= 0 && value <= 100) ? null : 'sampling_percentage must be 0-100'
    case 'request_body_inspection':
    case 'response_body_inspection':
    case 'audit_log':
    case 'enforce_bodyproc_urlencoded':
    case 'early_blocking':
      return (typeof value === 'boolean') ? null : `${key} must be a boolean`
    case 'header_rules':
      return Array.isArray(value) ? null : 'header_rules must be an array'
    default:
      return null
  }
}

function applySettingsUpdate(req, res, { reloadCaddy }) {
  const body = req.body || {}
  const rejectedKeys = Object.keys(body).filter(k => !SETTING_KEYS.includes(k))
  if (rejectedKeys.length > 0) {
    return res.status(400).json({ detail: `Unknown or unsettable key(s): ${rejectedKeys.join(', ')}` })
  }
  for (const [k, v] of Object.entries(body)) {
    const err = validateSetting(k, v)
    if (err) return res.status(400).json({ detail: err })
  }
  for (const [k, v] of Object.entries(body)) state.WAF[k] = v
  state.saveWAF(true); auditSvc.audit(req, 'settings.update', '', body)
  const o = {}; for (const k of SETTING_KEYS) o[k] = state.WAF[k]
  if (reloadCaddy) caddySvc.applyToCaddy('settings.post', req)
  res.json({ message: 'Updated', settings: o })
}

router.get('/api/waf/settings', (req, res) => { const o = {}; for (const k of SETTING_KEYS) o[k] = state.WAF[k]; res.json(o) })
router.patch('/api/waf/settings', writeRequired, (req, res) => applySettingsUpdate(req, res, { reloadCaddy: false }))

router.post('/api/waf/settings', writeRequired, (req, res) => applySettingsUpdate(req, res, { reloadCaddy: true }))

const PERFORMANCE_PRESETS = {
  fast: {
    label: 'Fast', paranoia_level: 1, executing_paranoia_level: 1,
    inbound_anomaly_threshold: 10, outbound_anomaly_threshold: 8,
    request_body_inspection: true, response_body_inspection: false,
    audit_log: false, early_blocking: true, sampling_percentage: 50,
  },
  balanced: {
    label: 'Balanced', paranoia_level: 1, executing_paranoia_level: 2,
    inbound_anomaly_threshold: 5, outbound_anomaly_threshold: 4,
    request_body_inspection: true, response_body_inspection: false,
    audit_log: true, early_blocking: true, sampling_percentage: 100,
  },
  maximum: {
    label: 'Maximum Security', paranoia_level: 3, executing_paranoia_level: 4,
    inbound_anomaly_threshold: 3, outbound_anomaly_threshold: 3,
    request_body_inspection: true, response_body_inspection: true,
    audit_log: true, early_blocking: true, sampling_percentage: 100,
  },
}

router.get('/api/performance-mode', (req, res) => {
  const current = {
    paranoia_level: state.WAF.paranoia_level, inbound_anomaly_threshold: state.WAF.inbound_anomaly_threshold,
  }
  let closest = 'custom'
  for (const [key, preset] of Object.entries(PERFORMANCE_PRESETS)) {
    if (preset.paranoia_level === current.paranoia_level && preset.inbound_anomaly_threshold === current.inbound_anomaly_threshold) closest = key
  }
  res.json({ current_mode: closest, presets: PERFORMANCE_PRESETS })
})

router.post('/api/performance-mode', writeRequired, (req, res) => {
  const { mode } = req.body || {}
  if (typeof mode !== 'string' || !Object.hasOwn(PERFORMANCE_PRESETS, mode)) {
    return res.status(400).json({ detail: 'Unknown mode. Use: fast, balanced, maximum' })
  }
  const preset = PERFORMANCE_PRESETS[mode]
  const { label, ...settings } = preset
  Object.assign(state.WAF, settings)
  state.saveWAF(true)
  auditSvc.audit(req, 'performance-mode.apply', mode)
  res.json({ message: `Applied ${label} mode`, applied: settings })
})

module.exports = router
