const express = require('express')
const router = express.Router()

const { authRequired, writeRequired } = require('../middleware/auth')
const auditSvc = require('../services/audit')
const rulesSvc = require('../services/rules')
const eventsSvc = require('../services/events')
const modesSvc = require('../services/modes')
const snapshotsSvc = require('../services/snapshots')
const healthcheckSvc = require('../services/healthcheck')
const securityTestSvc = require('../services/securityTest')
const simulateSvc = require('../services/simulate')
const requestLog = require('../services/requestLog')
const configTx = require('../services/configTx')
const state = require('../services/state')

function bad(res, detail, code = 400) { return res.status(code).json({ detail }) }

router.get('/api/events/:id/explain', authRequired, (req, res) => {
  const result = eventsSvc.explain({ id: req.params.id })
  if (!result.ok) return bad(res, result.detail || result.error, 404)
  res.json(result)
})

router.get('/api/events/latest/explain', authRequired, (req, res) => {
  const result = eventsSvc.explain({ last: true })
  if (!result.ok) return bad(res, result.error, 404)
  res.json(result)
})

router.post('/api/events/:id/replay', authRequired, writeRequired, async (req, res) => {
  const result = await eventsSvc.replay({ id: req.params.id })
  if (!result.ok) return bad(res, result.error, result.unavailable ? 503 : 400)
  auditSvc.audit(req, 'event.replay', req.params.id, { verdict: result.verdict })
  res.json(result)
})

router.get('/api/logs', authRequired, (req, res) => {
  const sinceMs = requestLog.parseWindow(req.query.last || '24h')
  if (sinceMs == null) return bad(res, 'Invalid window. Use forms like 30m, 24h, 7d.')
  const attackType = typeof req.query.attack === 'string' ? req.query.attack : null
  const severity = typeof req.query.severity === 'string' ? req.query.severity.toLowerCase() : null
  const action = req.query.action === 'block' || req.query.action === 'pass' ? req.query.action : null
  const limit = Math.min(Number(req.query.limit) || 50, 500)
  const offset = Math.max(Number(req.query.offset) || 0, 0)
  const search = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : ''

  let rows = requestLog.query({ sinceMs, attackType, severity, action, limit: search ? 2000 : limit, offset: search ? 0 : offset })
  if (search) {
    rows = rows.filter(r =>
      (r.ip || '').toLowerCase().includes(search) ||
      (r.uri || '').toLowerCase().includes(search) ||
      (r.country_code || '').toLowerCase().includes(search)
    ).slice(offset, offset + limit)
  }

  res.json({
    window_ms: sinceMs,
    logs: rows.map(r => ({
      id: r.id, timestamp: r.ts, ip: r.ip, method: r.method, uri: r.uri, status: r.status,
      action: r.action, attack_type: r.attack_type, severity: r.severity, anomaly_score: r.score,
      country_code: r.country_code, city: r.city, rule_ids: r.rule_ids,
    })),
  })
})

router.get('/api/audit/summary', authRequired, (req, res) => {
  const sinceMs = requestLog.parseWindow(req.query.last || '24h')
  if (sinceMs == null) return bad(res, 'Invalid window. Use forms like 30m, 24h, 7d.')
  const attackType = typeof req.query.attack === 'string' ? req.query.attack : null
  const severity = typeof req.query.severity === 'string' ? req.query.severity.toLowerCase() : null
  const limit = Math.min(Number(req.query.limit) || 10, 200)

  const summary = requestLog.summarize({ sinceMs, attackType, severity })
  const recent = requestLog.query({ sinceMs, attackType, severity, action: 'block', limit })
  res.json({
    ...summary,
    filters: { window: req.query.last || '24h', attack_type: attackType, severity },
    recent_attacks: recent.map(r => ({
      id: r.id, timestamp: r.ts, method: r.method, uri: r.uri,
      attack_type: r.attack_type, severity: r.severity, anomaly_score: r.score,
      rule_ids: r.rule_ids, client_ip: r.ip, status: r.status,
      country_code: r.country_code, city: r.city, lat: r.lat, lon: r.lon,
    })),
  })
})

router.post('/api/simulate', authRequired, writeRequired, async (req, res) => {
  const { url, request } = req.body || {}
  if (url != null && typeof url !== 'string') return bad(res, 'url must be a string.')
  if (request != null && typeof request !== 'string') return bad(res, 'request must be a raw HTTP request string.')
  if (!url && !request) return bad(res, 'Provide "url" or "request".')

  const result = await simulateSvc.simulate({ url: url || null, requestText: request != null ? request : null })
  if (!result.ok) return bad(res, result.error, result.unavailable ? 503 : 400)
  auditSvc.audit(req, 'waf.simulate', '', { blocked: result.blocked })
  res.json(result)
})

router.get('/api/rules', authRequired, (req, res) => {
  const enabled = req.query.enabled === 'true' ? true : req.query.enabled === 'false' ? false : null
  res.json(rulesSvc.list({
    category: typeof req.query.category === 'string' ? req.query.category : null,
    enabled,
    limit: Math.min(Number(req.query.limit) || 200, 1000),
    offset: Math.max(Number(req.query.offset) || 0, 0),
  }))
})

router.get('/api/rules/search', authRequired, (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q : ''
  if (!q.trim()) return bad(res, 'Query parameter "q" is required.')
  res.json(rulesSvc.search(q, { limit: Math.min(Number(req.query.limit) || 50, 200) }))
})

router.get('/api/rules/stats', authRequired, (req, res) => res.json(rulesSvc.stats()))

router.get('/api/rules/:id', authRequired, (req, res) => {
  if (!rulesSvc.isValidRuleId(req.params.id)) return bad(res, 'Rule ID must be 3-7 digits.')
  res.json(rulesSvc.describe(req.params.id))
})

router.post('/api/rules/:id/:action(enable|disable)', authRequired, writeRequired, (req, res) => {
  const { id, action } = req.params
  if (!rulesSvc.isValidRuleId(id)) return bad(res, 'Rule ID must be 3-7 digits.')
  const wantEnabled = action === 'enable'

  const tx = configTx.apply({
    label: `rules.${action}.${id}`,
    req,
    mutate: () => {
      const r = rulesSvc.setRuleEnabled(id, wantEnabled)
      if (!r.changed) throw new Error(r.reason)
      return r
    },
  })

  if (!tx.ok) return res.status(tx.phase === 'mutate' ? 400 : 500).json({ detail: tx.error, rolled_back: !!tx.rolledBack, phase: tx.phase })
  res.json({ ok: true, rule: rulesSvc.describe(id), reloaded: tx.reloaded })
})

router.get('/api/mode', authRequired, (req, res) => {
  res.json({ current: modesSvc.current(), available: modesSvc.listModes() })
})

router.post('/api/mode', authRequired, writeRequired, (req, res) => {
  const { mode } = req.body || {}
  if (!modesSvc.isValidMode(mode)) {
    return bad(res, `Unknown mode. Valid: ${modesSvc.listModes().map(m => m.id).join(', ')}.`)
  }
  const result = modesSvc.setMode(mode, { req })
  if (!result.ok) return res.status(500).json({ detail: result.error, rolled_back: !!result.rolledBack })
  res.json(result)
})

router.get('/api/config/snapshots', authRequired, (req, res) => {
  res.json({ snapshots: snapshotsSvc.list() })
})

router.post('/api/config/snapshots', authRequired, writeRequired, (req, res) => {
  const label = typeof req.body?.label === 'string' ? req.body.label : 'manual'
  const r = snapshotsSvc.create({ req, label })
  auditSvc.audit(req, 'config.snapshot', r.id, { label: r.label })
  res.status(201).json(r)
})

router.get('/api/config/snapshots/:id', authRequired, (req, res) => {
  const r = snapshotsSvc.view(req.params.id)
  if (!r.ok) return bad(res, r.error, 404)
  res.json(r)
})

router.get('/api/config/snapshots/:id/diff', authRequired, (req, res) => {
  const against = typeof req.query.against === 'string' ? req.query.against : null
  const r = snapshotsSvc.diff(req.params.id, { against })
  if (!r.ok) return bad(res, r.error, 404)
  res.json(r)
})

router.post('/api/config/snapshots/:id/restore', authRequired, writeRequired, (req, res) => {
  const r = snapshotsSvc.restore(req.params.id, { req })
  if (!r.ok) return res.status(r.error && /No snapshot/.test(r.error) ? 404 : 500).json({ detail: r.error, rolled_back: !!r.rolledBack })
  res.json(r)
})

router.get('/api/waf/health', authRequired, async (req, res) => {
  const r = await healthcheckSvc.run()
  res.status(r.status === 'unhealthy' ? 503 : 200).json(r)
})

router.get('/api/waf/security-test', authRequired, writeRequired, async (req, res) => {
  const r = await securityTestSvc.run()
  res.json(r)
})

router.get('/api/waf/paranoia-levels', authRequired, (req, res) => {
  res.json({
    current: state.WAF.paranoia_level,
    detection: state.WAF.executing_paranoia_level,
    levels: [
      { level: 1, name: 'Balanced', description: 'Blocks clear attacks with very few false positives.' },
      { level: 2, name: 'Elevated', description: 'Adds patterns that are usually malicious but occasionally legitimate.' },
      { level: 3, name: 'Aggressive', description: 'Adds aggressive heuristics. Expect to tune exclusions.' },
      { level: 4, name: 'Maximum', description: 'Blocks nearly anything unusual. Assume you will write exceptions.' },
    ],
  })
})

module.exports = router
