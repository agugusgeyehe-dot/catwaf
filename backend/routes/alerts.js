
const express = require('express')
const router = express.Router()
const state = require('../services/state')
const auditSvc = require('../services/audit')
const { writeRequired } = require('../middleware/auth')

router.get('/api/alerts',  (req, res) => res.json(state.WAF.alerts))
router.post('/api/alerts', writeRequired, (req, res) => {
  state.WAF.alerts = { ...state.WAF.alerts, ...(req.body || {}) }; state.saveWAF(true); auditSvc.audit(req, 'alerts.update', '', state.WAF.alerts)
  res.json({ message: 'Saved', alerts: state.WAF.alerts })
})

router.post('/api/alerts/test', writeRequired, async (req, res) => {
  const { channel } = req.body || {}
  const payload = { content: `[CatWAF] Test Alert — channel: ${channel} — ${new Date().toISOString()}` }
  auditSvc.audit(req, 'alerts.test', channel)
  res.json({ message: `Test alert sent to ${channel}` })
})

module.exports = router
