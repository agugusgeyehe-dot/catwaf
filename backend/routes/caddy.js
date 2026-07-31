
const express = require('express')
const router = express.Router()
const auditSvc = require('../services/audit')
const caddySvc = require('../services/caddy')
const { writeRequired } = require('../middleware/auth')

router.post('/api/caddy/reload', writeRequired, (req, res) => {
  const result = caddySvc.reloadCaddy()
  if (result.reloaded) auditSvc.audit(req, 'caddy.reload', caddySvc.CADDYFILE_PATH)
  res.status(result.reloaded ? 200 : 500).json({ reloaded: result.reloaded, error: result.error })
})

router.get('/api/caddy/status', (req, res) => {
  let caddyfile = ''
  try { caddyfile = require('fs').readFileSync(caddySvc.CADDYFILE_PATH, 'utf8') } catch {}
  res.json({ running: caddySvc.isCaddyRunning(), caddyfile_path: caddySvc.CADDYFILE_PATH, caddyfile })
})

router.get('/api/caddy/reload-queue/status', (req, res) => {
  res.json({ pending: caddySvc.isReloadPending(), debounce_ms: 800 })
})

module.exports = router
