
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

// The Caddyfile body is admin-only and redacted even then. It carries the
// derived X-CatWAF-Enforce-Key, the ACME dns-01 API token and the basic-auth
// hash as plaintext literals, and those fields are writeOnly everywhere else
// in the API — a read-only viewer must not be able to read here what
// settings redact() withholds from them on every other route.
router.get('/api/caddy/status', (req, res) => {
  const isAdmin = req.user && req.user.role === 'admin'
  let caddyfile = ''
  if (isAdmin) {
    try { caddyfile = caddySvc.redactCaddyfile(require('fs').readFileSync(caddySvc.CADDYFILE_PATH, 'utf8')) } catch {}
  }
  res.json({
    running: caddySvc.isCaddyRunning(),
    // Server filesystem layout is an admin concern; viewers get the state
    // without the path.
    caddyfile_path: isAdmin ? caddySvc.CADDYFILE_PATH : null,
    caddyfile,
    caddyfile_redacted: isAdmin,
    caddyfile_visible: isAdmin,
  })
})

router.get('/api/caddy/reload-queue/status', (req, res) => {
  res.json({ pending: caddySvc.isReloadPending(), debounce_ms: 800 })
})

module.exports = router
