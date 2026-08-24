
const express = require('express')
const fs = require('fs')
const path = require('path')
const router = express.Router()
const auditSvc = require('../services/audit')
const sensitiveSvc = require('../services/sensitive')
const { writeRequired } = require('../middleware/auth')
const { isValidCaddyPath } = require('../services/sanitize')

router.get('/api/sensitive/state', (req, res) => res.json(sensitiveSvc.getSensitiveState()))

// What each level is, measured from the wordlists rather than described.
router.get('/api/sensitive/levels', (req, res) => res.json(sensitiveSvc.describeLevels()))

router.get('/api/sensitive/blocked', (req, res) => res.json({ blocked: sensitiveSvc.getSensitiveState().blocked }))

router.post('/api/sensitive/level', writeRequired, (req, res) => {
  const { level } = req.body || {}
  if (![0,1,2,3,4].includes(level)) return res.status(400).json({ detail: 'Level must be 0-4' })
  const s = sensitiveSvc.getSensitiveState()
  s.sfl_level = level
  sensitiveSvc.saveSensitiveState(s)
  const caddy = sensitiveSvc.applyToCoraza(s, 'sensitive.level', req)
  res.json({
    message: level === 0 ? 'SFL disabled — rules removed from Caddyfile' : `SFL${level} applied to Caddyfile`,
    sfl_level: level,
    caddy_reloaded: caddy.reloaded,
    caddy_error: caddy.error,
  })
})

router.post('/api/sensitive/block', writeRequired, (req, res) => {
  const { path: p } = req.body || {}
  if (!p) return res.status(400).json({ detail: 'path required' })
  if (!isValidCaddyPath(p)) return res.status(400).json({ detail: 'path must start with / and contain no whitespace, quotes, backticks, or braces' })
  const s = sensitiveSvc.getSensitiveState()
  if (!s.blocked.includes(p)) s.blocked.push(p)
  sensitiveSvc.saveSensitiveState(s)
  const caddy = sensitiveSvc.applyToCoraza(s, 'sensitive.block', req)
  res.json({ message: `${p} blocked`, path: p, caddy_reloaded: caddy.reloaded, caddy_error: caddy.error })
})

router.delete('/api/sensitive/block/:path', writeRequired, (req, res) => {
  const p = decodeURIComponent(req.params.path)
  const s = sensitiveSvc.getSensitiveState()
  s.blocked = s.blocked.filter(b => b !== p)
  sensitiveSvc.saveSensitiveState(s)
  const caddy = sensitiveSvc.applyToCoraza(s, 'sensitive.unblock', req)
  res.json({ message: `${p} unblocked`, path: p, caddy_reloaded: caddy.reloaded, caddy_error: caddy.error })
})

router.get('/api/sensitive/scan', (req, res) => {
  const WEBROOT = process.env.WEBROOT_PATH || null

  if (!WEBROOT) {
    return res.json({
      files: [], scanned_at: auditSvc.now(), configured: false,
      detail: 'WEBROOT_PATH is not set, so there is no webroot to scan. Set it to your site\'s public directory (e.g. /var/www/html) in .env and restart CatWAF.',
    })
  }
  if (!fs.existsSync(WEBROOT)) {
    return res.json({
      files: [], scanned_at: auditSvc.now(), configured: false,
      detail: `WEBROOT_PATH is set to "${WEBROOT}", but that directory does not exist on this server. Correct it in .env and restart CatWAF.`,
    })
  }

  {
    const results = []
    const risky = { php: 'high', config: 'critical', backup: 'critical', html: 'low' }
    // The walk is synchronous — every directory level blocks the event loop
    // that serves the WAF control plane — so it runs with hard bounds rather
    // than trusting the webroot to be small. Symlinks are never followed
    // (readdirSync dirent.isDirectory() is false for them), which also keeps
    // a symlink farm from turning into an unbounded walk.
    const MAX_DEPTH = 12
    const MAX_RESULTS = 5000

    function walk(dir, base = '', depth = 0) {
      if (depth > MAX_DEPTH || results.length >= MAX_RESULTS) return
      let entries
      try { entries = fs.readdirSync(dir, { withFileTypes: true }) } catch { return }
      for (const e of entries) {
        if (results.length >= MAX_RESULTS) return
        const rel  = base + '/' + e.name
        const full = path.join(dir, e.name)
        if (e.isDirectory()) { walk(full, rel, depth + 1); continue }
        const ext = path.extname(e.name).toLowerCase()
        let cat = 'other', risk = 'low'
        if (['.php', '.php3', '.php4', '.php5', '.phtml'].includes(ext)) cat = 'php'
        else if (['.env', '.htaccess', '.htpasswd', '.conf', '.config', '.ini', '.xml', '.json'].includes(ext)) cat = 'config'
        else if (['.zip', '.tar', '.gz', '.bak', '.sql', '.dump', '.old', '.backup'].includes(ext)) cat = 'backup'
        else if (['.html', '.htm'].includes(ext)) cat = 'html'
        risk = risky[cat] || 'low'
        const dangerous = ['shell','backdoor','c99','r57','b374k','phpinfo','adminer','phpmyadmin','webshell']
        if (dangerous.some(d => e.name.toLowerCase().includes(d))) risk = 'critical'
        let size = '?'
        try { const stat = fs.statSync(full); size = stat.size < 1024 ? stat.size + ' B' : (stat.size/1024).toFixed(1) + ' KB' } catch {}
        results.push({ path: rel, cat, size, risk })
      }
    }
    walk(WEBROOT)
    auditSvc.audit(req, 'sensitive.scan', `${results.length} files found`)
    return res.json({
      files: results,
      scanned_at: auditSvc.now(),
      configured: true,
      truncated: results.length >= MAX_RESULTS,
    })
  }
})

module.exports = router
