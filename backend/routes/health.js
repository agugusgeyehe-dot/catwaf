
const express = require('express')
const fs = require('fs')
const router = express.Router()
const state = require('../services/state')
const auditSvc = require('../services/audit')
const db = require('../services/db')
const caddySvc = require('../services/caddy')
const lintSvc = require('../services/lint')
const { version: pkgVersion } = require('../../package.json')


router.get('/api/diagnostics', async (req, res) => {
  const checks = {}

  checks.caddy = caddySvc.isCaddyRunning()
    ? { ok: true, detail: 'running' }
    : { ok: false, detail: 'not running' }

  {
    const out = caddySvc.getCaddyModules()
    const hasWaf = out.includes('http.handlers.waf')
    checks.coraza = { ok: hasWaf, detail: hasWaf ? 'http.handlers.waf loaded' : (out ? 'Coraza module not found in this Caddy build' : 'Could not run "caddy list-modules" (locally or in the Caddy container)') }
  }

  try {
    const content = fs.readFileSync(caddySvc.CADDYFILE_PATH, 'utf8')
    checks.crs = { ok: content.includes('load_owasp_crs') || content.includes('owasp_crs'), detail: content.includes('load_owasp_crs') ? 'OWASP CRS directives present' : 'CRS not referenced in Caddyfile' }
    checks.caddyfile_valid = { ok: (content.match(/{/g) || []).length === (content.match(/}/g) || []).length, detail: 'brace balance check' }
  } catch (e) {
    checks.crs = { ok: false, detail: e.message }
    checks.caddyfile_valid = { ok: false, detail: e.message }
  }

  checks.cloudflare = {
    ok: (() => { try { return fs.readFileSync(caddySvc.CADDYFILE_PATH, 'utf8').includes('@@CATWAF_CF_LOCK_START@@') } catch { return false } })(),
    detail: 'origin firewall rule presence (does not verify live API connection)',
  }

  checks.tls = { ok: null, detail: 'Provide a domain via the Origin Scanner to check TLS' }

  {
    const major = parseInt(process.version.slice(1).split('.')[0], 10)
    checks.node = { ok: major >= 22, detail: `${process.version} (requires 22+)` }
  }

  try { db.getDb().prepare('SELECT 1').get(); checks.database = { ok: true, detail: `${db.DB_PATH}` } }
  catch (e) { checks.database = { ok: false, detail: e.message } }

  const allOk = Object.values(checks).filter(c => c.ok !== null).every(c => c.ok)
  res.json({
    overall: allOk ? 'healthy' : 'issues found',
    checks,
    checked_at: auditSvc.now(),
    catwaf_version: pkgVersion,
    edition: 'free',
    node_version: process.version,
  })
})

router.get('/api/diagnostics/export', (req, res) => {
  const lint = (() => { try { return lintSvc.lintConfig() } catch { return null } })()
  res.json({
    generated_at: auditSvc.now(),
    catwaf_version: pkgVersion,
    edition: 'free',
    node_version: process.version,
    waf_state: state.WAF,
    rule_categories: state.RULE_CATEGORIES,
    lint_result: lint,
    recent_audit: auditSvc.getAuditLogs(50),
  })
})

module.exports = router
