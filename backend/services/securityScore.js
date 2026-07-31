
const state = require('./state')
const cloudflareSvc = require('./cloudflare')
const db = require('./db')
const { needsBootstrap } = require('../middleware/auth')

const STATUS_CREDIT = { pass: 1, warn: 0.5, fail: 0, unknown: null }

function hasHeaderRule(name) {
  const rules = state.WAF.header_rules || []
  return rules.some(h => (h?.name || '').toLowerCase() === name.toLowerCase())
}

async function computeChecks() {
  const checks = []

  const cfConnected = !!cloudflareSvc.CF_STORE.token
  checks.push({
    id: 'cloudflare_connected', category: 'Perimeter', weight: 2,
    status: cfConnected ? 'pass' : 'warn',
    label: 'Cloudflare connected',
    detail: cfConnected ? 'Origin traffic is proxied through Cloudflare.' : 'No Cloudflare connection configured — origin IP may be directly reachable.',
    recommendation: cfConnected ? null : 'Connect Cloudflare from the Cloudflare tab to hide your origin and get edge-level DDoS protection.',
  })

  let sslCheck = { id: 'tls_strict', category: 'Perimeter', weight: 2, status: 'unknown', label: 'TLS/SSL mode', detail: 'Not checkable — connect Cloudflare to verify.', recommendation: 'Connect Cloudflare, then set SSL/TLS mode to Full (Strict).' }
  if (cfConnected && cloudflareSvc.CF_STORE.zone_id) {
    try {
      const data = await cloudflareSvc.cfFetch(`/zones/${cloudflareSvc.CF_STORE.zone_id}/settings/ssl`, cloudflareSvc.CF_STORE.token)
      const mode = data.result?.value
      const strict = mode === 'strict' || mode === 'full_strict'
      sslCheck = {
        ...sslCheck, status: strict ? 'pass' : 'warn',
        detail: `Cloudflare SSL/TLS mode is currently "${mode}".`,
        recommendation: strict ? null : 'Set SSL/TLS mode to Full (Strict) in the Cloudflare tab to prevent origin spoofing.',
      }
    } catch {}
  }
  checks.push(sslCheck)

  const engineOn = state.WAF.engine === 'On'
  checks.push({
    id: 'waf_engine', category: 'WAF', weight: 3,
    status: engineOn ? 'pass' : 'fail',
    label: 'WAF engine enabled',
    detail: engineOn ? 'Coraza is actively blocking, not just logging.' : `Engine is set to "${state.WAF.engine}" — requests are not being blocked.`,
    recommendation: engineOn ? null : 'Set the WAF engine to "On" in the WAF tab.',
  })

  const paranoia = state.WAF.paranoia_level
  checks.push({
    id: 'paranoia_level', category: 'WAF', weight: 1,
    status: paranoia >= 2 ? 'pass' : paranoia === 1 ? 'warn' : 'fail',
    label: 'Paranoia level',
    detail: `Currently PL${paranoia}.`,
    recommendation: paranoia >= 2 ? null : 'Consider PL2 once you\'ve tuned exclusions for your app\'s false positives — PL1 misses more attack patterns.',
  })

  checks.push({
    id: 'rate_limiting', category: 'WAF', weight: 2,
    status: state.WAF.rate_limit?.enabled ? 'pass' : 'fail',
    label: 'Rate limiting enabled',
    detail: state.WAF.rate_limit?.enabled
      ? `Limiting to ${state.WAF.rate_limit.requests_per_min}/min per ${state.WAF.rate_limit.per}.`
      : 'No rate limiting configured — brute-force and scraping traffic is unthrottled.',
    recommendation: state.WAF.rate_limit?.enabled ? null : 'Enable rate limiting in the WAF tab.',
  })

  checks.push({
    id: 'scanner_blocking', category: 'WAF', weight: 1,
    status: (state.WAF.blocked_user_agents || []).length > 0 ? 'pass' : 'warn',
    label: 'Known-scanner blocking',
    detail: `${(state.WAF.blocked_user_agents || []).length} blocked user-agent pattern(s).`,
    recommendation: (state.WAF.blocked_user_agents || []).length > 0 ? null : 'Add sqlmap/nikto/nmap-style scanner user agents to the block list.',
  })

  checks.push({
    id: 'audit_logging', category: 'WAF', weight: 1,
    status: state.WAF.audit_log ? 'pass' : 'warn',
    label: 'Audit logging enabled',
    detail: state.WAF.audit_log ? 'Coraza is writing an audit trail.' : 'Audit logging is off — you won\'t have request-level detail if you need to investigate later.',
    recommendation: state.WAF.audit_log ? null : 'Enable audit_log in WAF settings.',
  })

  const bootstrapped = !needsBootstrap()
  checks.push({
    id: 'default_credentials', category: 'Access Control', weight: 3,
    status: bootstrapped ? 'pass' : 'fail',
    label: 'Admin account configured',
    detail: bootstrapped
      ? 'A real admin account exists — CatWAF ships with no default credentials.'
      : 'No admin account has been created yet.',
    recommendation: bootstrapped ? null : 'Run `catwaf --setup` to create your admin login.',
  })

  const jwtConfigured = !!process.env.JWT_SECRET
  checks.push({
    id: 'jwt_secret', category: 'Access Control', weight: 2,
    status: jwtConfigured ? 'pass' : 'warn',
    label: 'JWT secret explicitly configured',
    detail: jwtConfigured ? 'JWT_SECRET is set via environment variable.' : 'No JWT_SECRET set — using a secret generated fresh at process start, which invalidates all sessions on every restart.',
    recommendation: jwtConfigured ? null : 'Set JWT_SECRET in your .env before deploying anywhere persistent.',
  })

  checks.push({
    id: 'two_factor_auth', category: 'Access Control', weight: 1,
    status: 'fail',
    label: 'Two-factor authentication',
    detail: 'CatWAF does not currently support 2FA for admin login.',
    recommendation: 'Not yet available — noted here so it isn\'t forgotten. Consider it for the user-management roadmap item.',
  })

  const headerChecks = [
    ['Content-Security-Policy', 'CSP'],
    ['Strict-Transport-Security', 'HSTS'],
    ['X-Frame-Options', 'X-Frame-Options'],
    ['X-Content-Type-Options', 'X-Content-Type-Options'],
  ]
  for (const [headerName, shortName] of headerChecks) {
    const present = hasHeaderRule(headerName)
    checks.push({
      id: `header_${shortName.toLowerCase().replace(/[^a-z0-9]/g, '_')}`, category: 'Security Headers', weight: 1,
      status: present ? 'pass' : 'warn',
      label: `${shortName} header`,
      detail: present ? `${headerName} is configured in header_rules.` : `${headerName} is not configured.`,
      recommendation: present ? null : `Add a header_rules entry for ${headerName} in WAF settings.`,
    })
  }

  return checks
}

function summarize(checks) {
  let earned = 0, possible = 0
  const byCategory = {}
  for (const c of checks) {
    if (!byCategory[c.category]) byCategory[c.category] = []
    byCategory[c.category].push(c)
    const credit = STATUS_CREDIT[c.status]
    if (credit === null) continue
    earned += credit * c.weight
    possible += c.weight
  }
  const score = possible > 0 ? Math.round((earned / possible) * 100) : 0
  const warnings = checks.filter(c => c.status === 'warn' || c.status === 'fail')
  const failures = checks.filter(c => c.status === 'fail')
  return {
    score,
    grade: score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F',
    checks,
    by_category: byCategory,
    passing: checks.filter(c => c.status === 'pass').length,
    warnings: warnings.length,
    critical_failures: failures.filter(c => c.weight >= 3).length,
    total_checks: checks.filter(c => c.status !== 'unknown').length,
    recommendations: checks.filter(c => c.recommendation).map(c => ({ id: c.id, label: c.label, recommendation: c.recommendation, severity: c.weight >= 3 ? 'high' : c.weight === 2 ? 'medium' : 'low' })),
    computed_at: new Date().toISOString(),
  }
}

async function getSecurityScore() {
  const checks = await computeChecks()
  return summarize(checks)
}

module.exports = { getSecurityScore }
