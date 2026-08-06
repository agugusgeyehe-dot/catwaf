
const state = require('./state')
const cloudflareSvc = require('./cloudflare')
const db = require('./db')
const settings = require('./settings')
const { needsBootstrap } = require('../middleware/auth')

const STATUS_CREDIT = { pass: 1, warn: 0.5, fail: 0, unknown: null }

// The score used to be unable to reward header hygiene at all, because
// CatWAF did not manage headers — the only signal was a hand-written
// header_rules entry. Now the header policy (idea #34) is real state, so
// each header is scored from whichever source actually sets it.
function headerSetBy(name) {
  const legacy = (state.WAF.header_rules || []).some(h => (h?.name || '').toLowerCase() === name.toLowerCase())
  if (legacy) return 'a header_rules entry'

  const cfg = settings.get('headers')
  if (cfg.preset === 'off') return null

  const managed = {
    'strict-transport-security': cfg.hsts_max_age > 0,
    'x-content-type-options': cfg.x_content_type_options,
    'x-frame-options': !!cfg.x_frame_options,
    'referrer-policy': !!cfg.referrer_policy,
    'content-security-policy': !!cfg.csp || cfg.preset === 'strict',
    'permissions-policy': !!cfg.permissions_policy || cfg.preset === 'strict',
    'cross-origin-opener-policy': !!cfg.coop || cfg.preset === 'strict',
    'cross-origin-resource-policy': !!cfg.corp || cfg.preset === 'strict',
  }
  if (managed[name.toLowerCase()]) return `the ${cfg.preset} header policy`

  if (cfg.custom.some(c => (c.name || '').toLowerCase() === name.toLowerCase())) return 'a custom header rule'
  return null
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

  const totp = require('./totp')
  const twoFactor = totp.anyEnabled()
  checks.push({
    id: 'two_factor_auth', category: 'Access Control', weight: 2,
    status: twoFactor ? 'pass' : 'warn',
    label: 'Two-factor authentication',
    detail: twoFactor
      ? 'An admin account is protected by a time-based one-time password.'
      : 'No admin account has a second factor enrolled. CatWAF Free is single-admin, so that one password is the whole path to taking over the WAF.',
    recommendation: twoFactor ? null : 'Enrol an authenticator app under Account → Two-factor authentication.',
  })

  const session = settings.get('session')
  const bound = session.bind_ip || session.bind_user_agent || session.idle_timeout_min > 0
  checks.push({
    id: 'session_hardening', category: 'Access Control', weight: 1,
    status: bound ? 'pass' : 'warn',
    label: 'Admin session hardening',
    detail: bound
      ? `Sessions expire after ${session.absolute_max_age_min} minutes${session.idle_timeout_min ? `, or ${session.idle_timeout_min} minutes idle` : ''}${session.bind_ip ? ', and are bound to the client address' : ''}.`
      : `Sessions last ${session.absolute_max_age_min} minutes with no idle timeout and no client binding.`,
    recommendation: bound ? null : 'Consider an idle timeout under Settings → Admin sessions. Binding to the client IP is stronger still, but logs you out when your address changes.',
  })

  const headerChecks = [
    ['Content-Security-Policy', 'CSP', 2],
    ['Strict-Transport-Security', 'HSTS', 2],
    ['X-Frame-Options', 'X-Frame-Options', 1],
    ['X-Content-Type-Options', 'X-Content-Type-Options', 1],
    ['Referrer-Policy', 'Referrer-Policy', 1],
    ['Permissions-Policy', 'Permissions-Policy', 1],
  ]
  for (const [headerName, shortName, weight] of headerChecks) {
    const setBy = headerSetBy(headerName)
    checks.push({
      id: `header_${shortName.toLowerCase().replace(/[^a-z0-9]/g, '_')}`, category: 'Security Headers', weight,
      status: setBy ? 'pass' : 'warn',
      label: `${shortName} header`,
      detail: setBy ? `${headerName} is set by ${setBy}.` : `${headerName} is not being sent.`,
      recommendation: setBy ? null : `Turn on the header policy under Content & Headers — the "strict" preset sets ${headerName} along with the rest.`,
    })
  }

  const cookies = settings.get('cookies')
  checks.push({
    id: 'cookie_flags', category: 'Security Headers', weight: 1,
    status: cookies.enabled ? 'pass' : 'warn',
    label: 'Cookie flags enforced',
    detail: cookies.enabled
      ? `Backend cookies are normalised to ${[cookies.secure !== 'off' && 'Secure', cookies.http_only && 'HttpOnly', cookies.same_site && `SameSite=${cookies.same_site}`].filter(Boolean).join(', ')}.`
      : 'Cookie security flags depend entirely on the application getting them right.',
    recommendation: cookies.enabled ? null : 'Enable cookie flags under Content & Headers so Secure/HttpOnly/SameSite are added even when the backend forgets.',
  })

  // ── Perimeter checks the new settings made answerable ──
  const access = settings.get('access')
  checks.push({
    id: 'reject_unknown_host', category: 'Perimeter', weight: 2,
    status: access.reject_unknown_host ? 'pass' : 'warn',
    label: 'Unknown Host/SNI rejected',
    detail: access.reject_unknown_host
      ? 'Requests whose Host does not match a known hostname are refused before reaching a site block.'
      : 'Any Host header reaches the site block, so an attacker who finds the origin IP can bypass a CDN in front of it.',
    recommendation: access.reject_unknown_host ? null : 'Turn on "Reject unknown Host/SNI" under Access control — this is the mechanical fix for the origin-exposure problem.',
  })

  const proxy = settings.get('proxy')
  checks.push({
    id: 'upstream_tls_verify', category: 'Perimeter', weight: 1,
    status: proxy.protocol === 'http' ? 'unknown' : proxy.upstream_tls_verify ? 'pass' : 'warn',
    label: 'Upstream certificate verified',
    detail: proxy.protocol === 'http'
      ? 'The backend is reached over plain HTTP, so there is no certificate to verify.'
      : proxy.upstream_tls_verify
        ? 'The backend\'s TLS certificate is verified before traffic is forwarded.'
        : 'The backend is reached over HTTPS but its certificate is not checked, so a spoofed backend would go undetected.',
    recommendation: proxy.protocol === 'http' || proxy.upstream_tls_verify ? null : 'Enable upstream TLS verification under Reverse proxy once the backend has a real certificate.',
  })

  const bans = require('./bans').stats()
  const autoBan = settings.get('bad_behavior').enabled
  checks.push({
    id: 'automatic_banning', category: 'WAF', weight: 1,
    status: autoBan ? 'pass' : 'warn',
    label: 'Behavioural banning',
    detail: autoBan
      ? `Enabled — ${bans.total} address(es) currently banned.`
      : 'Credential stuffing and endpoint brute-forcing never trip a WAF rule, because each individual request is valid. Nothing is counting failures.',
    recommendation: autoBan ? null : 'Enable behavioural banning under Protection so repeated failures get an address banned.',
  })

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
