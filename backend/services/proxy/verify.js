// proxy/verify.js — prove that traffic actually traverses the WAF.
//
// Writing a Caddyfile and reloading is not protection. A route can be
// generated, validated and applied and STILL leave the site unprotected —
// the upstream may not resolve, `order coraza_waf first` may be missing so
// requests reach the app before Coraza sees them, or the engine may be in
// DetectionOnly. None of that shows up in config validation.
//
// So after applying, CatWAF sends two real requests to its own protected
// endpoint and checks the outcomes:
//
//   1. a benign request  -> must be served (proves the upstream is reachable
//                           through the proxy, i.e. the site still works)
//   2. a CRS test payload -> must be refused (proves Coraza is genuinely in
//                           the request path and blocking, not bypassed)
//
// Only if BOTH hold is a route reported as protected. Anything else is
// reported as unverified, with the reason — never as "protected".
//
// The probe payload is the standard, inert OWASP CRS SQL-injection
// signature used throughout this repo's own tests. It is a detection
// string, not a working exploit: it is sent to CatWAF's own listener, and
// if the WAF is working it never reaches the application at all.

const http = require('http')

const BENIGN_PATH = '/'
const ATTACK_PATH = '/?id=1+UNION+SELECT+1,2,3--'

function request(port, path, { timeoutMs = 4000, headers = {} } = {}) {
  return new Promise(resolve => {
    const req = http.get({
      host: '127.0.0.1',
      port,
      path,
      timeout: timeoutMs,
      headers: { 'User-Agent': 'CatWAF-Protection-Selftest/1.0', ...headers },
    }, res => {
      let body = ''
      res.on('data', c => { if (body.length < 2048) body += c })
      res.on('end', () => resolve({ ok: true, status: res.statusCode, body }))
      res.resume()
    })
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }) })
    req.on('error', e => resolve({ ok: false, error: e.code || e.message }))
  })
}

// Blocked statuses Coraza/CRS may return depending on configuration.
const BLOCKED_STATUSES = new Set([403, 406, 418, 501])

async function verifyRoute(route, { attempts = 20, delayMs = 250 } = {}) {
  const port = route.listenPort

  // Caddy may still be reloading — wait for the listener to come up before
  // concluding anything.
  let benign = null
  for (let i = 0; i < attempts; i++) {
    benign = await request(port, BENIGN_PATH)
    if (benign.ok) break
    await new Promise(r => setTimeout(r, delayMs))
  }

  if (!benign || !benign.ok) {
    return {
      name: route.name,
      protected: false,
      reason: `CatWAF is not answering on :${port} (${benign?.error || 'no response'}). The route was written but no traffic can traverse it.`,
      benignStatus: null,
      attackStatus: null,
    }
  }

  // A 502/504 means Caddy is listening but cannot reach the upstream — the
  // site is DOWN, which is worse than unprotected. Say so plainly.
  if (benign.status === 502 || benign.status === 503 || benign.status === 504) {
    return {
      name: route.name,
      protected: false,
      upstreamUnreachable: true,
      reason: `CatWAF is listening on :${port} but cannot reach the upstream ${route.upstream} (HTTP ${benign.status}). Traffic would break rather than be protected.`,
      benignStatus: benign.status,
      attackStatus: null,
    }
  }

  const attack = await request(port, ATTACK_PATH)
  if (!attack.ok) {
    return {
      name: route.name,
      protected: false,
      reason: `The WAF probe to :${port} failed (${attack.error}).`,
      benignStatus: benign.status,
      attackStatus: null,
    }
  }

  const blocked = BLOCKED_STATUSES.has(attack.status)
  if (!blocked) {
    return {
      name: route.name,
      protected: false,
      wafBypassed: true,
      reason: `A CRS test payload reached the application on :${port} (HTTP ${attack.status}, expected a block). Coraza is not inspecting this route — check that \`order coraza_waf first\` is present and SecRuleEngine is On.`,
      benignStatus: benign.status,
      attackStatus: attack.status,
    }
  }

  return {
    name: route.name,
    protected: true,
    reason: null,
    benignStatus: benign.status,
    attackStatus: attack.status,
    upstream: route.upstream,
    listenPort: port,
  }
}

async function verifyRoutes(routes, opts = {}) {
  const results = []
  for (const route of routes) results.push(await verifyRoute(route, opts))
  return {
    results,
    protectedCount: results.filter(r => r.protected).length,
    allProtected: results.length > 0 && results.every(r => r.protected),
  }
}

module.exports = { verifyRoute, verifyRoutes, request, BLOCKED_STATUSES, ATTACK_PATH, BENIGN_PATH }
