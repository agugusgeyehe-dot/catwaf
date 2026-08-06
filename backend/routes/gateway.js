// routes/gateway.js — the endpoints that live OUTSIDE CatWAF's rotating
// admin path, because something other than the dashboard has to reach them
// at a fixed URL:
//
//   /api/enforce        Caddy's forward_auth hop into the classification
//                       pipeline (ideas #1-#13).
//   /catwaf-challenge   the interstitial a challenged visitor is sent to.
//   /metrics            the Prometheus scrape endpoint (idea #46).
//
// Being outside the gate makes each of these its own trust boundary, so each
// carries its own authentication:
//   * /api/enforce requires a shared key derived from the instance secret and
//     rendered into the Caddyfile, so only this install's own Caddy can call it.
//   * /metrics requires a bearer token and a source-CIDR allowlist.
//   * /catwaf-challenge is deliberately public — it is served to unverified
//     visitors — and holds no state beyond a short-lived signed token.
//
// One failure mode matters more than the others: if /api/enforce returned a
// non-2xx for an operational reason, forward_auth would read that as "deny"
// and take the whole site down. Every error path here therefore answers 200
// with an allow verdict; enforcement failing open is the only safe default
// for a layer that sits in front of the real WAF.

const express = require('express')
const crypto = require('crypto')

const router = express.Router()

const enforce = require('../services/enforce')
const challenge = require('../services/challenge')
const settings = require('../services/settings')
const secrets = require('../services/secrets')
const bans = require('../services/bans')
const metricsSvc = require('../services/metrics')
const logger = require('../services/logger')
const { ipCoveredBy, normalizeClientIp } = require('../services/sanitize')

const log = logger.child('gateway')

function timingSafeEquals(a, b) {
  const bufA = Buffer.from(String(a || ''))
  const bufB = Buffer.from(String(b || ''))
  if (bufA.length === 0 || bufA.length !== bufB.length) return false
  return crypto.timingSafeEqual(bufA, bufB)
}

function forwardedIp(req) {
  const real = req.headers['x-catwaf-client-ip'] || req.headers['x-real-ip']
  if (real) return normalizeClientIp(String(real).split(',')[0].trim())
  const xff = req.headers['x-forwarded-for']
  if (xff) return normalizeClientIp(String(xff).split(',')[0].trim())
  return normalizeClientIp(req.ip || '')
}

function forwardedUri(req) {
  return String(req.headers['x-forwarded-uri'] || req.query.uri || '/').slice(0, 2048)
}

// Just the header *names* the visitor sent — not values, so nothing like a
// cookie or auth token ends up flowing into fingerprint scoring. Caddy's
// forward_auth proxies the full original request, so req.headers here is
// the visitor's own header set, not something CatWAF invented.
function forwardedHeaderNames(req) {
  return Object.keys(req.headers || {}).slice(0, 100)
}

// ─── /api/enforce ───────────────────────────────────────────────────────

router.all('/api/enforce', async (req, res) => {
  if (!timingSafeEquals(req.headers['x-catwaf-enforce-key'], secrets.derive('enforce-key'))) {
    // A wrong key is a misconfiguration or a probe, not a reason to break
    // the site — but it must not be treated as an authenticated call either.
    return res.status(404).json({ detail: 'Not found' })
  }

  const ip = forwardedIp(req)
  const uri = forwardedUri(req)
  const userAgent = String(req.headers['user-agent'] || '').slice(0, 512)
  const headers = forwardedHeaderNames(req)

  let verdict
  try {
    verdict = await enforce.evaluate({ ip, uri, userAgent, headers })
  } catch (e) {
    log.error('Enforcement pipeline failed — allowing the request', { error: e.message, ip })
    res.set('X-CatWAF-Verdict', 'allow-error')
    return res.status(200).json({ action: 'allow', error: e.message })
  }

  if (verdict.action === 'block') {
    const access = settings.get('access')
    res.set('X-CatWAF-Verdict', 'block')
    res.set('X-CatWAF-Reason', String(verdict.reason || '').replace(/[\r\n]/g, ' ').slice(0, 200))
    if (access.block_response_mode === 'silent') {
      // No body and an immediate socket destroy is the closest an Express
      // handler can get to Coraza's `drop`.
      res.status(access.blocked_status_code)
      return req.socket.destroy()
    }
    return res.status(access.blocked_status_code).json({ detail: 'Forbidden' })
  }

  if (verdict.action === 'challenge' && !challenge.isVerified(req)) {
    res.set('X-CatWAF-Verdict', 'challenge')
    return res.redirect(302, `/catwaf-challenge?return_to=${encodeURIComponent(uri)}`)
  }

  res.set('X-CatWAF-Verdict', verdict.greylisted ? 'greylist' : 'allow')
  return res.status(200).json({ action: 'allow', cached: verdict.cached })
})

// ─── /catwaf-challenge ──────────────────────────────────────────────────

const challengeBody = express.urlencoded({ extended: false, limit: '16kb' })

function isSecureRequest(req) {
  return req.secure || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https'
}

router.get('/catwaf-challenge', (req, res) => {
  const cfg = settings.get('challenge')
  if (cfg.mode === 'off') return res.redirect(302, challenge.safeReturnTo(req.query.return_to))
  if (challenge.isVerified(req)) return res.redirect(302, challenge.safeReturnTo(req.query.return_to))

  const issued = challenge.issue({
    ip: forwardedIp(req),
    userAgent: req.headers['user-agent'],
    returnTo: req.query.return_to,
  })
  res.set('Cache-Control', 'no-store, private')
  res.set('X-Robots-Tag', 'noindex, nofollow')
  res.type('html').status(503).send(issued.html)
})

router.get('/catwaf-challenge/status', (req, res) => {
  res.set('Cache-Control', 'no-store').json({
    verified: challenge.isVerified(req),
    mode: settings.get('challenge').mode,
  })
})

router.post('/catwaf-challenge/verify', challengeBody, async (req, res) => {
  const cfg = settings.get('challenge')
  if (cfg.mode === 'off') return res.redirect(302, '/')

  const ip = forwardedIp(req)
  const body = req.body || {}
  const providerToken = body[`g-recaptcha-response`] || body['h-captcha-response'] || body['cf-turnstile-response'] || body['mcaptcha__token'] || body.token

  let result
  try {
    result = await challenge.solve({
      id: String(body.challenge_id || ''),
      ip,
      userAgent: req.headers['user-agent'],
      answer: body.answer,
      proof: body.proof,
      providerToken,
    })
  } catch (e) {
    log.error('Challenge verification failed', { error: e.message })
    result = { ok: false, error: 'Verification could not be completed. Please try again.' }
  }

  const returnTo = challenge.safeReturnTo(body.return_to)

  if (result.banned) {
    bans.ban({
      target: ip,
      source: 'challenge',
      seconds: 3600,
      reason: `Failed the challenge ${cfg.max_attempts} times.`,
    })
    return res.status(429).type('html').send(
      require('../services/challenge/page').build({
        mode: cfg.mode, provider: cfg.provider, siteKey: cfg.site_key,
        token: '', returnTo, error: 'Too many failed attempts. Try again later.', challengeId: '',
      })
    )
  }

  if (!result.ok) {
    const reissued = challenge.issue({ ip, userAgent: req.headers['user-agent'], returnTo, error: result.error })
    return res.status(403).type('html').send(reissued.html)
  }

  res.set('Set-Cookie', challenge.cookieHeader(result.token, result.maxAge, { secure: isSecureRequest(req) }))
  res.set('Cache-Control', 'no-store, private')
  return res.redirect(303, returnTo)
})

// ─── /metrics (idea #46) ────────────────────────────────────────────────

function metricsAllowed(req) {
  const cfg = settings.get('metrics')
  if (!cfg.enabled) return { ok: false, status: 404, detail: 'Not found' }

  const ip = normalizeClientIp(req.ip || '')
  if (cfg.allow_cidrs.length && !cfg.allow_cidrs.some(cidr => ipCoveredBy(ip, cidr))) {
    return { ok: false, status: 403, detail: 'Metrics are not exposed to this address.' }
  }

  if (cfg.require_token) {
    const header = String(req.headers.authorization || '')
    const bearer = header.startsWith('Bearer ') ? header.slice(7) : ''
    if (!cfg.token || !timingSafeEquals(bearer, cfg.token)) {
      return { ok: false, status: 401, detail: 'A bearer token is required to scrape metrics.' }
    }
  }
  return { ok: true }
}

router.get('/metrics', (req, res) => {
  const check = metricsAllowed(req)
  if (!check.ok) return res.status(check.status).json({ detail: check.detail })
  res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  res.set('Cache-Control', 'no-store')
  res.send(metricsSvc.render())
})

// The path is configurable, so the configured one is also served when it
// differs from the default.
router.get(/^\/[A-Za-z0-9._~/-]{1,120}$/, (req, res, next) => {
  const cfg = settings.get('metrics')
  if (!cfg.enabled || cfg.path === '/metrics' || req.path !== cfg.path) return next()
  const check = metricsAllowed(req)
  if (!check.ok) return res.status(check.status).json({ detail: check.detail })
  res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
  res.set('Cache-Control', 'no-store')
  res.send(metricsSvc.render())
})

module.exports = router
