
const crypto = require('crypto')
const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const router = express.Router()

const {
  USERS, JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE,
  loginRateLimit, clearLoginAttempts, needsBootstrap,
} = require('../middleware/auth')
const auditSvc = require('../services/audit')
const passwordHash = require('../services/passwordHash')
const secrets = require('../services/secrets')
const totp = require('../services/totp')
const settings = require('../services/settings')
const sessionSvc = require('../services/session')
const { currentSegment } = require('../middleware/dynamicPath')

const TOKEN_TTL = '12h'

const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(24).toString('hex'), 12)

const MAX_PASSWORD_BYTES = 1024

router.post('/api/auth/login', loginRateLimit, async (req, res, next) => {
  const { username, password } = req.body || {}

  if (needsBootstrap()) {
    return res.status(409).json({
      detail: 'No account has been created yet. Run `catwaf --setup` on the server first.',
      code: 'NEEDS_SETUP',
    })
  }

  if (typeof username !== 'string' || typeof password !== 'string' || password.length > MAX_PASSWORD_BYTES) {
    return res.status(400).json({ detail: 'Invalid credentials' })
  }

  const u = USERS.find(x => x.username === username)

  let ok
  try {
    ok = await passwordHash.compare(password, (u && typeof u.password_hash === 'string') ? u.password_hash : DUMMY_HASH)
  } catch (e) { return next(e) }

  if (!u || !ok) {
    auditSvc.audit({ user: { username: 'anonymous' }, ip: req.ip }, 'auth.login-failed', String(username || '').slice(0, 64))
    return res.status(401).json({ detail: 'Invalid credentials' })
  }

  // Second factor (idea #49). The password check has already succeeded, so
  // a missing code is answered with a distinct code the client can act on
  // rather than a generic failure — but the account is not logged in, and
  // the rate limiter is not cleared until the second factor also passes.
  if (totp.isEnabled(u.username)) {
    const code = (req.body || {}).totp
    if (typeof code !== 'string' || !code.trim()) {
      return res.status(401).json({ detail: 'Enter the code from your authenticator app.', code: 'TOTP_REQUIRED' })
    }
    const check = totp.verify(u.username, code)
    if (!check.ok) {
      auditSvc.audit({ user: { username: u.username }, ip: req.ip }, 'auth.totp-failed', u.username)
      return res.status(401).json({ detail: check.error, code: 'TOTP_INVALID' })
    }
    if (check.used_recovery_code) {
      auditSvc.audit({ user: u, ip: req.ip }, 'auth.recovery-code-used', u.username, { remaining: check.recovery_codes_remaining })
    }
  }

  clearLoginAttempts(req)

  const jti = crypto.randomBytes(16).toString('hex')
  const session = settings.get('session')
  // softAuth invalidates any token whose iat is at or before the account's
  // tokens_valid_after stamp, which is inclusive so that a token minted in
  // the same second as a password reset cannot survive it. Stamping this
  // token one second past the reset keeps that boundary from catching a
  // legitimate login that happens to land in the reset's own second.
  const iat = Math.max(Math.floor(Date.now() / 1000), (u.tokens_valid_after || 0) + 1)
  const token = jwt.sign(
    { id: u.id, username: u.username, role: u.role, iat },
    JWT_SECRET,
    {
      // Idea #25: the absolute session lifetime is a setting rather than a
      // hardcoded 12 hours, with the previous value as the default so no
      // existing install's behaviour changes until an admin opts in.
      expiresIn: `${Math.max(5, session.absolute_max_age_min)}m`,
      algorithm: 'HS256', issuer: JWT_ISSUER, audience: JWT_AUDIENCE, jwtid: jti,
    },
  )

  sessionSvc.open({ jti, user: u, req })

  auditSvc.audit({ user: u, ip: req.ip }, 'auth.login', u.username, { totp: totp.isEnabled(u.username) })

  res.json({
    token,
    sessionKey: secrets.sessionKey(jti),
    api: currentSegment(),
    user: { id: u.id, username: u.username, role: u.role },
    session: {
      expires_in_min: Math.max(5, session.absolute_max_age_min),
      idle_timeout_min: session.idle_timeout_min || null,
      bound: [session.bind_ip && 'ip', session.bind_user_agent && 'browser'].filter(Boolean),
    },
  })
})

router.post('/api/auth/logout', (req, res) => {
  if (req.user?.jti) sessionSvc.close(req.user.jti)
  auditSvc.audit(req, 'auth.logout', req.user?.username || 'unknown')
  res.json({ ok: true })
})

router.get('/api/auth/status', (req, res) => {
  res.json({ needs_setup: needsBootstrap() })
})

router.get('/api/auth/me', (req, res) => {
  const { id, username, role } = req.user || {}
  res.json({ user: username === 'guest' ? null : { id, username, role } })
})

router.get('/api/handshake', (req, res) => {
  if (!req.user || !req.user.jti) {
    return res.status(401).json({ detail: 'Authentication required.', code: 'AUTH_REQUIRED' })
  }
  // /api/handshake is a FIXED_PATH, so requireDynamicPath short-circuits and
  // server.js never runs authRequired for it — which means the one call site
  // of session.touch(), and with it the revocation, idle-timeout and binding
  // checks, is skipped. Signing out has to end the session here too, or a
  // logged-out token still collects the current rotating path. Failing closed
  // when the check itself errors: this endpoint hands out the gate path, so
  // "we could not confirm the session is live" must not mean "here you go".
  let check
  try {
    check = sessionSvc.touch(req.user.jti, req)
  } catch {
    return res.status(401).json({ detail: 'This session could not be verified. Log in again.', code: 'SESSION_UNVERIFIED' })
  }
  if (check && check.ok === false) {
    return res.status(401).json({ detail: check.detail, code: check.code })
  }
  res.json({ api: currentSegment(), user: { username: req.user.username, role: req.user.role } })
})

module.exports = router
