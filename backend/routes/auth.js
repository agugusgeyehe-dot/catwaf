
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

  clearLoginAttempts(req)

  const jti = crypto.randomBytes(16).toString('hex')
  const token = jwt.sign(
    { id: u.id, username: u.username, role: u.role },
    JWT_SECRET,
    { expiresIn: TOKEN_TTL, algorithm: 'HS256', issuer: JWT_ISSUER, audience: JWT_AUDIENCE, jwtid: jti },
  )

  auditSvc.audit({ user: u, ip: req.ip }, 'auth.login', u.username)

  res.json({
    token,
    sessionKey: secrets.sessionKey(jti),
    api: currentSegment(),
    user: { id: u.id, username: u.username, role: u.role },
  })
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
  res.json({ api: currentSegment(), user: { username: req.user.username, role: req.user.role } })
})

module.exports = router
