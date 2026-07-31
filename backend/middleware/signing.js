
const crypto = require('crypto')
const secrets = require('../services/secrets')
const { FIXED_PATHS } = require('./dynamicPath')

const MAX_SKEW_MS = 2 * 60 * 1000
const NONCE_TTL_MS = 5 * 60 * 1000

const SIGNATURE_EXEMPT_PATHS = new Set([...FIXED_PATHS])

const seenNonces = new Map()

function rememberNonce(nonce) {
  const now = Date.now()
  if (seenNonces.size > 10000) {
    for (const [k, exp] of seenNonces) if (exp <= now) seenNonces.delete(k)
  }
  seenNonces.set(nonce, now + NONCE_TTL_MS)
}

function nonceSeen(nonce) {
  const exp = seenNonces.get(nonce)
  if (exp === undefined) return false
  if (exp <= Date.now()) { seenNonces.delete(nonce); return false }
  return true
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf ?? Buffer.alloc(0)).digest('hex')
}

function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false
  try { return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')) }
  catch { return false }
}

function canonicalString({ method, path, ts, nonce, bodyHash }) {
  return [method.toUpperCase(), path, ts, nonce, bodyHash].join('\n')
}

function sign(sessionKey, parts) {
  return crypto.createHmac('sha256', sessionKey).update(canonicalString(parts)).digest('hex')
}

function captureRawBody(req, res, buf) {
  req.rawBody = buf && buf.length ? Buffer.from(buf) : Buffer.alloc(0)
}

function verifySignature(req, res, next) {
  if (!req.user || !req.user.jti) return next()
  if (SIGNATURE_EXEMPT_PATHS.has((req.signedPath || '').split('?')[0])) return next()

  const ts = req.get('x-catwaf-ts')
  const nonce = req.get('x-catwaf-nonce')
  const provided = req.get('x-catwaf-sig')

  if (!ts || !nonce || !provided) {
    return res.status(401).json({ detail: 'Request signature missing.', code: 'SIG_REQUIRED' })
  }
  if (!/^[0-9a-f]{16,64}$/.test(nonce)) {
    return res.status(401).json({ detail: 'Invalid request nonce.', code: 'SIG_INVALID' })
  }

  const tsNum = Number(ts)
  if (!Number.isFinite(tsNum) || Math.abs(Date.now() - tsNum) > MAX_SKEW_MS) {
    return res.status(401).json({ detail: 'Request timestamp outside the accepted window.', code: 'SIG_EXPIRED' })
  }
  if (nonceSeen(nonce)) {
    return res.status(401).json({ detail: 'Replayed request rejected.', code: 'SIG_REPLAY' })
  }

  const sessionKey = secrets.sessionKey(req.user.jti)
  const expected = sign(sessionKey, {
    method: req.method,
    path: req.signedPath,
    ts,
    nonce,
    bodyHash: sha256Hex(req.rawBody),
  })

  if (!safeEqualHex(provided, expected)) {
    return res.status(401).json({ detail: 'Invalid request signature.', code: 'SIG_INVALID' })
  }

  rememberNonce(nonce)
  next()
}

function recordSignedPath(req, res, next) {
  req.signedPath = req.url
  next()
}

module.exports = { verifySignature, recordSignedPath, captureRawBody, sign, canonicalString, MAX_SKEW_MS }
