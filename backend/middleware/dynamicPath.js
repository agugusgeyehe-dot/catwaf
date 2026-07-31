
const crypto = require('crypto')
const secrets = require('../services/secrets')

const WINDOW_MS = 15 * 60 * 1000
const SEGMENT_BYTES = 16

const FIXED_PATHS = new Set(['/api/auth/login', '/api/auth/status', '/api/handshake', '/healthz'])

function segmentForWindow(w) {
  return crypto.createHmac('sha256', secrets.pathSecret())
    .update(`window:${w}`)
    .digest('hex')
    .slice(0, SEGMENT_BYTES * 2)
}

function currentWindow() { return Math.floor(Date.now() / WINDOW_MS) }

function currentSegment() {
  const w = currentWindow()
  return {
    segment: segmentForWindow(w),
    basePath: `/g/${segmentForWindow(w)}`,
    expiresAt: (w + 1) * WINDOW_MS,
    windowMs: WINDOW_MS,
  }
}

function isValidSegment(seg) {
  if (typeof seg !== 'string' || seg.length !== SEGMENT_BYTES * 2) return false
  const w = currentWindow()
  const buf = Buffer.from(seg)
  for (const candidate of [segmentForWindow(w), segmentForWindow(w - 1)]) {
    const cand = Buffer.from(candidate)
    if (buf.length === cand.length && crypto.timingSafeEqual(buf, cand)) return true
  }
  return false
}

const SEGMENT_RE = /^\/g\/([0-9a-f]{32})(\/.*)?$/

function unwrapDynamicPath(req, res, next) {
  const m = SEGMENT_RE.exec(req.url.split('?')[0])
  if (!m) return next()

  if (!isValidSegment(m[1])) {
    return res.status(410).json({ detail: 'Expired API path — re-handshake required.', code: 'PATH_ROTATED' })
  }

  const qIndex = req.url.indexOf('?')
  const query = qIndex === -1 ? '' : req.url.slice(qIndex)
  const rest = (m[2] || '/').split('?')[0]
  req.url = rest + query
  req.viaDynamicPath = true
  next()
}

function requireDynamicPath(decoyResponder) {
  return function requireDynamicPathMw(req, res, next) {
    const path = req.path.toLowerCase()
    if (!path.startsWith('/api')) return next()
    if (FIXED_PATHS.has(path)) return next()
    if (req.viaDynamicPath) return next()
    return decoyResponder(req, res)
  }
}

module.exports = { unwrapDynamicPath, requireDynamicPath, currentSegment, isValidSegment, FIXED_PATHS, WINDOW_MS }
