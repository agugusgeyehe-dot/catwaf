
const logger = require('../services/logger')
const log = logger.child('error')
const auditSvc = require('../services/audit')

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next)
}

const API_DECOY_LINES = [
  'I love cats and you are not a cat.',
  '404: this is not the endpoint you are looking for.',
  'Nothing to see here. Nice try, though.',
  'This route does not exist, and neither does your foothold.',
  'Meow. That is all you get.',
]

const SENSITIVE_QUERY = /([?&](?:token|sig|password|secret|api[_-]?key)=)[^&#]*/gi
function redactUrl(url) {
  return String(url || '').replace(SENSITIVE_QUERY, '$1[REDACTED]')
}

function decoyNotFound(req, res) {
  // The probed URL is attacker-controlled and often carries secrets in its
  // query string — redact before it lands in the audit store.
  try { auditSvc.audit({ user: { username: 'probe' } }, 'security.api-probe', redactUrl(req.originalUrl), { method: req.method }) } catch {}
  const line = API_DECOY_LINES[Math.floor(Math.random() * API_DECOY_LINES.length)]
  return res.status(404).json({ detail: line })
}

function notFoundHandler(req, res) {
  if (req.originalUrl.startsWith('/api') || req.originalUrl.startsWith('/g/')) {
    return decoyNotFound(req, res)
  }
  res.status(404).json({ detail: 'Not found' })
}

function errorHandler(err, req, res, next) {
  const status = err.status || err.statusCode || 500
  const safeUrl = redactUrl(req.originalUrl)
  const meta = {
    method: req.method,
    path: safeUrl,
    status,
    user: req.user?.username || 'guest',
    error: err.message,
    stack: err.stack,
  }
  if (status >= 500) log.error(`Unhandled error on ${req.method} ${safeUrl}`, meta)
  else log.warn(`Request error on ${req.method} ${safeUrl}`, meta)

  if (res.headersSent) return next(err)

  res.status(status).json({
    detail: status >= 500 ? 'Internal server error' : (err.message || 'Request failed'),
  })
}

module.exports = { asyncHandler, notFoundHandler, errorHandler, decoyNotFound }
