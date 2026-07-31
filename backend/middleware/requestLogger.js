
const logger = require('../services/logger')
const log = logger.child('http')

const SENSITIVE_QUERY = /([?&](?:token|sig|password|secret|api[_-]?key)=)[^&#]*/gi
function redactUrl(url) {
  return String(url || '').replace(SENSITIVE_QUERY, '$1[REDACTED]')
}

function requestLogger(req, res, next) {
  const startedAt = process.hrtime.bigint()

  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
    const safeUrl = redactUrl(req.originalUrl)
    const meta = {
      method: req.method,
      path: safeUrl,
      status: res.statusCode,
      duration_ms: Math.round(durationMs * 100) / 100,
      user: req.user?.username || 'guest',
      ip: req.ip,
    }
    const message = `${req.method} ${safeUrl} ${res.statusCode} (${meta.duration_ms}ms)`
    if (res.statusCode >= 500) log.error(message, meta)
    else if (res.statusCode >= 400) log.warn(message, meta)
    else log.info(message, meta)
  })

  next()
}

module.exports = requestLogger
