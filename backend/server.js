
require('./services/env').load()

const express = require('express')
const cors = require('cors')
const helmet = require('helmet')
const rateLimit = require('express-rate-limit')
const path = require('path')
const fs = require('fs')
const { version: pkgVersion } = require('../package.json')

const { softAuth, authRequired, needsBootstrap } = require('./middleware/auth')
const requestLogger = require('./middleware/requestLogger')
const { notFoundHandler, errorHandler, decoyNotFound } = require('./middleware/errorHandler')
const { unwrapDynamicPath, requireDynamicPath } = require('./middleware/dynamicPath')
const { verifySignature, recordSignedPath, captureRawBody } = require('./middleware/signing')
const db = require('./services/db')
const auditSvc = require('./services/audit')
const caddySvc = require('./services/caddy')
const logger = require('./services/logger')
const log = logger.child('server')

process.on('uncaughtException', (err) => {
  log.error('Uncaught exception — process will exit', { error: err.message, stack: err.stack })
  process.exit(1)
})
process.on('unhandledRejection', (reason) => {
  const err = reason instanceof Error ? reason : new Error(String(reason))
  log.error('Unhandled promise rejection', { error: err.message, stack: err.stack })
})

let CORS_ORIGIN = process.env.CORS_ORIGIN
if (!CORS_ORIGIN) {
  CORS_ORIGIN = 'http://localhost:3000'
  console.warn('[CatWAF] CORS_ORIGIN is not set — defaulting to the local dev frontend origin (http://localhost:3000).')
  console.warn('[CatWAF] `catwaf --setup` sets this to your real dashboard URL.')
}
const allowedOrigins = CORS_ORIGIN.split(',').map(o => o.trim()).filter(Boolean)

const app = express()

app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS ?? 1))
app.disable('x-powered-by')
app.disable('etag')

const connectSrc = ["'self'"]
if (process.env.DOMAIN) connectSrc.push(`https://api.catwaf.${process.env.DOMAIN}`)
for (const extra of (process.env.CATWAF_CONNECT_SRC || '').split(',').map(s => s.trim()).filter(Boolean)) {
  connectSrc.push(extra)
}
for (const origin of allowedOrigins) {
  if (/^https?:\/\//.test(origin) && !connectSrc.includes(origin)) connectSrc.push(origin)
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      connectSrc,
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", 'https:', "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'", 'https:', 'data:'],
      frameAncestors: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'self'"],
      objectSrc: ["'none'"],
    },
  },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'no-referrer' },
  crossOriginResourcePolicy: { policy: 'same-site' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  noSniff: true,
  frameguard: { action: 'deny' },
}))

app.use(cors({
  origin: (origin, cb) => {
    cb(null, !origin || allowedOrigins.includes(origin))
  },
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CatWAF-Ts', 'X-CatWAF-Nonce', 'X-CatWAF-Sig'],
  maxAge: 600,
}))

app.get('/healthz', (req, res) => res.json({ ok: true }))

const ungatedLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { detail: 'Too many requests — slow down.' },
})
const gatedLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { detail: 'Too many requests — slow down.' },
})

app.use(unwrapDynamicPath)
app.use(recordSignedPath)
app.use(express.json({ limit: '2mb', verify: captureRawBody }))
app.use('/api', softAuth)
app.use('/api', (req, res, next) => (req.viaDynamicPath ? gatedLimiter : ungatedLimiter)(req, res, next))
app.use(requireDynamicPath(decoyNotFound))
app.use('/api', verifySignature)
app.use('/api', (req, res, next) => (req.viaDynamicPath ? authRequired(req, res, next) : next()))
app.use(requestLogger)

app.use(require('./routes/auth'))
app.use(require('./routes/dashboard'))
app.use(require('./routes/waf'))
app.use(require('./routes/network'))
app.use(require('./routes/alerts'))
app.use(require('./routes/sensitive'))
app.use(require('./routes/health'))
app.use(require('./routes/cloudflare'))
app.use(require('./routes/caddy'))
app.use(require('./routes/scanner'))
app.use(require('./routes/security'))
app.use(require('./routes/users'))
app.use(require('./routes/waftools'))
app.use(require('./routes/catai'))

const DIST = path.join(__dirname, '..', 'frontend', 'dist')
if (fs.existsSync(path.join(DIST, 'index.html'))) {
  app.use(express.static(DIST, {
    index: false,
    setHeaders: (res, filePath) => {
      res.setHeader('Cache-Control', /[\\/]assets[\\/]/.test(filePath) ? 'public, max-age=31536000, immutable' : 'no-store')
    },
  }))
  app.get(/^\/assets\//, (req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    res.status(404).json({ detail: 'Asset not found. Reload the page to pick up the current build.' })
  })

  app.get(/^(?!\/api|\/g\/|\/healthz).*/, (req, res) => {
    res.setHeader('Cache-Control', 'no-store')
    res.sendFile(path.join(DIST, 'index.html'))
  })
} else {
  app.get('/', (req, res) => res.json({ status: 'CatWAF Free API running', version: pkgVersion }))
}

app.use(notFoundHandler)
app.use(errorHandler)

const PORT = Number(process.env.PORT || 8000)
const HOST = process.env.HOST || '127.0.0.1'
const requestLogSvc = require('./services/requestLog')
const state = require('./services/state')

function start() {
  if (auditSvc.getSnapshots().length === 0) auditSvc.snapshot({ user: { username: 'system' } }, 'initial')

  const ingestResult = requestLogSvc.ingestNewEntries()
  if (ingestResult.reason) log.info(`Request log ingestion: ${ingestResult.reason}`)
  const ingestTimer = setInterval(() => {
    try { requestLogSvc.ingestNewEntries() }
    catch (e) { log.error('Request log ingestion failed', { error: e.message }) }
  }, 5000)
  ingestTimer.unref()

  try { requestLogSvc.purgeOldEntries(state.WAF.retention_days) }
  catch (e) { log.error('Request log purge failed', { error: e.message }) }
  const purgeTimer = setInterval(() => {
    try { requestLogSvc.purgeOldEntries(state.WAF.retention_days) }
    catch (e) { log.error('Request log purge failed', { error: e.message }) }
  }, 6 * 60 * 60 * 1000)
  purgeTimer.unref()

  const server = app.listen(PORT, HOST, () => {
    log.info(`CatWAF Free API listening on http://${HOST}:${PORT}`, { port: PORT, db: db.DB_PATH, version: pkgVersion })
    console.log(`[CatWAF] API    http://${HOST}:${PORT}`)
    console.log(`[CatWAF] Data   ${db.DB_PATH}`)
    console.log(`[CatWAF] Caddy  ${caddySvc.CADDYFILE_PATH}${caddySvc.CADDYFILE_SOURCE === 'auto-detected' ? ' (auto-detected)' : ''}`)
    try {
      fs.accessSync(caddySvc.CADDYFILE_PATH, fs.constants.W_OK)
    } catch {
      console.log('[CatWAF]        ⚠ not writable by this user — WAF changes will fail until that is fixed.')
      console.log('[CatWAF]          Set CADDYFILE_PATH to a Caddyfile you can write, or run as a user that can.')
    }
    if (needsBootstrap()) {
      console.log('[CatWAF] No admin account yet — run `catwaf --setup` to create one.')
    }
  })

  server.headersTimeout = 20000
  server.requestTimeout = 60000
  server.keepAliveTimeout = 10000

  for (const sig of ['SIGTERM', 'SIGINT']) {
    process.on(sig, () => {
      log.info(`Received ${sig} — shutting down`)
      server.close(() => process.exit(0))
      setTimeout(() => process.exit(0), 5000).unref()
    })
  }
}

if (require.main === module) start()

module.exports = { app, start }
