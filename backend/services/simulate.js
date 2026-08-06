const fs = require('fs')
const os = require('os')
const net = require('net')
const path = require('path')
const http = require('http')
const { spawn, execFileSync } = require('child_process')

const state = require('./state')
const caddySvc = require('./caddy')
const rulesSvc = require('./rules')

const MAX_URL_LENGTH = 8000
const MAX_HEADER_COUNT = 60
const MAX_HEADER_VALUE = 4000
const MAX_BODY_BYTES = 256 * 1024

const SENSITIVE_HEADERS = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'set-cookie',
  'x-api-key', 'x-auth-token', 'x-catwaf-sig', 'x-csrf-token', 'x-xsrf-token',
])

const SAFE_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'])

function redactHeaders(headers) {
  const out = {}
  const redacted = []
  for (const [k, v] of Object.entries(headers || {})) {
    const key = String(k).toLowerCase()
    if (SENSITIVE_HEADERS.has(key)) { redacted.push(key); continue }
    out[key] = String(v).slice(0, MAX_HEADER_VALUE)
  }
  return { headers: out, redacted }
}

function parseTargetUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return { ok: false, error: 'A URL is required.' }
  const value = raw.trim()
  if (value.length > MAX_URL_LENGTH) return { ok: false, error: 'URL is too long.' }

  let u
  try { u = new URL(value) } catch { return { ok: false, error: `"${value}" is not a valid absolute URL.` } }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return { ok: false, error: `Unsupported scheme "${u.protocol}" — only http and https can be simulated.` }
  }
  return {
    ok: true,
    method: 'GET',
    target: (u.pathname || '/') + (u.search || ''),
    host: u.host,
    headers: {},
    body: '',
    note: 'CatWAF does not fetch this URL. Only its method, path, query string and headers are replayed through the WAF.',
  }
}

function parseRequestFile(body) {
  const text = String(body).replace(/\r\n/g, '\n')
  const split = text.indexOf('\n\n')
  const head = split === -1 ? text : text.slice(0, split)
  const rawBody = split === -1 ? '' : text.slice(split + 2)

  const lines = head.split('\n').filter(l => l.trim().length)
  if (!lines.length) return { ok: false, error: 'Request file is empty.' }

  const requestLine = lines[0].trim()
  const m = /^([A-Z]+)\s+(\S+)(?:\s+HTTP\/[\d.]+)?$/.exec(requestLine)
  if (!m) return { ok: false, error: `First line must look like "GET /path HTTP/1.1" (got: ${requestLine.slice(0, 60)})` }

  const method = m[1].toUpperCase()
  if (!SAFE_METHODS.has(method)) return { ok: false, error: `Unsupported method "${method}".` }

  const headers = {}
  let host = null
  for (const line of lines.slice(1, 1 + MAX_HEADER_COUNT)) {
    const idx = line.indexOf(':')
    if (idx === -1) continue
    const name = line.slice(0, idx).trim().toLowerCase()
    const value = line.slice(idx + 1).trim()
    if (!name) continue
    if (name === 'host') { host = value; continue }
    if (name === 'content-length' || name === 'transfer-encoding' || name === 'connection') continue
    headers[name] = value.slice(0, MAX_HEADER_VALUE)
  }

  if (Buffer.byteLength(rawBody) > MAX_BODY_BYTES) {
    return { ok: false, error: `Request body exceeds the ${MAX_BODY_BYTES} byte simulation limit.` }
  }

  return { ok: true, method, target: m[2], host, headers, body: rawBody }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.unref()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port
      srv.close(() => resolve(port))
    })
  })
}

function caddyAvailable() {
  try {
    const mods = execFileSync('caddy', ['list-modules'], { timeout: 8000 }).toString()
    return mods.includes('http.handlers.waf')
  } catch { return false }
}

function waitFor(fn, attempts = 60, delayMs = 100) {
  return new Promise(async resolve => {
    for (let i = 0; i < attempts; i++) {
      try { if (await fn()) return resolve(true) } catch {}
      await new Promise(r => setTimeout(r, delayMs))
    }
    resolve(false)
  })
}

function rawRequest({ port, method, target, host, headers, body }) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      method,
      path: target,
      headers: { ...headers, host: host || `127.0.0.1:${port}` },
      timeout: 10000,
    }, res => {
      let chunks = ''
      res.on('data', c => { chunks += c })
      res.on('end', () => resolve({ status: res.statusCode, body: chunks.slice(0, 2048) }))
    })
    req.on('error', reject)
    req.on('timeout', () => req.destroy(new Error('simulation request timed out')))
    if (body) req.write(body)
    req.end()
  })
}

async function runSandbox(request, { engineOverride = null } = {}) {
  if (!caddyAvailable()) {
    return { ok: false, unavailable: true, error: 'Caddy with the Coraza module is not available, so the WAF cannot be simulated. Simulation deliberately uses the real engine rather than approximating it.' }
  }

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-sim-'))
  const auditLog = path.join(work, 'audit.json')
  const caddyfile = path.join(work, 'Caddyfile')

  let sinkServer = null
  let caddyProc = null

  const cleanup = () => {
    try { if (caddyProc) caddyProc.kill('SIGKILL') } catch {}
    try { if (sinkServer) sinkServer.close() } catch {}
    try { fs.rmSync(work, { recursive: true, force: true }) } catch {}
  }

  try {
    const sinkPort = await freePort()
    const wafPort = await freePort()
    const adminPort = await freePort()

    let reachedUpstream = false
    sinkServer = http.createServer((req, res) => {
      reachedUpstream = true
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      res.end('catwaf-simulation-sink')
    })
    await new Promise((resolve, reject) => {
      sinkServer.on('error', reject)
      sinkServer.listen(sinkPort, '127.0.0.1', resolve)
    })

    const simWaf = JSON.parse(JSON.stringify(state.WAF))
    simWaf.audit_log = true
    if (engineOverride) simWaf.engine = engineOverride

    const originalPath = caddySvc.CADDYFILE_PATH
    const originalAudit = caddySvc.AUDIT_LOG_PATH

    fs.writeFileSync(caddyfile, [
      '{',
      `    admin 127.0.0.1:${adminPort}`,
      '    order coraza_waf first',
      '}',
      '',
      `:${wafPort} {`,
      `    reverse_proxy 127.0.0.1:${sinkPort}`,
      '}',
      '',
    ].join('\n'))

    // `backend: null` renders the block without the hops back into CatWAF's
    // own API (the challenge endpoints and the `forward_auth` enforcement
    // hop). This sandbox is a private Caddy with no CatWAF behind it, so
    // those hops cannot be answered and Caddy would return 502 for every
    // request that Coraza allowed — making a benign request look like it had
    // been stopped. What is being simulated here is Coraza + the CRS.
    const block = caddySvc.buildWAFBlock(simWaf, { backend: null, recordReport: false }).replace(
      new RegExp(escapeRegExp(originalAudit), 'g'), auditLog
    )
    const body = fs.readFileSync(caddyfile, 'utf8')
    const lastBrace = body.lastIndexOf('}')
    fs.writeFileSync(caddyfile, body.slice(0, lastBrace) + '\n' + block + '\n' + body.slice(lastBrace), 'utf8')

    caddyProc = spawn('caddy', ['run', '--config', caddyfile], { stdio: 'ignore' })

    const up = await waitFor(async () => {
      try {
        const r = await rawRequest({ port: wafPort, method: 'GET', target: '/__catwaf_sim_probe', host: null, headers: {}, body: '' })
        return r.status > 0
      } catch { return false }
    })
    if (!up) { cleanup(); return { ok: false, error: 'The simulation sandbox did not start in time.' } }

    reachedUpstream = false
    const response = await rawRequest({
      port: wafPort,
      method: request.method,
      target: request.target,
      host: request.host,
      headers: request.headers,
      body: request.body,
    })

    await new Promise(r => setTimeout(r, 400))

    let events = []
    try {
      const raw = fs.readFileSync(auditLog, 'utf8')
      const requestLog = require('./requestLog')
      events = raw.split('\n').filter(Boolean)
        .map(l => requestLog.parseAuditEntry(l))
        .filter(Boolean)
        .filter(e => !String(e.uri || '').includes('__catwaf_sim_probe'))
    } catch {}

    cleanup()

    const blocked = response.status === 403 || events.some(e => e.action === 'block')
    const event = events[events.length - 1] || null
    const ruleIds = event ? JSON.parse(event.rule_ids || '[]') : []

    return {
      ok: true,
      simulation: true,
      blocked,
      upstreamReached: reachedUpstream && !blocked,
      status: response.status,
      matched_rules: ruleIds.map(id => rulesSvc.describe(id)),
      rule_ids: ruleIds,
      attack_type: event?.attack_type || null,
      severity: event?.severity || null,
      anomaly_score: event?.score ?? null,
      reason: event?.reason || null,
      paranoia_level: simWaf.paranoia_level,
      engine: simWaf.engine,
      inbound_anomaly_threshold: simWaf.inbound_anomaly_threshold,
    }
  } catch (e) {
    cleanup()
    return { ok: false, error: e.message }
  }
}

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

async function simulate({ url = null, file = null, requestText = null, engineOverride = null } = {}) {
  let parsed
  if (url) parsed = parseTargetUrl(url)
  else if (requestText != null) parsed = parseRequestFile(requestText)
  else if (file) {
    let body
    try { body = fs.readFileSync(file, 'utf8') } catch (e) { return { ok: false, error: `Cannot read request file: ${e.message}` } }
    parsed = parseRequestFile(body)
  } else {
    return { ok: false, error: 'Provide --url or --request <file>.' }
  }

  if (!parsed.ok) return { ok: false, error: parsed.error }

  const { headers, redacted } = redactHeaders(parsed.headers)
  const request = { ...parsed, headers }

  const result = await runSandbox(request, { engineOverride })
  if (!result.ok) return result

  return {
    ...result,
    request: {
      method: request.method,
      target: request.target,
      host: request.host || null,
      headers,
      redacted_headers: redacted,
      body_bytes: Buffer.byteLength(request.body || ''),
    },
    note: parsed.note || 'Evaluated by a throwaway Caddy + Coraza instance against a local sink. Your real upstream was never contacted.',
  }
}

module.exports = {
  simulate, runSandbox, parseTargetUrl, parseRequestFile, redactHeaders,
  caddyAvailable, SENSITIVE_HEADERS,
}
