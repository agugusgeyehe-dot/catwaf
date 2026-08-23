#!/usr/bin/env node

// End-to-end tests for upload malware scanning: the clamd client's wire
// protocol, and the /api/upload-gate hop that sits inline for upload paths.
//
// The gate is the only place CatWAF is in the data path, so the properties
// that matter are behavioural, not structural: infected uploads must not
// reach the origin, clean ones must arrive byte-for-byte, and the endpoint
// must not be usable as a general-purpose proxy by anything that gets to the
// port. A mock clamd speaking the real protocol stands in for the daemon so
// the suite needs no ClamAV install.

const fs = require('fs')
const os = require('os')
const net = require('net')
const path = require('path')
const http = require('http')

const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-upload-'))
process.env.DB_DIR = path.join(WORK, 'db')
process.env.CADDYFILE_PATH = path.join(WORK, 'Caddyfile')
process.env.CORAZA_AUDIT_LOG = path.join(WORK, 'audit.json')
process.env.JWT_SECRET = 'f'.repeat(64)
process.env.CATWAF_SECRET = 'c'.repeat(64)

// Never let a config reload reach a Caddy running on this machine.
// `reloadCaddy()` POSTs to CADDY_ADMIN_URL, which defaults to Caddy's real
// admin port — running the suite on a host where CatWAF is live would replace
// that Caddy's configuration with this file's fixture and take the site down.
process.env.CADDY_ADMIN_URL = process.env.CADDY_ADMIN_URL || 'http://127.0.0.1:19918'
fs.mkdirSync(process.env.DB_DIR, { recursive: true })
fs.mkdirSync(path.join(WORK, 'logs'), { recursive: true })
fs.writeFileSync(process.env.CORAZA_AUDIT_LOG, '')

let pass = 0, fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra !== undefined ? JSON.stringify(extra) : '') }
}
function section(t) { console.log('\n== ' + t + ' ==') }

process.on('exit', () => { try { fs.rmSync(WORK, { recursive: true, force: true }) } catch {} })

const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

// ─── Mock clamd, speaking the real protocol ─────────────────────────────

function startClamd({ hang = false } = {}) {
  const received = []
  const server = net.createServer(sock => {
    let buf = Buffer.alloc(0)
    let streaming = false
    let payload = Buffer.alloc(0)
    sock.on('data', chunk => {
      buf = Buffer.concat([buf, chunk])
      if (!streaming) {
        const nul = buf.indexOf(0)
        if (nul === -1) return
        const cmd = buf.subarray(0, nul).toString()
        buf = buf.subarray(nul + 1)
        if (hang) return
        if (cmd === 'zPING') return void sock.end('PONG\0')
        if (cmd === 'zVERSION') return void sock.end('ClamAV 1.0.0\0')
        if (cmd !== 'zINSTREAM') return void sock.end('UNKNOWN COMMAND ERROR\0')
        streaming = true
      }
      while (buf.length >= 4) {
        const len = buf.readUInt32BE(0)
        if (len === 0) {
          received.push(payload)
          streaming = false
          return void sock.end(payload.toString('latin1').includes(EICAR)
            ? 'stream: Eicar-Test-Signature FOUND\0'
            : 'stream: OK\0')
        }
        if (buf.length < 4 + len) return
        payload = Buffer.concat([payload, buf.subarray(4, 4 + len)])
        buf = buf.subarray(4 + len)
      }
    })
    sock.on('error', () => {})
  })
  return { server, received }
}

// ─── Mock origin behind the scanner ─────────────────────────────────────

function startOrigin() {
  const seen = []
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, body: Buffer.concat(chunks), headers: req.headers })
      res.writeHead(201, { 'content-type': 'text/plain', 'x-origin': 'yes' })
      res.end('stored')
    })
  })
  return { server, seen }
}

function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)))
}

function request(port, opts, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, ...opts }, res => {
      const chunks = []
      res.on('data', c => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }))
    })
    req.on('error', reject)
    req.end(body)
  })
}

;(async () => {
  const clamav = require('../backend/services/clamav')

  // ─── clamd client ─────────────────────────────────────────────────────
  section('clamd client')
  const clamd = startClamd()
  const clamdPort = await listen(clamd.server)
  const clamCfg = { host: '127.0.0.1', port: clamdPort }

  check('PING is answered', await clamav.ping(clamCfg) === true)
  check('availability is detected', (await clamav.available({ force: true, cfg: clamCfg })).available === true)

  const cleanScan = await clamav.scanBuffer(Buffer.from('harmless'), clamCfg)
  check('a clean buffer scans clean', cleanScan.clean === true && cleanScan.error === null, cleanScan)

  const dirtyScan = await clamav.scanBuffer(Buffer.from(EICAR), clamCfg)
  check('EICAR is reported with its signature name',
    dirtyScan.clean === false && dirtyScan.virus === 'Eicar-Test-Signature', dirtyScan)

  // Framing: a payload spanning several INSTREAM chunks must arrive intact,
  // or a signature straddling a boundary would be missed.
  clamd.received.length = 0
  const spanning = Buffer.concat([Buffer.alloc(clamav.CHUNK_BYTES * 2 + 7, 0x41), Buffer.from(EICAR)])
  const spanningScan = await clamav.scanBuffer(spanning, clamCfg)
  check('a multi-chunk body reaches clamd byte-for-byte',
    clamd.received[0] && clamd.received[0].equals(spanning))
  check('malware past a chunk boundary is still found', spanningScan.clean === false)

  const unreachable = await clamav.scanBuffer(Buffer.from('x'), { host: '127.0.0.1', port: 1 })
  check('an unreachable daemon is an error, never a clean verdict',
    unreachable.clean === null && !!unreachable.error, unreachable)

  check('an ERROR reply is not read as clean', clamav.interpret('INSTREAM size limit exceeded. ERROR').clean === null)
  check('an empty reply is not read as clean', clamav.interpret('').clean === null)
  check('an unrecognised reply is not read as clean', clamav.interpret('what').clean === null)

  // ─── The inline gate ──────────────────────────────────────────────────
  section('upload gate')

  const origin = startOrigin()
  const originPort = await listen(origin.server)
  const upstream = `127.0.0.1:${originPort}`

  // The gate only forwards to upstreams this Caddyfile actually proxies to.
  fs.writeFileSync(process.env.CADDYFILE_PATH, `{\n}\n\nexample.com {\n    reverse_proxy ${upstream}\n}\n`)

  const settings = require('../backend/services/settings')
  const secrets = require('../backend/services/secrets')
  settings.set('upload_scan', {
    enabled: true,
    host: '127.0.0.1',
    port: clamdPort,
    action: 'block',
    fail_open: true,
    max_scan_bytes: 1024 * 1024,
  })

  const express = require('express')
  const app = express()
  app.use(require('../backend/routes/gateway'))
  const gate = http.createServer(app)
  const gatePort = await listen(gate)

  const KEY = secrets.derive('upload-gate-key')
  const gateHeaders = (extra = {}) => ({
    'x-catwaf-upload-key': KEY,
    'x-catwaf-upload-upstream': upstream,
    'x-catwaf-upload-path': '/upload/file',
    'content-type': 'application/octet-stream',
    ...extra,
  })

  // A clean upload must reach the origin unchanged.
  origin.seen.length = 0
  const cleanBody = 'a perfectly ordinary file'
  const cleanRes = await request(gatePort, { method: 'POST', path: '/api/upload-gate', headers: gateHeaders() }, cleanBody)
  check('a clean upload gets the origin\'s response', cleanRes.status === 201 && cleanRes.body === 'stored', cleanRes)
  check('the origin\'s headers are passed back', cleanRes.headers['x-origin'] === 'yes')
  check('the clean verdict is reported', cleanRes.headers['x-catwaf-verdict'] === 'upload-clean', cleanRes.headers)
  check('the origin received the body intact', origin.seen[0]?.body.toString() === cleanBody)
  check('the original path is restored on the way to the origin', origin.seen[0]?.url === '/upload/file', origin.seen[0]?.url)
  check('the method is preserved', origin.seen[0]?.method === 'POST')
  check('CatWAF\'s control headers are stripped before the origin sees them',
    origin.seen[0] && !Object.keys(origin.seen[0].headers).some(h => h.startsWith('x-catwaf-')),
    origin.seen[0] && Object.keys(origin.seen[0].headers))

  // An infected upload must be refused, and must never reach the origin.
  origin.seen.length = 0
  const dirtyRes = await request(gatePort, { method: 'POST', path: '/api/upload-gate', headers: gateHeaders() }, EICAR)
  check('an infected upload is refused with 403', dirtyRes.status === 403, dirtyRes)
  check('the malware verdict is reported', dirtyRes.headers['x-catwaf-verdict'] === 'upload-malware')
  check('the signature name is in the response', dirtyRes.body.includes('Eicar-Test-Signature'), dirtyRes.body)
  check('an infected upload never reaches the origin', origin.seen.length === 0, origin.seen.length)

  // PUT and PATCH go through the same gate, so they must be handled too.
  origin.seen.length = 0
  const putRes = await request(gatePort, { method: 'PUT', path: '/api/upload-gate', headers: gateHeaders() }, EICAR)
  check('an infected PUT is refused as well', putRes.status === 403, putRes)
  const putClean = await request(gatePort, { method: 'PUT', path: '/api/upload-gate', headers: gateHeaders() }, 'fine')
  check('a clean PUT is forwarded with its method intact',
    putClean.status === 201 && origin.seen.at(-1)?.method === 'PUT', origin.seen.at(-1)?.method)

  // ─── The gate must not be a proxy for anything else ───────────────────
  section('upload gate is not an open proxy')

  const wrongKey = await request(gatePort, { method: 'POST', path: '/api/upload-gate', headers: gateHeaders({ 'x-catwaf-upload-key': 'nope' }) }, 'x')
  check('a wrong key is refused', wrongKey.status === 404, wrongKey.status)

  const noKey = await request(gatePort, { method: 'POST', path: '/api/upload-gate', headers: { 'x-catwaf-upload-upstream': upstream } }, 'x')
  check('a missing key is refused', noKey.status === 404, noKey.status)

  // Even holding the key, the upstream is checked against the Caddyfile —
  // otherwise the header would turn this endpoint into an SSRF pivot.
  const evil = startOrigin()
  const evilPort = await listen(evil.server)
  const ssrf = await request(gatePort, {
    method: 'POST', path: '/api/upload-gate',
    headers: gateHeaders({ 'x-catwaf-upload-upstream': `127.0.0.1:${evilPort}` }),
  }, 'x')
  check('an upstream this instance does not proxy to is refused', ssrf.status === 502, ssrf.status)
  check('the unlisted upstream is never contacted', evil.seen.length === 0)

  const noUpstream = await request(gatePort, {
    method: 'POST', path: '/api/upload-gate',
    headers: { 'x-catwaf-upload-key': KEY, 'x-catwaf-upload-path': '/upload' },
  }, 'x')
  check('a missing upstream is refused', noUpstream.status === 502, noUpstream.status)

  // ─── Scanner unavailable: fail open vs fail closed ────────────────────
  section('scanner availability policy')

  settings.set('upload_scan', { host: '127.0.0.1', port: 1, fail_open: true })
  origin.seen.length = 0
  const failOpen = await request(gatePort, { method: 'POST', path: '/api/upload-gate', headers: gateHeaders() }, 'payload')
  check('fail_open lets an unscannable upload reach the origin', failOpen.status === 201, failOpen.status)
  check('the origin still got the body', origin.seen[0]?.body.toString() === 'payload')

  settings.set('upload_scan', { fail_open: false })
  origin.seen.length = 0
  const failClosed = await request(gatePort, { method: 'POST', path: '/api/upload-gate', headers: gateHeaders() }, 'payload')
  check('fail_open off refuses an upload that could not be scanned', failClosed.status === 503, failClosed.status)
  check('nothing reached the origin when failing closed', origin.seen.length === 0)

  // ─── Oversize bodies ──────────────────────────────────────────────────
  section('bodies too large to scan')

  settings.set('upload_scan', { host: '127.0.0.1', port: clamdPort, fail_open: true, max_scan_bytes: 1024, oversize_action: 'block' })
  const tooBig = await request(gatePort, { method: 'POST', path: '/api/upload-gate', headers: gateHeaders() }, 'z'.repeat(5000))
  check('an oversize body is refused when the policy says block', tooBig.status === 413, tooBig.status)

  settings.set('upload_scan', { oversize_action: 'pass' })
  origin.seen.length = 0
  const bigBody = 'z'.repeat(5000)
  const passed = await request(gatePort, { method: 'POST', path: '/api/upload-gate', headers: gateHeaders() }, bigBody)
  check('an oversize body is forwarded when the policy says pass', passed.status === 201, passed.status)
  check('an oversize body is forwarded in full, not truncated to the scan limit',
    origin.seen[0]?.body.length === bigBody.length, origin.seen[0]?.body.length)

  // ─── Disabled ─────────────────────────────────────────────────────────
  section('disabled')
  settings.set('upload_scan', { enabled: false })
  origin.seen.length = 0
  const off = await request(gatePort, { method: 'POST', path: '/api/upload-gate', headers: gateHeaders() }, EICAR)
  check('with scanning off the gate just forwards', off.status === 201, off.status)
  check('nothing is scanned when disabled', origin.seen[0]?.body.toString() === EICAR)

  // ─── Rendering ────────────────────────────────────────────────────────
  section('Caddyfile rendering')
  const site = require('../backend/services/render/site')
  const { defaultsFor } = require('../backend/services/settings/schema')
  const withScan = { get: g => (g === 'upload_scan' ? { ...defaultsFor('upload_scan'), enabled: true } : defaultsFor(g)) }

  const rendered = site.build({ settings: withScan, upstreams: ['127.0.0.1:8080'], backend: '127.0.0.1:5000' })
  const text = rendered.lines.join('\n')
  check('the gate is rendered when enabled', text.includes('@catwaf_uploadscan'))
  check('it routes to CatWAF, not the origin', text.includes('reverse_proxy "127.0.0.1:5000"'))
  check('it carries the upstream onward', text.includes('X-CatWAF-Upload-Upstream "127.0.0.1:8080"'))
  check('it rewrites to the gate path', text.includes('rewrite "/api/upload-gate"'))

  const offRender = site.build({ settings: { get: defaultsFor }, upstreams: ['127.0.0.1:8080'], backend: '127.0.0.1:5000' })
  check('nothing is rendered when disabled', !offRender.lines.join('\n').includes('uploadscan'))

  // With no upstream there is nowhere to forward to, so the gate must be
  // skipped rather than black-holing every upload.
  const noUp = site.build({ settings: withScan, upstreams: [], backend: '127.0.0.1:5000' })
  check('the gate is skipped when the site has no upstream',
    !noUp.lines.join('\n').includes('uploadscan') && noUp.skipped.some(s => s.feature === 'upload_scan'), noUp.skipped)

  const noBackend = site.build({ settings: withScan, upstreams: ['127.0.0.1:8080'], backend: null })
  check('the gate is skipped when CatWAF\'s own address is unknown',
    !noBackend.lines.join('\n').includes('uploadscan') && noBackend.skipped.some(s => s.feature === 'upload_scan'))

  clamd.server.close(); origin.server.close(); evil.server.close(); gate.close()

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
})().catch(e => { console.error(e); process.exit(1) })
