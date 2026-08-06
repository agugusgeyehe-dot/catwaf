#!/usr/bin/env node
// test/protect-e2e.test.js — proves that the configuration `catwaf auto` /
// `catwaf start` GENERATES actually puts the WAF in the request path.
//
// This is deliberately not a mock test. It runs the real generator, the
// real validate/backup/atomic-apply path, then starts a real Caddy with the
// real Coraza module and sends real HTTP requests through it:
//
//     client -> CatWAF (Caddy + Coraza + OWASP CRS) -> upstream app
//
// and asserts that a CRS payload is refused BEFORE the application sees it,
// while benign traffic is proxied normally. "Config generated" is not
// accepted as evidence of protection anywhere in this file.
//
// The upstream stands in for the discovered container; the Docker-specific
// parts (network attachment, name resolution) are covered by mocks in
// test/discovery.test.js. What is proven here is the part that cannot be
// mocked: that traffic really traverses Coraza.

const fs = require('fs')
const os = require('os')
const path = require('path')
const http = require('http')
const { execFileSync, spawn } = require('child_process')

const ROOT = path.join(__dirname, '..')
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-protect-e2e-'))
const LOG_DIR = path.join(WORK, 'logs')
const AUDIT_LOG = path.join(LOG_DIR, 'audit.json')
const CADDYFILE = path.join(WORK, 'Caddyfile')
const DB_DIR = path.join(WORK, 'db')

const APP_PORT = Number(process.env.PROTECT_APP_PORT || 19180)
const WAF_PORT = Number(process.env.PROTECT_WAF_PORT || 19181)
const ADMIN_PORT = Number(process.env.PROTECT_ADMIN_PORT || 19119)

fs.mkdirSync(LOG_DIR, { recursive: true })
fs.mkdirSync(DB_DIR, { recursive: true })

process.env.DB_DIR = DB_DIR
process.env.CADDYFILE_PATH = CADDYFILE
process.env.CADDY_ADMIN_URL = `http://127.0.0.1:${ADMIN_PORT}`
process.env.CORAZA_AUDIT_LOG = AUDIT_LOG
process.env.JWT_SECRET = 'p'.repeat(64)

let pass = 0, fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra !== undefined ? JSON.stringify(extra) : '') }
}
function section(t) { console.log('\n== ' + t + ' ==') }

function haveCaddyWithCoraza() {
  try { return execFileSync('caddy', ['list-modules'], { timeout: 8000 }).toString().includes('http.handlers.waf') }
  catch { return false }
}

function get(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { headers }, res => {
      let body = ''
      res.on('data', c => { body += c })
      res.on('end', () => resolve({ status: res.statusCode, body }))
    })
    req.on('error', reject)
    req.setTimeout(8000, () => req.destroy(new Error('timeout')))
  })
}

async function waitFor(fn, attempts = 40, delayMs = 250) {
  for (let i = 0; i < attempts; i++) {
    try { if (await fn()) return true } catch {}
    await new Promise(r => setTimeout(r, delayMs))
  }
  return false
}

// Upstream stand-in for the discovered application. Records every request
// it receives, so we can prove a blocked request never arrived.
const received = []
let appServer = null
let caddyProc = null

function cleanup() {
  try { if (caddyProc) caddyProc.kill('SIGKILL') } catch {}
  try { if (appServer) appServer.close() } catch {}
  try { fs.rmSync(WORK, { recursive: true, force: true }) } catch {}
}
process.on('exit', cleanup)
process.on('SIGINT', () => { cleanup(); process.exit(130) })

;(async () => {
  section('prerequisites')
  if (!haveCaddyWithCoraza()) {
    console.log('  SKIP  caddy with the Coraza module (http.handlers.waf) is not on PATH.')
    console.log('        This test proves real WAF blocking and cannot be faked without it.')
    console.log('\n0 passed, 0 failed, SKIPPED (no caddy+coraza)')
    process.exit(0)
  }
  check('caddy binary with the Coraza module present', true)

  appServer = http.createServer((req, res) => {
    received.push(req.url)
    res.writeHead(200, { 'Content-Type': 'text/html', 'X-Powered-By': 'PHP/8.3.28' })
    res.end('<html><body>FRESHMART-UPSTREAM-OK</body></html>')
  })
  await new Promise(r => appServer.listen(APP_PORT, '127.0.0.1', r))
  check('upstream application is listening', true)

  // A Caddyfile that already contains unrelated user configuration —
  // CatWAF must protect the app without disturbing any of it.
  const PREEXISTING = [
    '{',
    `    admin 127.0.0.1:${ADMIN_PORT}`,
    '}',
    '',
    ':19190 {',
    '    respond "UNRELATED-USER-SITE" 200',
    '}',
    '',
  ].join('\n')
  fs.writeFileSync(CADDYFILE, PREEXISTING)

  const state = require(path.join(ROOT, 'backend/services/state'))
  state.WAF.engine = 'On'
  state.WAF.paranoia_level = 1
  state.WAF.audit_log = true
  state.WAF.geo_blocking = []
  state.WAF.ip_blacklist = []

  const applySvc = require(path.join(ROOT, 'backend/services/proxy/apply.js'))
  const verifySvc = require(path.join(ROOT, 'backend/services/proxy/verify.js'))

  // Exactly the route shape proxy/routes.js produces for a discovered app.
  const route = {
    name: 'nginx',
    containerName: 'freshmart_nginx',
    containerId: 'fm1',
    listenPort: WAF_PORT,
    upstream: `127.0.0.1:${APP_PORT}`,
    upstreamBasis: 'docker-network-alias',
    runtime: 'PHP 8.3',
    framework: null,
    phpConfidence: 70,
    reachability: 'docker-internal',
    warnings: [],
  }

  section('generate -> validate -> apply (atomic, backed up)')
  const applied = applySvc.apply({ routes: [route], waf: state.WAF, dryRun: false })
  check('apply succeeded', applied.ok === true, applied)
  check('a backup was taken', typeof applied.backup === 'string' && fs.existsSync(applied.backup))

  const written = fs.readFileSync(CADDYFILE, 'utf8')
  check('unrelated user configuration was preserved', written.includes('UNRELATED-USER-SITE'))
  check('the protected route was written', written.includes(`:${WAF_PORT} {`))
  check('coraza_waf is inside the route block', written.includes('coraza_waf {'))
  check('OWASP CRS is loaded', written.includes('load_owasp_crs'))
  check('`order coraza_waf first` is present (without it requests skip Coraza)', written.includes('order coraza_waf first'))

  section('the WAF is actually in the request path')
  caddyProc = spawn('caddy', ['run', '--config', CADDYFILE], { stdio: 'ignore' })
  const up = await waitFor(async () => (await get(`http://127.0.0.1:${WAF_PORT}/`)).status === 200)
  check('CatWAF is serving the protected endpoint', up)
  if (!up) { console.log(`\n${pass} passed, ${fail + 1} failed`); process.exit(1) }

  received.length = 0

  const normal = await get(`http://127.0.0.1:${WAF_PORT}/`)
  check('benign request returns 200 through CatWAF', normal.status === 200, normal.status)
  check('benign response really came from the upstream app', normal.body.includes('FRESHMART-UPSTREAM-OK'))
  check('upstream received the benign request', received.length === 1, received)

  section('malicious traffic is blocked BEFORE reaching the application')
  const receivedBeforeAttack = received.length
  const sqli = await get(`http://127.0.0.1:${WAF_PORT}/?id=1+UNION+SELECT+1,2,3--`)
  check('CRS SQLi payload is refused with 403', sqli.status === 403, sqli.status)
  check('blocked response did not contain the app body', !sqli.body.includes('FRESHMART-UPSTREAM-OK'))
  check('the application NEVER received the blocked request', received.length === receivedBeforeAttack, received)

  const xss = await get(`http://127.0.0.1:${WAF_PORT}/?q=%3Cscript%3Ealert(1)%3C/script%3E`)
  check('CRS XSS payload is refused with 403', xss.status === 403, xss.status)
  check('the application NEVER received the XSS request', received.length === receivedBeforeAttack, received)

  const scanner = await get(`http://127.0.0.1:${WAF_PORT}/`, { 'User-Agent': 'sqlmap/1.0' })
  check('known scanner user-agent is refused with 403', scanner.status === 403, scanner.status)

  section('normal traffic still works after the blocks')
  const after = await get(`http://127.0.0.1:${WAF_PORT}/`)
  check('benign request still returns 200', after.status === 200, after.status)
  check('benign response still comes from the app', after.body.includes('FRESHMART-UPSTREAM-OK'))

  section('verify.js reaches the same verdict programmatically')
  const verification = await verifySvc.verifyRoutes([route])
  check('route is reported protected', verification.allProtected === true, verification.results)
  check('verification recorded a benign 200', verification.results[0].benignStatus === 200)
  check('verification recorded a blocked attack', verifySvc.BLOCKED_STATUSES.has(verification.results[0].attackStatus), verification.results[0])

  section('verify.js refuses to call an unprotected route protected')
  // Point a route at a listener with no WAF in front of it — the payload
  // sails through, and verification must say so rather than report success.
  const bareServer = http.createServer((req, res) => { res.writeHead(200); res.end('NO-WAF-HERE') })
  await new Promise(r => bareServer.listen(19195, '127.0.0.1', r))
  const bad = await verifySvc.verifyRoute({ name: 'unprotected', listenPort: 19195, upstream: 'x' })
  check('unprotected route is NOT reported protected', bad.protected === false, bad)
  check('reason identifies the WAF bypass', bad.wafBypassed === true, bad)
  await new Promise(r => bareServer.close(r))

  section('WAF log entries for the blocked requests')
  const auditWritten = await waitFor(() => fs.existsSync(AUDIT_LOG) && fs.statSync(AUDIT_LOG).size > 0, 40, 250)
  check('Coraza wrote a JSON audit log', auditWritten)

  const requestLog = require(path.join(ROOT, 'backend/services/requestLog'))
  requestLog._resetOffsetForTests()
  const ingest = requestLog.ingestNewEntries()
  check('CatWAF ingested the audit entries', ingest.ingested >= 3, ingest)

  const rows = requestLog.getRecent(50)
  const blocked = rows.filter(r => r.action === 'block')
  check('entries are recorded as blocked', blocked.length >= 3, { total: rows.length, blocked: blocked.length })

  const sqliRow = rows.find(r => (r.uri || '').includes('UNION'))
  check('the SQLi block was logged', !!sqliRow)
  if (sqliRow) {
    check('logged as a block with 403', sqliRow.action === 'block' && sqliRow.status === 403, sqliRow)
    check('classified as SQLi', sqliRow.attack_type === 'SQLi', sqliRow.attack_type)
    check('carries the matching CRS rule IDs', Array.isArray(sqliRow.rule_ids) && sqliRow.rule_ids.length > 0, sqliRow.rule_ids)
  }

  console.log('\n  --- WAF log entries (as `catwaf audit` would show them) ---')
  for (const r of blocked.slice(0, 5)) {
    console.log(`  [${r.ts}] ${r.action.toUpperCase()} ${r.status} ${r.method} ${r.uri}`)
    console.log(`      attack=${r.attack_type || '-'} severity=${r.severity || '-'} rules=${(r.rule_ids || []).join(',') || '-'}`)
  }

  console.log(`\n${pass} passed, ${fail} failed\n`)
  process.exit(fail ? 1 : 0)
})()
