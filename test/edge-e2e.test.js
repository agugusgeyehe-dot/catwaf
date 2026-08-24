#!/usr/bin/env node

// Real end-to-end proof that an edge-rendered ban aborts connections at
// Caddy BEFORE they ever reach the origin/WAF behind it.
//
// Unlike waf-e2e.test.js this exercises ENFORCEMENT, not rendering: the
// Caddyfile below is hand-written (the renderer that produces exactly this
// region is covered by features.test.js via backend/services/edgeBans.js),
// so plain Caddy — with or without the Coraza module — is enough to run.

const fs = require('fs')
const os = require('os')
const path = require('path')
const http = require('http')
const { execFileSync, spawn } = require('child_process')

const ROOT = path.join(__dirname, '..')
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-edge-e2e-'))
const CADDYFILE = path.join(WORK, 'Caddyfile')

const APP_PORT = Number(process.env.E2E_APP_PORT || 19180)
const EDGE_PORT = Number(process.env.E2E_EDGE_PORT || 19181)
const ADMIN_PORT = Number(process.env.E2E_ADMIN_PORT || 19119)

// Any 127.0.0.0/8 address is local on Linux, so we can source requests
// from a second loopback identity without root.
const BANNED_SOURCE = '127.0.0.2'
const APP_MARKER = 'CATWAF SECURITY TEST ENVIRONMENT'

let pass = 0, fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra !== undefined ? JSON.stringify(extra) : '') }
}
function section(t) { console.log('\n== ' + t + ' ==') }

function resolveCaddy() {
  for (const candidate of ['caddy', path.join(ROOT, 'bin', 'vendor', 'caddy')]) {
    try { execFileSync(candidate, ['version'], { timeout: 8000 }); return candidate } catch {}
  }
  return null
}

function get(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { headers }, res => {
      let body = ''
      res.on('data', c => { body += c })
      res.on('end', () => resolve({ status: res.statusCode, body }))
    })
    req.on('error', reject)
    req.setTimeout(8000, () => { req.destroy(new Error('timeout')) })
  })
}

// A single GET pinned to a specific local source address. Never rejects —
// transport failures come back as { kind: 'error' } so callers can classify.
function getFrom(localAddress, port, pathStr = '/') {
  return new Promise(resolve => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: pathStr,
      method: 'GET',
      localAddress,
    }, res => {
      let body = ''
      res.on('data', c => { body += c })
      res.on('end', () => resolve({ kind: 'response', status: res.statusCode, body }))
    })
    req.on('error', err => resolve({ kind: 'error', code: err.code || String(err) }))
    req.setTimeout(8000, () => req.destroy())
    req.end()
  })
}

// `abort` closes the connection without writing a status line, so a real
// edge-banned client sees ECONNRESET / empty reply / garbage — never a
// clean answer from the app. EADDRNOTAVAIL is the one outcome that means
// our harness couldn't source from 127.0.0.2, so it counts as failure.
function isAborted(result) {
  if (result.kind === 'error') return result.code !== 'EADDRNOTAVAIL'
  if (result.kind === 'response') return result.status !== 200 || !result.body.includes(APP_MARKER)
  return false
}

async function waitFor(fn, attempts = 40, delayMs = 250) {
  for (let i = 0; i < attempts; i++) {
    try { if (await fn()) return true } catch {}
    await new Promise(r => setTimeout(r, delayMs))
  }
  return false
}

// Mirrors the shape backend/services/edgeBans.js renders (buildBlock()):
// named remote_ip matcher + `abort` handle, with the proxy in a sibling
// handle so unmatched traffic falls through to the origin.
function renderCaddyfile(withBan) {
  const lines = [
    '{',
    `    admin 127.0.0.1:${ADMIN_PORT}`,
    '}',
    '',
    `:${EDGE_PORT} {`,
  ]
  if (withBan) {
    lines.push(
      `    @catwaf_edge_bans remote_ip ${BANNED_SOURCE}`,
      '    handle @catwaf_edge_bans {',
      '        abort',
      '    }',
    )
  }
  lines.push(
    '    handle {',
    `        reverse_proxy 127.0.0.1:${APP_PORT}`,
    '    }',
    '}',
    '',
  )
  return lines.join('\n')
}

let appProc = null
let caddyProc = null

function cleanup() {
  try { if (caddyProc) caddyProc.kill('SIGKILL') } catch {}
  try { if (appProc) appProc.kill('SIGKILL') } catch {}
  try { fs.rmSync(WORK, { recursive: true, force: true }) } catch {}
}
process.on('exit', cleanup)
process.on('SIGINT', () => { cleanup(); process.exit(130) })
process.on('SIGTERM', () => { cleanup(); process.exit(143) })

;(async () => {
  section('prerequisites')
  const caddyBin = resolveCaddy()
  if (!caddyBin) {
    console.log('  SKIP  no caddy binary found (looked at `caddy` and bin/vendor/caddy).')
    console.log('        This test proves real edge enforcement and cannot be faked without it.')
    console.log('        Install it: npm install   (or see docs/installation.md)')
    console.log('\n0 passed, 0 failed, SKIPPED (no caddy)')
    process.exit(0)
  }
  check(`caddy binary present (${caddyBin})`, true)

  appProc = spawn(process.execPath, [path.join(ROOT, 'test', 'testapp', 'server.js')], {
    env: { ...process.env, TEST_APP_PORT: String(APP_PORT), TEST_APP_HOST: '127.0.0.1' },
    stdio: 'ignore',
  })
  const appUp = await waitFor(async () => (await get(`http://127.0.0.1:${APP_PORT}/healthz`)).status === 200)
  check('local-only test app is listening', appUp)
  if (!appUp) { console.log('\n' + pass + ' passed, ' + (fail + 1) + ' failed'); process.exit(1) }

  fs.writeFileSync(CADDYFILE, renderCaddyfile(true))

  caddyProc = spawn(caddyBin, ['run', '--config', CADDYFILE, '--adapter', 'caddyfile'], { stdio: 'ignore' })
  const edgeUp = await waitFor(async () => {
    const r = await get(`http://127.0.0.1:${EDGE_PORT}/`)
    return r.status === 200
  })
  check('caddy is serving the site with the edge-ban region active', edgeUp)
  if (!edgeUp) { console.log('\n' + pass + ' passed, ' + (fail + 1) + ' failed'); process.exit(1) }

  section('unbanned traffic reaches the application')
  const allowed = await get(`http://127.0.0.1:${EDGE_PORT}/`)
  check('request from 127.0.0.1 returns 200', allowed.status === 200, allowed.status)
  check('response really came from the test app', allowed.body.includes(APP_MARKER))

  section('banned source is aborted at the edge')
  const attempts = [1, 2, 3].map(i => getFrom(BANNED_SOURCE, EDGE_PORT).then(r => ({ i, r })))
  const results = await Promise.all(attempts)
  for (const { i, r } of results) {
    check(`banned-source request ${i} was aborted (reset/empty/non-200)`, isAborted(r), r.kind === 'error' ? r.code : { status: r.status, len: r.body && r.body.length })
  }
  const leaked = results.filter(({ r }) =>
    r.kind === 'response' && r.status === 200 && r.body.includes(APP_MARKER))
  check('no banned request saw the application body', leaked.length === 0)

  section('ban is targeted, not blanket')
  const otherDuringBan = await get(`http://127.0.0.1:${EDGE_PORT}/`)
  check('127.0.0.1 still gets 200 while the ban is active', otherDuringBan.status === 200, otherDuringBan.status)

  section('lifting the ban propagates without restarting Caddy')
  fs.writeFileSync(CADDYFILE, renderCaddyfile(false))
  let reloaded = true
  try {
    execFileSync(caddyBin, ['reload', '--config', CADDYFILE, '--adapter', 'caddyfile'], { timeout: 15000, stdio: 'ignore' })
  } catch (e) {
    reloaded = false
    console.log('  reload error:', e.message)
  }
  check('caddy reload accepted the lifted config', reloaded)

  const restored = await waitFor(async () => {
    const r = await getFrom(BANNED_SOURCE, EDGE_PORT)
    return r.kind === 'response' && r.status === 200 && r.body.includes(APP_MARKER)
  })
  check('previously banned source reaches the app again after reload', restored)
  const stillServing = await get(`http://127.0.0.1:${EDGE_PORT}/`)
  check('unbanned traffic unaffected after reload', stillServing.status === 200, stillServing.status)

  console.log(`\n${pass} passed, ${fail} failed`)
  cleanup()
  process.exit(fail ? 1 : 0)
})().catch(e => {
  console.error('\nEdge E2E harness error:', e.message)
  cleanup()
  process.exit(1)
})
