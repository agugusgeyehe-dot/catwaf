#!/usr/bin/env node
//
// Proves, against a real running site, that CatWAF's Sensitive File Level
// (SFL) feature actually blocks sensitive files — and that higher levels are
// strictly cumulative (SFL2 ⊇ SFL1, SFL3 ⊇ SFL2, SFL4 ⊇ SFL3), the way the
// docs describe them. This is a regression test for two historical bugs:
//   1. wordlist-derived path patterns had no leading "/", so Caddy's `path`
//      matcher never matched a real request and SFL1-3 blocked nothing.
//   2. the SFL4 branch emitted an unbalanced brace, producing a Caddyfile
//      Caddy could not load at all.
//
// Same pattern as test/waf-e2e.test.js: real caddy binary, real local-only
// test app, real production code from backend/services/sensitive.js — no
// mocking.

const fs = require('fs')
const os = require('os')
const path = require('path')
const http = require('http')
const { execFileSync, spawn } = require('child_process')

const ROOT = path.join(__dirname, '..')
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-sfl-e2e-'))
const DB_DIR = path.join(WORK, 'db')
const CADDYFILE = path.join(WORK, 'Caddyfile')
const CORAZA_LIST_DIR = path.join(WORK, 'coraza-lists')

const APP_PORT = Number(process.env.SFL_E2E_APP_PORT || 19180)
const WAF_PORT = Number(process.env.SFL_E2E_WAF_PORT || 19199)
const ADMIN_PORT = Number(process.env.SFL_E2E_ADMIN_PORT || 19119)
const ADMIN_URL = `http://127.0.0.1:${ADMIN_PORT}`

fs.mkdirSync(DB_DIR, { recursive: true })
fs.mkdirSync(CORAZA_LIST_DIR, { recursive: true })

process.env.DB_DIR = DB_DIR
process.env.CADDYFILE_PATH = CADDYFILE
process.env.CADDY_ADMIN_URL = ADMIN_URL
process.env.CORAZA_LIST_DIR = CORAZA_LIST_DIR
process.env.JWT_SECRET = 'e'.repeat(64)

let pass = 0, fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra !== undefined ? JSON.stringify(extra) : '') }
}
function section(t) { console.log('\n== ' + t + ' ==') }

function haveCaddy() {
  try {
    execFileSync('caddy', ['version'], { timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] })
    return true
  } catch { return false }
}

function get(urlPath, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get(`http://127.0.0.1:${WAF_PORT}${urlPath}`, { headers }, res => {
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

let appProc = null, caddyProc = null
function cleanup() {
  try { if (appProc) appProc.kill('SIGKILL') } catch {}
  try { if (caddyProc) caddyProc.kill('SIGKILL') } catch {}
  try { fs.rmSync(WORK, { recursive: true, force: true }) } catch {}
}
process.on('exit', cleanup)
process.on('SIGINT', () => { cleanup(); process.exit(130) })

async function isBlocked(urlPath) {
  const r = await get(urlPath)
  return r.status === 403 && r.body.includes('You have been blocked by CatWAF')
}
async function reachesApp(urlPath) {
  const r = await get(urlPath)
  return r.status === 200 && r.body.includes('CATWAF SECURITY TEST ENVIRONMENT')
}

;(async () => {
  section('prerequisites')
  if (!haveCaddy()) {
    console.log('  SKIP  caddy is not on PATH.')
    console.log('        This test proves real SFL blocking and cannot be faked without it.')
    console.log('\n0 passed, 0 failed, SKIPPED (no caddy)')
    process.exit(0)
  }
  check('caddy binary present', true)

  appProc = spawn(process.execPath, [path.join(ROOT, 'test', 'testapp', 'server.js')], {
    env: { ...process.env, TEST_APP_PORT: String(APP_PORT), TEST_APP_HOST: '127.0.0.1' },
    stdio: 'ignore',
  })
  const appHealthy = await waitFor(async () => {
    return await new Promise((resolve, reject) => {
      const req = http.get(`http://127.0.0.1:${APP_PORT}/healthz`, r => resolve(r.statusCode === 200))
      req.on('error', reject)
    })
  })
  check('local-only test app is listening', appHealthy)
  if (!appHealthy) { console.log('\n' + pass + ' passed, ' + (fail + 1) + ' failed'); process.exit(1) }

  fs.writeFileSync(CADDYFILE, [
    '{',
    `    admin 127.0.0.1:${ADMIN_PORT}`,
    '}',
    '',
    `:${WAF_PORT} {`,
    `    reverse_proxy 127.0.0.1:${APP_PORT}`,
    '}',
    '',
  ].join('\n'))

  caddyProc = spawn('caddy', ['run', '--config', CADDYFILE], { stdio: 'ignore' })
  const wafUp = await waitFor(async () => (await get('/')).status === 200)
  check('caddy is proxying to the test app', wafUp)
  if (!wafUp) { console.log('\n' + pass + ' passed, ' + (fail + 1) + ' failed'); process.exit(1) }

  const sensitiveSvc = require(path.join(ROOT, 'backend/services/sensitive'))
  const caddySvc = require(path.join(ROOT, 'backend/services/caddy'))

  async function applyLevel(level, blocked = []) {
    const state = { sfl_level: level, blocked }
    sensitiveSvc.saveSensitiveState(state)
    sensitiveSvc.patchCaddyfile(state)
    const result = caddySvc.reloadCaddy()
    await new Promise(r => setTimeout(r, 300))
    return result
  }

  section('cumulativeSflPaths() is a strict superset chain (SFL2 ⊇ SFL1 ⊇ ..., pure function, all ~1500 paths)')
  const l1 = new Set(sensitiveSvc.cumulativeSflPaths(1))
  const l2 = new Set(sensitiveSvc.cumulativeSflPaths(2))
  const l3 = new Set(sensitiveSvc.cumulativeSflPaths(3))
  const l4 = new Set(sensitiveSvc.cumulativeSflPaths(4))
  const isSubset = (a, b) => [...a].every(x => b.has(x))

  check('SFL1 is non-empty', l1.size > 0, l1.size)
  check('SFL1 ⊆ SFL2', isSubset(l1, l2))
  check('SFL2 ⊆ SFL3', isSubset(l2, l3))
  check('SFL3 ⊆ SFL4', isSubset(l3, l4))
  check('SFL2 is not smaller than SFL1', l2.size >= l1.size, { l1: l1.size, l2: l2.size })
  check('SFL3 is not smaller than SFL2', l3.size >= l2.size, { l2: l2.size, l3: l3.size })
  check('SFL4 is not smaller than SFL3', l4.size >= l3.size, { l3: l3.size, l4: l4.size })
  for (const [lvl, set] of [[1, l1], [2, l2], [3, l3], [4, l4]]) {
    check(`/.env present in cumulative SFL${lvl}`, set.has('/.env'))
    check(`/.gitignore present in cumulative SFL${lvl}`, set.has('/.gitignore'))
  }
  check('every cumulative path has a leading slash', [...l4].every(p => p.startsWith('/')))

  section('SFL1 — blocks .env/.gitignore on a real request; normal traffic unaffected')
  await applyLevel(1)
  check('/ is allowed', await reachesApp('/'))
  check('/.env is blocked', await isBlocked('/.env'))
  check('/.gitignore is blocked', await isBlocked('/.gitignore'))

  section('SFL2 — still blocks .env/.gitignore (cumulative) plus a level-2-only path')
  await applyLevel(2)
  check('/ is allowed', await reachesApp('/'))
  check('/.env is still blocked at SFL2', await isBlocked('/.env'))
  check('/.gitignore is still blocked at SFL2', await isBlocked('/.gitignore'))
  check('/UploadDemo (SFL2-introduced) is blocked', await isBlocked('/UploadDemo'))

  section('SFL3 — still blocks .env/.gitignore (cumulative) plus a level-3-only path')
  await applyLevel(3)
  check('/ is allowed', await reachesApp('/'))
  check('/.env is still blocked at SFL3', await isBlocked('/.env'))
  check('/.gitignore is still blocked at SFL3', await isBlocked('/.gitignore'))
  check('/passwords (SFL3-introduced) is blocked', await isBlocked('/passwords'))

  section('SFL4 — still blocks .env/.gitignore (cumulative) plus level-4-only paths; config stays valid')
  const sfl4Result = await applyLevel(4)
  check('reloadCaddy() succeeded at SFL4 (regression: used to corrupt the Caddyfile)', sfl4Result.reloaded === true, sfl4Result)
  check('/ is allowed', await reachesApp('/'))
  check('/.env is still blocked at SFL4', await isBlocked('/.env'))
  check('/.gitignore is still blocked at SFL4', await isBlocked('/.gitignore'))
  check('/.git/config (SFL4-introduced) is blocked', await isBlocked('/.git/config'))
  check('/.htpasswd (SFL4-introduced) is blocked', await isBlocked('/.htpasswd'))
  check('/id_rsa (SFL4-introduced) is blocked', await isBlocked('/id_rsa'))

  let validateOk = false
  try {
    execFileSync('caddy', ['validate', '--config', CADDYFILE], { stdio: 'pipe' })
    validateOk = true
  } catch {}
  check('caddy validate confirms the SFL4 Caddyfile is well-formed', validateOk)

  section('SFL0 — disabling SFL removes blocking again')
  await applyLevel(0)
  check('/.env is allowed once SFL is off', await reachesApp('/.env'))

  console.log(`\n${pass} passed, ${fail} failed`)
  cleanup()
  process.exit(fail ? 1 : 0)
})().catch(e => {
  console.error('\nSFL e2e harness error:', e)
  cleanup()
  process.exit(1)
})
