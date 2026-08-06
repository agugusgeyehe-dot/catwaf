#!/usr/bin/env node

// test/auth-flow.test.js — the login flow, in a real browser, including the
// failure modes that broke it.
//
// The existing frontend smoke test proves pages render. This proves the
// things that went wrong in practice and that a render check cannot see:
//
//   * signing in and STAYING signed in — the login loop was caused by login
//     dispatching a refresh whose failure cleared the session it had just
//     created;
//   * a backend that is down producing "CatWAF API is unavailable" rather
//     than "Failed to fetch", and NOT throwing the operator back to a login
//     form that could never succeed;
//   * a session surviving a page reload and a backend restart;
//   * reaching the dashboard over 127.0.0.1, over localhost and over the
//     machine's LAN address — CORS previously allowed only the single origin
//     recorded at setup time, so the other two failed at login;
//   * logout actually closing the session server-side.

const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawn, execFileSync } = require('child_process')

const ROOT = path.join(__dirname, '..')
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-auth-'))
const PORT = Number(process.env.AUTH_TEST_PORT || 18700)
const ADMIN = 'auth_flow_admin'
const PASSWORD = 'AuthFlowTestPass123'

let pass = 0, fail = 0
const check = (n, c, x) => c
  ? (pass++, console.log('  ok   ' + n))
  : (fail++, console.log('  FAIL ' + n, x !== undefined ? JSON.stringify(x).slice(0, 300) : ''))
const section = t => console.log('\n== ' + t + ' ==')

function resolvePlaywright() {
  for (const p of [
    process.env.PLAYWRIGHT_CORE,
    path.join(os.homedir(), '.local/pw/node_modules/playwright-core'),
    path.join(ROOT, 'node_modules/playwright-core'),
  ].filter(Boolean)) {
    try { return require(p) } catch {}
  }
  return null
}

function resolveChrome() {
  if (process.env.PW_CHROME && fs.existsSync(process.env.PW_CHROME)) return process.env.PW_CHROME
  const root = path.join(os.homedir(), '.cache/ms-playwright')
  let entries = []
  try { entries = fs.readdirSync(root) } catch { return null }
  for (const e of entries) {
    for (const rel of ['chrome-linux64/chrome', 'chrome-linux/chrome', 'chrome-headless-shell-linux64/chrome-headless-shell']) {
      const p = path.join(root, e, rel)
      if (fs.existsSync(p)) return p
    }
  }
  return null
}

// The machine's own non-loopback address, so the LAN case is exercised for
// real rather than approximated with another alias for 127.0.0.1.
function lanAddress() {
  for (const list of Object.values(os.networkInterfaces())) {
    for (const iface of list || []) {
      if (iface.family === 'IPv4' && !iface.internal) return iface.address
    }
  }
  return null
}

let server = null
function stopServer() {
  try { if (server) server.kill('SIGKILL') } catch {}
  server = null
}
function cleanup() {
  stopServer()
  try { fs.rmSync(WORK, { recursive: true, force: true }) } catch {}
}
process.on('exit', cleanup)
process.on('SIGINT', () => { cleanup(); process.exit(130) })

let ENV = null
function startServer() {
  server = spawn(process.execPath, [path.join(ROOT, 'backend', 'server.js')], { env: ENV, stdio: 'ignore' })
}

async function waitForHttp(url, attempts = 80, delayMs = 250) {
  for (let i = 0; i < attempts; i++) {
    try { if ((await fetch(url, { signal: AbortSignal.timeout(2000) })).ok) return true } catch {}
    await new Promise(r => setTimeout(r, delayMs))
  }
  return false
}
async function waitForDown(url, attempts = 40, delayMs = 200) {
  for (let i = 0; i < attempts; i++) {
    try { await fetch(url, { signal: AbortSignal.timeout(1000) }) } catch { return true }
    await new Promise(r => setTimeout(r, delayMs))
  }
  return false
}

;(async () => {
  section('prerequisites')

  if (!fs.existsSync(path.join(ROOT, 'frontend', 'dist', 'index.html'))) {
    console.log('  SKIP  dashboard is not built — run `npm run build` first.')
    console.log('\n0 passed, 0 failed, SKIPPED (no dashboard build)')
    process.exit(0)
  }
  const playwright = resolvePlaywright()
  const chrome = resolveChrome()
  if (!playwright || !chrome) {
    console.log('  SKIP  playwright-core and/or a Chromium build are unavailable.')
    console.log('\n0 passed, 0 failed, SKIPPED (no browser)')
    process.exit(0)
  }
  check('dashboard build and browser available', true)

  ENV = {
    ...process.env,
    PORT: String(PORT),
    // Bind every interface so the LAN-address case is reachable. This is what
    // a self-hosted install does.
    HOST: '0.0.0.0',
    DB_DIR: path.join(WORK, 'db'),
    JWT_SECRET: 'c'.repeat(64),
    CADDYFILE_PATH: path.join(WORK, 'Caddyfile'),
    CORAZA_AUDIT_LOG: path.join(WORK, 'audit.json'),
    CATAI_ENABLED: 'false',
  }
  // Deliberately NOT setting CORS_ORIGIN. A self-hosted install that never
  // configured one must still be reachable from every address that resolves
  // to it — that is the bug this file guards.
  delete ENV.CORS_ORIGIN
  fs.mkdirSync(ENV.DB_DIR, { recursive: true })
  fs.writeFileSync(ENV.CADDYFILE_PATH, '{\n    order coraza_waf first\n}\n\n:9910 {\n    respond "x" 200\n}\n')

  execFileSync(process.execPath, [path.join(ROOT, 'bin', 'catwaf.js'), 'user', 'add', ADMIN, '--role', 'admin'], {
    env: { ...ENV, CATWAF_USER_PASSWORD: PASSWORD },
    stdio: 'ignore',
    timeout: 20000,
  })

  startServer()
  const up = await waitForHttp(`http://127.0.0.1:${PORT}/healthz`)
  check('backend started', up)
  if (!up) { console.log(`\n${pass} passed, ${fail + 1} failed`); process.exit(1) }

  const browser = await playwright.chromium.launch({ executablePath: chrome, args: ['--no-sandbox'] })

  async function freshPage() {
    const context = await browser.newContext({ viewport: { width: 1400, height: 900 } })
    const page = await context.newPage()
    return { context, page }
  }
  const text = page => page.locator('body').innerText()

  async function signIn(page, base, user = ADMIN, pw = PASSWORD) {
    await page.goto(base, { waitUntil: 'networkidle' })
    await page.waitForTimeout(900)
    const inputs = page.locator('form input')
    await inputs.nth(0).fill(user)
    await page.locator('input[type="password"]').fill(pw)
    await page.locator('button:has-text("Sign in")').click()
    await page.waitForTimeout(2600)
  }

  try {
    // ── Reaching CatWAF over every address that resolves to it ──────────
    section('access over localhost, 127.0.0.1 and the LAN address')

    const origins = [
      ['127.0.0.1', `http://127.0.0.1:${PORT}`],
      ['localhost', `http://localhost:${PORT}`],
    ]
    const lan = lanAddress()
    if (lan) origins.push([`LAN address (${lan})`, `http://${lan}:${PORT}`])
    else console.log('  note  no non-loopback interface on this machine — LAN case not exercised')

    for (const [label, base] of origins) {
      const { context, page } = await freshPage()
      const failures = []
      page.on('requestfailed', r => failures.push(`${r.url()} ${r.failure()?.errorText || ''}`))
      await signIn(page, base)
      const signedIn = await page.locator('input[type="password"]').count() === 0
      check(`signs in over ${label}`, signedIn, (await text(page)).slice(0, 200))
      check(`no blocked requests over ${label}`, failures.length === 0, failures.slice(0, 3))
      await context.close()
    }

    // ── The login loop ──────────────────────────────────────────────────
    section('the session survives (no login loop)')
    const { context, page } = await freshPage()
    await signIn(page, `http://127.0.0.1:${PORT}`)
    check('signed in', await page.locator('input[type="password"]').count() === 0)

    // The loop showed up as: sign in, then get bounced back within a second
    // or two by a background refresh.
    await page.waitForTimeout(4000)
    check('still signed in four seconds later', await page.locator('input[type="password"]').count() === 0)

    await page.reload({ waitUntil: 'networkidle' })
    await page.waitForTimeout(2200)
    check('still signed in after a reload', await page.locator('input[type="password"]').count() === 0)

    // ── Backend down ────────────────────────────────────────────────────
    section('backend stopped')
    stopServer()
    await waitForDown(`http://127.0.0.1:${PORT}/healthz`)

    await page.reload({ waitUntil: 'domcontentloaded' }).catch(() => {})
    await page.waitForTimeout(3000)
    // With the backend down the served page cannot reload, so drive the
    // running app instead: a fresh page has nothing to load from.
    const downText = await text(page).catch(() => '')
    check('a stopped backend does not silently log the operator out',
      !/Welcome back/i.test(downText) || /unavailable/i.test(downText), downText.slice(0, 200))

    // ── Backend restarted ───────────────────────────────────────────────
    section('backend restarted')
    startServer()
    check('backend is back', await waitForHttp(`http://127.0.0.1:${PORT}/healthz`))

    await page.goto(`http://127.0.0.1:${PORT}`, { waitUntil: 'networkidle' })
    await page.waitForTimeout(2600)
    check('the session survives a backend restart (JWT_SECRET is persistent)',
      await page.locator('input[type="password"]').count() === 0, (await text(page)).slice(0, 200))

    // ── Invalid credentials ─────────────────────────────────────────────
    section('invalid credentials')
    const { context: c2, page: p2 } = await freshPage()
    await signIn(p2, `http://127.0.0.1:${PORT}`, ADMIN, 'the-wrong-password')
    const wrongText = await text(p2)
    check('a wrong password is refused', await p2.locator('input[type="password"]').count() > 0)
    check('a wrong password says so plainly', /invalid credentials/i.test(wrongText), wrongText.slice(0, 200))
    check('a wrong password is not reported as an API failure', !/unavailable/i.test(wrongText))

    // ── The API-unavailable message on the login screen ─────────────────
    section('signing in while the backend is down')
    stopServer()
    await waitForDown(`http://127.0.0.1:${PORT}/healthz`)
    await p2.locator('input[type="password"]').fill(PASSWORD)
    await p2.locator('button:has-text("Sign in")').click()
    await p2.waitForTimeout(2500)
    const apiDownText = await text(p2)
    check('the login form reports that the API is unavailable',
      /API is unavailable/i.test(apiDownText), apiDownText.slice(0, 260))
    check('it does not show a raw fetch error', !/failed to fetch|networkerror|typeerror/i.test(apiDownText))
    check('it tells the operator what to do', /backend is running|catwaf status/i.test(apiDownText))
    await c2.close()

    startServer()
    await waitForHttp(`http://127.0.0.1:${PORT}/healthz`)

    // ── Logout closes the session server-side ───────────────────────────
    section('logout')
    await page.goto(`http://127.0.0.1:${PORT}`, { waitUntil: 'networkidle' })
    await page.waitForTimeout(2400)
    const token = await page.evaluate(() => localStorage.getItem('catwaf-token'))
    check('a token is held while signed in', !!token)

    // A first-run session shows the welcome tour, which is modal and sits
    // over the header. Dismiss it the way an operator would.
    const skipTour = page.locator('button:has-text("Skip Tour")')
    if (await skipTour.count()) { await skipTour.first().click(); await page.waitForTimeout(700) }

    await page.locator('button[aria-label="Sign out"]').click()
    await page.waitForTimeout(1600)
    check('signing out returns to the login screen', await page.locator('input[type="password"]').count() > 0)
    check('signing out clears the stored token',
      await page.evaluate(() => localStorage.getItem('catwaf-token')) === null)

    await context.close()

    // ── Logout really ends the session, server-side ─────────────────────
    //
    // Driven over HTTP rather than through the browser, because a revoked
    // token has to be replayed deliberately — which is the whole point. The
    // dashboard clears its own storage on sign-out; that protects nobody if
    // the token still works for whoever kept a copy.
    section('a signed-out token is refused')
    const crypto = require('crypto')
    const base = `http://127.0.0.1:${PORT}`

    const login = await fetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: ADMIN, password: PASSWORD }),
    }).then(r => r.json())
    check('signed in over HTTP', !!login.token, login)

    const sign = (m, p, bodyStr) => {
      const ts = String(Date.now()), nonce = crypto.randomBytes(16).toString('hex')
      const bh = crypto.createHash('sha256').update(bodyStr || '').digest('hex')
      const sig = crypto.createHmac('sha256', login.sessionKey)
        .update([m.toUpperCase(), p, ts, nonce, bh].join('\n')).digest('hex')
      return { 'Content-Type': 'application/json', Authorization: `Bearer ${login.token}`, 'X-CatWAF-Ts': ts, 'X-CatWAF-Nonce': nonce, 'X-CatWAF-Sig': sig }
    }
    const gated = (m, p, bodyStr) => fetch(base + login.api.basePath + p, {
      method: m, headers: sign(m, p, bodyStr), body: bodyStr,
    })

    const before = await gated('GET', '/api/auth/me')
    check('the token works before signing out', before.status === 200, before.status)

    const out = await gated('POST', '/api/auth/logout', undefined)
    check('logout is accepted', out.status === 200, out.status)

    const after = await gated('GET', '/api/auth/me')
    const afterBody = await after.json().catch(() => ({}))
    check('the same token is refused after signing out', after.status === 401, { status: after.status, afterBody })
    check('the refusal says the session was signed out',
      afterBody.code === 'SESSION_REVOKED', afterBody)

    // A fresh login must still work — revocation is per token, not per user.
    const again = await fetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: ADMIN, password: PASSWORD }),
    }).then(r => r.json())
    check('signing in again issues a working session', !!again.token && again.token !== login.token)
  } finally {
    await browser.close().catch(() => {})
  }

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
})().catch(e => {
  console.error('\nFATAL', e)
  process.exit(1)
})
