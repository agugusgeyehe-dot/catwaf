const os = require('os')
const fs = require('fs')
const path = require('path')

const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-test-'))
process.env.JWT_SECRET = 'a'.repeat(64)
process.env.DB_DIR = DATA_DIR

const crypto = require('crypto')
const ROOT = path.join(__dirname, '..')

const { addUser, needsBootstrap } = require(path.join(ROOT, 'backend/middleware/auth'))
const { app } = require(path.join(ROOT, 'backend/server.js'))

let pass = 0, fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra ?? '') }
}

const server = app.listen(0, '127.0.0.1', async () => {
  const base = `http://127.0.0.1:${server.address().port}`

  async function raw(method, path, { body, headers = {} } = {}) {
    const opts = { method, headers: { 'Content-Type': 'application/json', ...headers } }
    if (body !== undefined) opts.body = JSON.stringify(body)
    const res = await fetch(base + path, opts)
    let json = null
    try { json = await res.json() } catch {}
    return { status: res.status, json }
  }

  console.log('\n== bootstrap ==')
  if (needsBootstrap()) addUser({ username: 'owner', password: 'correct-horse-battery', role: 'admin' })
  check('no default admin/admin account', (await raw('POST', '/api/auth/login', { body: { username: 'admin', password: 'admin' } })).status === 401)

  console.log('\n== fixed paths ==')
  check('/healthz reachable', (await raw('GET', '/healthz')).status === 200)
  const st = await raw('GET', '/api/auth/status')
  check('/api/auth/status reachable', st.status === 200 && st.json.needs_setup === false)

  console.log('\n== ungated API is invisible ==')
  const direct = await raw('GET', '/api/waf/engine')
  check('direct /api/waf/engine -> 404 decoy', direct.status === 404, direct)
  const bogus = await raw('GET', '/api/definitely-not-real')
  check('unknown path -> 404 decoy', bogus.status === 404)
  check('real and fake endpoints indistinguishable', direct.status === bogus.status)

  console.log('\n== case-insensitive path cannot bypass the gate ==')
  for (const p of ['/API/waf/settings', '/Api/stats', '/API/caddy/status', '/API/diagnostics/export', '/ApI/alerts']) {
    const r = await raw('GET', p)
    check(`${p} -> 404 decoy (no unauth read)`, r.status === 404, r)
  }

  console.log('\n== login ==')
  const login = await raw('POST', '/api/auth/login', { body: { username: 'owner', password: 'correct-horse-battery' } })
  check('login succeeds', login.status === 200, login)
  const { token, sessionKey, api } = login.json
  check('login returns a session key', typeof sessionKey === 'string' && sessionKey.length === 64)
  check('login returns a rotating base path', /^\/g\/[0-9a-f]{32}$/.test(api.basePath), api)

  function signed(method, path, body) {
    const ts = String(Date.now())
    const nonce = crypto.randomBytes(16).toString('hex')
    const bodyHash = crypto.createHash('sha256')
      .update(body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body)))
      .digest('hex')
    const sig = crypto.createHmac('sha256', sessionKey)
      .update([method.toUpperCase(), path, ts, nonce, bodyHash].join('\n'))
      .digest('hex')
    return { 'Authorization': `Bearer ${token}`, 'X-CatWAF-Ts': ts, 'X-CatWAF-Nonce': nonce, 'X-CatWAF-Sig': sig }
  }

  console.log('\n== gated + signed requests ==')
  const good = await raw('GET', api.basePath + '/api/waf/engine', { headers: signed('GET', '/api/waf/engine') })
  check('gated+signed GET works', good.status === 200, good)

  const unsigned = await raw('GET', api.basePath + '/api/waf/engine', { headers: { Authorization: `Bearer ${token}` } })
  check('token without signature rejected', unsigned.status === 401 && unsigned.json.code === 'SIG_REQUIRED', unsigned)

  console.log('\n== replay ==')
  const h = signed('GET', '/api/waf/engine')
  const first = await raw('GET', api.basePath + '/api/waf/engine', { headers: h })
  const replay = await raw('GET', api.basePath + '/api/waf/engine', { headers: h })
  check('first use accepted', first.status === 200)
  check('replayed signature rejected', replay.status === 401 && replay.json.code === 'SIG_REPLAY', replay)

  console.log('\n== tamper ==')
  const tamperHdrs = signed('POST', '/api/waf/engine', { mode: 'On' })
  const tampered = await raw('POST', api.basePath + '/api/waf/engine', { body: { mode: 'Off' }, headers: tamperHdrs })
  check('body tampering rejected', tampered.status === 401 && tampered.json.code === 'SIG_INVALID', tampered)

  const pathSwap = await raw('GET', api.basePath + '/api/security/score', { headers: signed('GET', '/api/waf/engine') })
  check('path swapping rejected', pathSwap.status === 401, pathSwap)

  console.log('\n== Caddyfile injection via allowed_content_types ==')
  {
    const evil = ['application/json', 'x`\n  }\n  handle /pwn* { respond "PWNED" 200 }\n  x `']
    const inj = await raw('POST', api.basePath + '/api/waf/settings',
      { body: { allowed_content_types: evil }, headers: signed('POST', '/api/waf/settings', { allowed_content_types: evil }) })
    check('backtick content-type rejected (no directive injection)', inj.status === 400, inj)
    const legit = ['application/json', 'multipart/form-data']
    const okResp = await raw('POST', api.basePath + '/api/waf/settings',
      { body: { allowed_content_types: legit }, headers: signed('POST', '/api/waf/settings', { allowed_content_types: legit }) })
    check('well-formed MIME content-types accepted', okResp.status === 200, okResp)
  }

  console.log('\n== stale gate segment ==')
  const badSeg = await raw('GET', '/g/' + '0'.repeat(32) + '/api/waf/engine', { headers: signed('GET', '/api/waf/engine') })
  check('wrong segment -> 410 PATH_ROTATED', badSeg.status === 410 && badSeg.json.code === 'PATH_ROTATED', badSeg)

  console.log('\n== clock skew ==')
  {
    const ts = String(Date.now() - 10 * 60 * 1000)
    const nonce = crypto.randomBytes(16).toString('hex')
    const bodyHash = crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex')
    const sig = crypto.createHmac('sha256', sessionKey).update(['GET', '/api/waf/engine', ts, nonce, bodyHash].join('\n')).digest('hex')
    const old = await raw('GET', api.basePath + '/api/waf/engine', { headers: { Authorization: `Bearer ${token}`, 'X-CatWAF-Ts': ts, 'X-CatWAF-Nonce': nonce, 'X-CatWAF-Sig': sig } })
    check('stale timestamp rejected', old.status === 401 && old.json.code === 'SIG_EXPIRED', old)
  }

  console.log('\n== forged token (alg confusion / wrong secret) ==')
  {
    const jwt = require('jsonwebtoken')
    const forged = jwt.sign({ username: 'owner', role: 'admin' }, 'wrong-secret', { algorithm: 'HS256', jwtid: 'deadbeef' })
    const r = await raw('GET', api.basePath + '/api/waf/engine', { headers: { Authorization: `Bearer ${forged}` } })
    check('token signed with wrong secret is not authenticated', r.status !== 200, r)
  }

  console.log(`\n${pass} passed, ${fail} failed\n`)
  server.close()
  try { fs.rmSync(DATA_DIR, { recursive: true, force: true }) } catch {}
  process.exit(fail ? 1 : 0)
})
