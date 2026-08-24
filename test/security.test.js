const os = require('os')
const fs = require('fs')
const path = require('path')

const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-test-'))
process.env.JWT_SECRET = 'a'.repeat(64)
process.env.DB_DIR = DATA_DIR
// This test boots the real API, whose WAF endpoints rewrite the Caddyfile.
// Without pinning these, caddy.js falls back to .env / auto-detection and the
// suite edits the developer's REAL configuration. Must be set before
// backend/server.js (and therefore services/caddy.js) is first required.
process.env.CADDYFILE_PATH = path.join(DATA_DIR, 'Caddyfile')
process.env.CORAZA_AUDIT_LOG = path.join(DATA_DIR, 'logs', 'audit.json')

// Never let a config reload reach a Caddy running on this machine.
// `reloadCaddy()` POSTs to CADDY_ADMIN_URL, which defaults to Caddy's real
// admin port — running the suite on a host where CatWAF is live would replace
// that Caddy's configuration with this file's fixture and take the site down.
// Unconditional: an inherited CADDY_ADMIN_URL could point this suite's fixture
// Caddyfile load at a live Caddy instance.
process.env.CADDY_ADMIN_URL = 'http://127.0.0.1:19918'
fs.writeFileSync(process.env.CADDYFILE_PATH, '{\n}\n\n:19992 {\n    respond "test" 200\n}\n')

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

  console.log('\n== /api/caddy/status does not leak the Caddyfile or its secrets ==')
  {
    const secretful = [
      '{',
      '}',
      '',
      'example.com {',
      '    forward_auth 127.0.0.1:8081 {',
      '        uri "/api/enforce"',
      '        header_up X-CatWAF-Enforce-Key "s3cr3t-enforce-key-value"',
      '        copy_headers "X-CatWAF-Verdict"',
      '    }',
      '    basic_auth /* {',
      '        "opsuser" "$2a$12$' + 'a'.repeat(53) + '"',
      '    }',
      '    tls {',
      '        dns cloudflare "cf-api-token-abcdef"',
      '        resolvers 1.1.1.1 8.8.8.8',
      '    }',
      '    reverse_proxy 127.0.0.1:3000',
      '}',
      '',
    ].join('\n')
    fs.writeFileSync(process.env.CADDYFILE_PATH, secretful)

    const asAdmin = await raw('GET', api.basePath + '/api/caddy/status', { headers: signed('GET', '/api/caddy/status') })
    check('admin can still read caddy status', asAdmin.status === 200, asAdmin)
    const body = asAdmin.json.caddyfile || ''
    check('admin still receives the Caddyfile body', body.includes('reverse_proxy 127.0.0.1:3000'), body.slice(0, 200))
    check('enforce key is redacted for admins', !body.includes('s3cr3t-enforce-key-value'), body)
    check('dns-01 API token is redacted for admins', !body.includes('cf-api-token-abcdef'), body)
    check('basic-auth hash is redacted for admins', !/\$2[aby]\$\d\d\$/.test(body), body)
    check('the basic-auth username is kept (not a credential)', body.includes('opsuser'), body)
    check('the response says the body was redacted', asAdmin.json.caddyfile_redacted === true, asAdmin.json)

    // A read-only viewer must get no Caddyfile at all.
    const { addUser: addUser2 } = require(path.join(ROOT, 'backend/middleware/auth'))
    try { addUser2({ username: 'readonly', password: 'viewer-pass-1234', role: 'viewer' }) } catch {}
    const vLogin = await raw('POST', '/api/auth/login', { body: { username: 'readonly', password: 'viewer-pass-1234' } })
    check('viewer can log in', vLogin.status === 200, vLogin)
    const vSigned = (method, p, b) => {
      const ts = String(Date.now())
      const nonce = crypto.randomBytes(16).toString('hex')
      const bodyHash = crypto.createHash('sha256')
        .update(b === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(b))).digest('hex')
      const sig = crypto.createHmac('sha256', vLogin.json.sessionKey)
        .update([method.toUpperCase(), p, ts, nonce, bodyHash].join('\n')).digest('hex')
      return { 'Authorization': `Bearer ${vLogin.json.token}`, 'X-CatWAF-Ts': ts, 'X-CatWAF-Nonce': nonce, 'X-CatWAF-Sig': sig }
    }
    const asViewer = await raw('GET', vLogin.json.api.basePath + '/api/caddy/status',
      { headers: vSigned('GET', '/api/caddy/status') })
    check('viewer still gets a status answer', asViewer.status === 200, asViewer)
    check('viewer receives no Caddyfile body', asViewer.json.caddyfile === '', asViewer.json)
    check('viewer sees no enforce key', !JSON.stringify(asViewer.json).includes('s3cr3t-enforce-key-value'), asViewer.json)
    check('viewer sees no dns token', !JSON.stringify(asViewer.json).includes('cf-api-token-abcdef'), asViewer.json)
    check('viewer sees no basic-auth hash', !/\$2[aby]\$\d\d\$/.test(JSON.stringify(asViewer.json)), asViewer.json)
  }

  console.log('\n== a signed-out token cannot use /api/handshake ==')
  {
    const l = await raw('POST', '/api/auth/login', { body: { username: 'owner', password: 'correct-horse-battery' } })
    check('login for the handshake test succeeds', l.status === 200, l)
    const bearer = { Authorization: `Bearer ${l.json.token}` }

    const before = await raw('GET', '/api/handshake', { headers: bearer })
    check('a live token gets the rotating path from /api/handshake',
      before.status === 200 && /^\/g\/[0-9a-f]{32}$/.test(before.json.api.basePath), before)

    // Logout is not a fixed path, so it goes through the gate like any other
    // write, signed with this session's own key.
    const outTs = String(Date.now())
    const outNonce = crypto.randomBytes(16).toString('hex')
    const outHash = crypto.createHash('sha256').update(Buffer.alloc(0)).digest('hex')
    const outSig = crypto.createHmac('sha256', l.json.sessionKey)
      .update(['POST', '/api/auth/logout', outTs, outNonce, outHash].join('\n')).digest('hex')
    const out = await raw('POST', l.json.api.basePath + '/api/auth/logout', {
      headers: { ...bearer, 'X-CatWAF-Ts': outTs, 'X-CatWAF-Nonce': outNonce, 'X-CatWAF-Sig': outSig },
    })
    check('logout succeeds', out.status === 200, out)

    const after = await raw('GET', '/api/handshake', { headers: bearer })
    check('a revoked token is refused at /api/handshake', after.status === 401, after)
    check('the refusal names the revoked session', after.json && after.json.code === 'SESSION_REVOKED', after.json)
    check('no rotating path is disclosed to a revoked token',
      !after.json || after.json.api === undefined, after.json)
    check('no username or role is disclosed to a revoked token',
      !after.json || after.json.user === undefined, after.json)
  }

  console.log('\n== a password reset invalidates every token issued before it ==')
  {
    const { setPassword } = require(path.join(ROOT, 'backend/middleware/auth'))

    const l = await raw('POST', '/api/auth/login', { body: { username: 'readonly', password: 'viewer-pass-1234' } })
    check('pre-reset login succeeds', l.status === 200, l)
    const bearer = { Authorization: `Bearer ${l.json.token}` }
    check('the pre-reset token works', (await raw('GET', '/api/handshake', { headers: bearer })).status === 200)

    // Same wall-clock second as the token above — this is the window the
    // strict `<` comparison used to leave open.
    setPassword('readonly', 'viewer-pass-5678')
    const after = await raw('GET', '/api/handshake', { headers: bearer })
    check('a token issued in the reset second does not survive the reset', after.status === 401, after)

    // Directly assert the boundary rather than relying on timing: a token
    // whose iat is exactly the reset stamp must be rejected.
    const jwt2 = require('jsonwebtoken')
    const { findUser, JWT_ISSUER: iss, JWT_AUDIENCE: aud } = require(path.join(ROOT, 'backend/middleware/auth'))
    const target = findUser('readonly')
    const sameSecond = jwt2.sign(
      { id: target.id, username: target.username, role: target.role, iat: target.tokens_valid_after },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', issuer: iss, audience: aud, jwtid: crypto.randomBytes(16).toString('hex'), expiresIn: '12h' },
    )
    const edge = await raw('GET', '/api/handshake', { headers: { Authorization: `Bearer ${sameSecond}` } })
    check('iat === tokens_valid_after is rejected (no one-second window)', edge.status === 401, edge)

    const older = jwt2.sign(
      { id: target.id, username: target.username, role: target.role, iat: target.tokens_valid_after - 5 },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', issuer: iss, audience: aud, jwtid: crypto.randomBytes(16).toString('hex'), expiresIn: '12h' },
    )
    check('a token from before the reset is rejected',
      (await raw('GET', '/api/handshake', { headers: { Authorization: `Bearer ${older}` } })).status === 401)

    // And a legitimate login right after the reset still works — the fix must
    // not lock the account out of its own new password.
    const relogin = await raw('POST', '/api/auth/login', { body: { username: 'readonly', password: 'viewer-pass-5678' } })
    check('logging in with the new password still works', relogin.status === 200, relogin)
    const fresh = await raw('GET', '/api/handshake', { headers: { Authorization: `Bearer ${relogin.json.token}` } })
    check('the post-reset token is accepted', fresh.status === 200, fresh)
  }

  console.log(`\n${pass} passed, ${fail} failed\n`)
  server.close()
  try { fs.rmSync(DATA_DIR, { recursive: true, force: true }) } catch {}
  process.exit(fail ? 1 : 0)
})
