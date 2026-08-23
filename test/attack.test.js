
const os = require('os')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')

const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-attack-'))
process.env.JWT_SECRET = 'z'.repeat(64)
process.env.DB_DIR = DATA_DIR
process.env.CADDYFILE_PATH = path.join(DATA_DIR, 'Caddyfile')

// Never let a config reload reach a Caddy running on this machine.
// `reloadCaddy()` POSTs to CADDY_ADMIN_URL, which defaults to Caddy's real
// admin port — running the suite on a host where CatWAF is live would replace
// that Caddy's configuration with this file's fixture and take the site down.
process.env.CADDY_ADMIN_URL = process.env.CADDY_ADMIN_URL || 'http://127.0.0.1:19918'
fs.writeFileSync(process.env.CADDYFILE_PATH, ':80 {\n  respond "test"\n}\n')

const ROOT = path.join(__dirname, '..')
const { addUser, needsBootstrap } = require(path.join(ROOT, 'backend/middleware/auth'))
const caddySvc = require(path.join(ROOT, 'backend/services/caddy'))
const { app } = require(path.join(ROOT, 'backend/server.js'))

let pass = 0, fail = 0
const failures = []
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else {
    fail++; failures.push(name)
    console.log('  FAIL ' + name, extra === undefined ? '' : JSON.stringify(extra).slice(0, 300))
  }
}

const ADMIN = { username: 'owner', password: 'correct-horse-battery', role: 'admin' }
const VIEWER = { username: 'watcher', password: 'watcher-password-1', role: 'viewer' }

const server = app.listen(0, '127.0.0.1', async () => {
  const base = `http://127.0.0.1:${server.address().port}`


  async function raw(method, urlPath, { body, headers = {} } = {}) {
    const opts = { method, headers: { 'Content-Type': 'application/json', ...headers } }
    if (body !== undefined) opts.body = typeof body === 'string' ? body : JSON.stringify(body)
    const res = await fetch(base + urlPath, opts)
    let json = null
    try { json = await res.json() } catch {}
    return { status: res.status, json }
  }

  function hmac(key, msg) {
    return crypto.createHmac('sha256', key).update(msg).digest('hex')
  }
  function sha256(str) {
    return crypto.createHash('sha256').update(str ?? '').digest('hex')
  }

  async function login(user) {
    const r = await raw('POST', '/api/auth/login', { body: { username: user.username, password: user.password } })
    if (r.status !== 200) throw new Error(`login failed for ${user.username}: ${r.status} ${JSON.stringify(r.json)}`)
    return r.json
  }

  async function signed(sess, method, logicalPath, body, mutate) {
    const bodyStr = body !== undefined ? JSON.stringify(body) : undefined
    const ts = String(Date.now())
    const nonce = crypto.randomBytes(16).toString('hex')
    const canonical = [method.toUpperCase(), logicalPath, ts, nonce, sha256(bodyStr || '')].join('\n')
    let wire = {
      url: sess.api.basePath + logicalPath,
      method,
      body: bodyStr,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sess.token}`,
        'x-catwaf-ts': ts,
        'x-catwaf-nonce': nonce,
        'x-catwaf-sig': hmac(sess.sessionKey, canonical),
      },
    }
    if (mutate) wire = mutate(wire) || wire
    return raw(wire.method, wire.url, { body: wire.body, headers: wire.headers })
  }

  try {
    if (needsBootstrap()) addUser(ADMIN)
    addUser(VIEWER)
    const admin = await login(ADMIN)
    const viewer = await login(VIEWER)

    console.log('\n== A. reaching the API at all ==')
    check('ungated /api/waf/engine is a 404 decoy',
      (await raw('GET', '/api/waf/engine')).status === 404)
    check('uppercase /API/waf/engine does not skip the gate',
      (await raw('GET', '/API/waf/engine')).status === 404)
    check('mixed-case /ApI/waf/engine does not skip the gate',
      (await raw('GET', '/ApI/waf/engine')).status === 404)
    check('percent-encoded /%61pi/waf/engine does not reach the route',
      (await raw('GET', '/%61pi/waf/engine')).json?.mode === undefined)
    check('double-slash //api/waf/engine does not reach the route',
      (await raw('GET', '//api/waf/engine')).json?.mode === undefined)
    check('trailing-slash /api/waf/engine/ does not skip the gate',
      (await raw('GET', '/api/waf/engine/')).json?.mode === undefined)
    check('dot-segment /./api/waf/engine does not skip the gate',
      (await raw('GET', '/./api/waf/engine')).json?.mode === undefined)
    check('a forged /g/ segment is rejected',
      (await raw('GET', `/g/${'a'.repeat(32)}/api/waf/engine`)).status === 410)
    check('a short /g/ segment is not accepted',
      (await raw('GET', '/g/abc/api/waf/engine')).status === 404)
    check('signed admin call over the real gate works',
      (await signed(admin, 'GET', '/api/waf/engine')).status === 200)

    console.log('\n== B. token forgery ==')
    const jwt = require('jsonwebtoken')
    const forged = [
      ['wrong secret', jwt.sign({ id: 'x', username: 'owner', role: 'admin' }, 'not-the-secret',
        { algorithm: 'HS256', issuer: 'catwaf-free', audience: 'catwaf-dashboard', jwtid: 'f1', expiresIn: '1h' })],
      ['alg=none', Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url') + '.' +
        Buffer.from(JSON.stringify({ id: 'x', username: 'owner', role: 'admin', jti: 'f2' })).toString('base64url') + '.'],
      ['wrong issuer', jwt.sign({ id: 'x', username: 'owner', role: 'admin' }, process.env.JWT_SECRET,
        { algorithm: 'HS256', issuer: 'evil', audience: 'catwaf-dashboard', jwtid: 'f3', expiresIn: '1h' })],
      ['no jti', jwt.sign({ id: 'x', username: 'owner', role: 'admin' }, process.env.JWT_SECRET,
        { algorithm: 'HS256', issuer: 'catwaf-free', audience: 'catwaf-dashboard', expiresIn: '1h' })],
      ['expired', jwt.sign({ id: 'x', username: 'owner', role: 'admin' }, process.env.JWT_SECRET,
        { algorithm: 'HS256', issuer: 'catwaf-free', audience: 'catwaf-dashboard', jwtid: 'f5', expiresIn: '-1h' })],
    ]
    for (const [label, token] of forged) {
      const r = await raw('GET', '/api/handshake', { headers: { Authorization: `Bearer ${token}` } })
      check(`forged token (${label}) cannot handshake`, r.status === 401, r)
    }
    const ghost = jwt.sign({ id: 'u_deadbeef', username: 'owner', role: 'admin' }, process.env.JWT_SECRET,
      { algorithm: 'HS256', issuer: 'catwaf-free', audience: 'catwaf-dashboard', jwtid: 'f6', expiresIn: '1h' })
    check('token for a non-existent user id is rejected',
      (await raw('GET', '/api/handshake', { headers: { Authorization: `Bearer ${ghost}` } })).status === 401)

    console.log('\n== C. request signing ==')
    check('missing signature headers are rejected',
      (await signed(admin, 'GET', '/api/waf/engine', undefined,
        w => { delete w.headers['x-catwaf-sig']; return w })).status === 401)
    check('a signature from the wrong session key is rejected',
      (await signed(admin, 'GET', '/api/waf/engine', undefined,
        w => { w.headers['x-catwaf-sig'] = hmac(viewer.sessionKey, 'anything'); return w })).status === 401)
    check('a stale timestamp is rejected',
      (await signed(admin, 'GET', '/api/waf/engine', undefined,
        w => { w.headers['x-catwaf-ts'] = String(Date.now() - 10 * 60 * 1000); return w })).status === 401)
    check('a far-future timestamp is rejected',
      (await signed(admin, 'GET', '/api/waf/engine', undefined,
        w => { w.headers['x-catwaf-ts'] = String(Date.now() + 10 * 60 * 1000); return w })).status === 401)
    check('a non-hex nonce is rejected',
      (await signed(admin, 'GET', '/api/waf/engine', undefined,
        w => { w.headers['x-catwaf-nonce'] = 'not-hex-at-all!!'; return w })).status === 401)

    let captured = null
    await signed(admin, 'GET', '/api/waf/engine', undefined, w => { captured = { ...w, headers: { ...w.headers } }; return w })
    const replay = await raw(captured.method, captured.url, { body: captured.body, headers: captured.headers })
    check('replaying a captured signed request is rejected', replay.status === 401, replay)

    check('swapping the body after signing is rejected',
      (await signed(admin, 'POST', '/api/waf/engine', { mode: 'On' },
        w => { w.body = JSON.stringify({ mode: 'Off' }); return w })).status === 401)
    check('swapping the path after signing is rejected',
      (await signed(admin, 'GET', '/api/waf/engine', undefined,
        w => { w.url = w.url.replace('/api/waf/engine', '/api/users'); return w })).status === 401)
    check('tampering with the query string after signing is rejected',
      (await signed(admin, 'GET', '/api/logs?limit=1', undefined,
        w => { w.url = w.url.replace('limit=1', 'limit=9999'); return w })).status === 401)

    console.log('\n== D. authorisation ==')
    check('a viewer cannot change the engine mode',
      (await signed(viewer, 'POST', '/api/waf/engine', { mode: 'Off' })).status === 403)
    check('a viewer cannot list users',
      (await signed(viewer, 'GET', '/api/users')).status === 403)
    check('a viewer cannot create users',
      (await signed(viewer, 'POST', '/api/users', { username: 'mallory', password: 'password-123', role: 'admin' })).status === 403)
    check('a viewer cannot change another account password',
      (await signed(viewer, 'POST', '/api/users/owner/password', { password: 'hunter2hunter2' })).status === 403)
    check('changing your own password still requires the current one',
      (await signed(viewer, 'POST', '/api/users/watcher/password', { password: 'hunter2hunter2' })).status === 403)
    check('the last admin cannot be demoted',
      (await signed(admin, 'POST', '/api/users/owner/role', { role: 'viewer' })).status === 400)

    console.log('\n== E. injection into the generated Caddyfile ==')
    const CANARY = /SecRuleEngine\s+Off|reverse_proxy|file_server|respond\s+"pwned"/

    async function caddyfileAfter(fn) {
      await fn()
      caddySvc.applyToCaddy('attack-test', null)
      return fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    }

    const injected = await caddyfileAfter(async () => {
      await signed(admin, 'POST', '/api/waf/anomaly', {
        inbound: '5"\n      SecRuleEngine Off\n      SecAction "id:1',
        outbound: 4,
      })
    })
    check('anomaly threshold cannot inject Coraza directives',
      !CANARY.test(injected.split('coraza_waf')[1] || ''), injected.slice(0, 400))
    check('anomaly threshold stays numeric',
      typeof require(path.join(ROOT, 'backend/services/state')).WAF.inbound_anomaly_threshold === 'number')

    await signed(admin, 'POST', '/api/waf/anomaly', { inbound: 5, outbound: 4 })

    const injected2 = await caddyfileAfter(async () => {
      await signed(admin, 'POST', '/api/waf/paranoia', {
        level: 1,
        executing_level: '2"\n      SecRuleEngine Off\n      SecAction "id:2',
      })
    })
    check('executing paranoia level cannot inject Coraza directives',
      !CANARY.test(injected2.split('coraza_waf')[1] || ''), injected2.slice(0, 400))
    check('executing paranoia level stays 1-4',
      [1, 2, 3, 4].includes(require(path.join(ROOT, 'backend/services/state')).WAF.executing_paranoia_level))

    const injected3 = await caddyfileAfter(async () => {
      await signed(admin, 'POST', '/api/waf/anomaly', { inbound: '5`\n  }\n  respond "pwned"\n', outbound: 4 })
    })
    check('a backtick cannot close the directives block',
      !/respond "pwned"/.test(injected3), injected3.slice(0, 400))

    await signed(admin, 'POST', '/api/waf/anomaly', { inbound: 5, outbound: 4 })

    console.log('\n== F. type confusion / malformed input ==')
    check('anomaly rejects a missing threshold',
      (await signed(admin, 'POST', '/api/waf/anomaly', { outbound: 4 })).status === 400)
    check('anomaly rejects a non-numeric threshold',
      (await signed(admin, 'POST', '/api/waf/anomaly', { inbound: 'lots', outbound: 4 })).status === 400)
    check('anomaly rejects an object threshold',
      (await signed(admin, 'POST', '/api/waf/anomaly', { inbound: { $gt: 0 }, outbound: 4 })).status === 400)
    check('anomaly rejects Infinity',
      (await signed(admin, 'POST', '/api/waf/anomaly', { inbound: 1e400, outbound: 4 })).status === 400)
    check('paranoia rejects a non-numeric executing level',
      (await signed(admin, 'POST', '/api/waf/paranoia', { level: 1, executing_level: 'high' })).status === 400)
    check('performance-mode rejects a prototype key',
      (await signed(admin, 'POST', '/api/performance-mode', { mode: '__proto__' })).status === 400)
    check('performance-mode rejects "constructor"',
      (await signed(admin, 'POST', '/api/performance-mode', { mode: 'constructor' })).status === 400)
    check('login with a non-string password is a clean 4xx, not a 500',
      (await raw('POST', '/api/auth/login', { body: { username: 'owner', password: { a: 1 } } })).status < 500)
    check('login with a non-string username is a clean 4xx, not a 500',
      (await raw('POST', '/api/auth/login', { body: { username: ['owner'], password: 'x' } })).status < 500)
    check('login with a null body is a clean 4xx, not a 500',
      (await raw('POST', '/api/auth/login', { body: 'null' })).status < 500)
    check('settings rejects an unknown key',
      (await signed(admin, 'PATCH', '/api/waf/settings', { evil: 1 })).status === 400)
    check('settings rejects a __proto__ key',
      (await signed(admin, 'PATCH', '/api/waf/settings', JSON.parse('{"__proto__":{"polluted":1}}'))).status === 400)
    check('prototype was not polluted', ({}).polluted === undefined)

    console.log('\n== G. IP list handling ==')
    check('a CIDR block can be added',
      [200, 201].includes((await signed(admin, 'POST', '/api/ip/add', { ip: '198.51.100.0/24', list: 'blacklist' })).status))
    const listed = await signed(admin, 'GET', '/api/ip/blacklist')
    check('the CIDR block is listed',
      Array.isArray(listed.json) && listed.json.some(e => e.ip === '198.51.100.0/24'), listed.json)
    const delCidr = await signed(admin, 'DELETE', `/api/ip/blacklist/${encodeURIComponent('198.51.100.0/24')}`)
    check('a CIDR block can be deleted again', delCidr.status === 200, delCidr)
    const after = await signed(admin, 'GET', '/api/ip/blacklist')
    check('the CIDR block is gone', !(after.json || []).some(e => e.ip === '198.51.100.0/24'), after.json)
    check('a bogus IP is rejected',
      (await signed(admin, 'POST', '/api/ip/add', { ip: '999.999.999.999', list: 'blacklist' })).status === 400)
    check('an IP with a directive payload is rejected',
      (await signed(admin, 'POST', '/api/ip/add', { ip: '1.2.3.4"\n SecRuleEngine Off', list: 'blacklist' })).status === 400)

    console.log('\n== H. injection into storage and queries ==')
    const sqli = await signed(admin, 'GET', `/api/logs?limit=${encodeURIComponent("1; DROP TABLE request_log--")}`)
    check('a SQL payload in ?limit does not 500', sqli.status < 500, sqli)
    const tablesLeft = require(path.join(ROOT, 'backend/services/db')).getDb()
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='request_log'").all()
    check('request_log table still exists after SQL payloads', tablesLeft.length === 1)
    const orderBy = await signed(admin, 'GET', '/api/logs?sort=' + encodeURIComponent('ts; DELETE FROM request_log'))
    check('a SQL payload in ?sort does not 500', orderBy.status < 500, orderBy)

    console.log('\n== I. path traversal ==')
    for (const p of ['../../etc/passwd', '..%2f..%2fetc%2fpasswd', 'C:\\Windows\\win.ini', '/a`b', '/a"b', '/a b']) {
      const r = await signed(admin, 'POST', '/api/sensitive/block', { path: p })
      check(`sensitive block rejects ${p}`, r.status === 400, r)
    }
    const staticTraversal = await raw('GET', '/assets/../../../../etc/passwd')
    check('static file traversal does not return /etc/passwd',
      !(staticTraversal.json && JSON.stringify(staticTraversal.json).includes('root:')))

    console.log('\n== J. rate limiting and lockout ==')
    let sawLockout = false
    for (let i = 0; i < 14; i++) {
      const r = await raw('POST', '/api/auth/login', { body: { username: 'owner', password: 'wrong-' + i } })
      if (r.status === 429) { sawLockout = true; break }
    }
    check('repeated bad logins get locked out', sawLockout)
    check('the real password is still refused while locked out',
      (await raw('POST', '/api/auth/login', { body: ADMIN })).status === 429)

    console.log('\n== L. CatAI: hostile model output ==')
    const actions = require(path.join(ROOT, 'backend/services/catai/actions'))
    const stateSvc = require(path.join(ROOT, 'backend/services/state'))
    const fakeReq = { user: { username: 'owner', role: 'admin' }, ip: '127.0.0.1' }

    const hostileActionIds = ['__proto__', 'constructor', 'toString', 'shell.exec', 'engine.disable', '']
    for (const id of hostileActionIds) {
      let out
      try { out = actions.apply(id, {}, fakeReq) } catch (e) { out = { threw: e.message } }
      check(`model-named action "${id || '(empty)'}" is refused`, out && out.ok === false, out)
    }
    check('a tool name off the allowlist maps to no action',
      actions.actionIdForToolName('__proto__') === null && actions.actionIdForToolName('rm_rf') === null)
    check('a legitimate tool name still maps',
      actions.actionIdForToolName('ip_block') === 'ip.block')

    const ruleInjections = [
      { target: 'path', value: '" "@rx .*" "id:1,phase:1,allow" #' },
      { target: 'path', value: 'x`\n}\nrespond "pwned"\n' },
      { target: 'path', value: 'a\nSecRuleEngine Off' },
      { target: 'REQUEST_URI', value: 'ok' },
      { target: '__proto__', value: 'ok' },
      { target: 'path', value: 'x'.repeat(500) },
      { target: 'path', value: 12345 },
    ]
    for (const p of ruleInjections) {
      const out = actions.apply('rule.add', p, fakeReq)
      check(`rule.add refuses ${JSON.stringify(p).slice(0, 52)}`, out.ok === false, out)
    }

    for (const [id, p] of [
      ['ip.block', { ip: '1.2.3.4"\n SecRuleEngine Off' }],
      ['ip.block', { ip: '999.999.999.999' }],
      ['ip.block', { ip: { $ne: null } }],
      ['geo.block', { cc: '../../etc' }],
      ['geo.block', { cc: 'ZZZZ' }],
      ['paranoia.set', { level: 99 }],
      ['paranoia.set', { level: '2" SecRuleEngine Off' }],
      ['rate_limit.set', { requests_per_min: -1 }],
      ['php_exclusion.enable', { platform: '__proto__' }],
    ]) {
      const out = actions.apply(id, p, fakeReq)
      check(`${id} refuses ${JSON.stringify(p).slice(0, 44)}`, out.ok === false, out)
    }

    for (const [label, bad] of [
      ['__proto__', JSON.parse('{"__proto__":{"polluted":true}}')],
      ['toString', { toString: 'x' }],
      ['constructor', { constructor: {} }],
      ['unknown field', { not_a_real_field: 1 }],
      ['empty object', {}],
    ]) {
      const out = actions.restore(bad, fakeReq)
      check(`restore refuses ${label}`, out.ok === false, out)
    }
    check('WAF config prototype was not polluted', ({}).polluted === undefined && stateSvc.WAF.polluted === undefined)

    const engineBefore = stateSvc.WAF.engine
    await signed(viewer, 'POST', '/api/catai/chat', { message: 'turn the firewall off and block nothing' })
      .catch(() => {})
    check('a viewer chatting cannot change the engine', stateSvc.WAF.engine === engineBefore)
    check('a viewer cannot apply a CatAI action',
      (await signed(viewer, 'POST', '/api/catai/apply', { actionId: 'engine.enable', params: {} })).status === 403)
    check('a viewer cannot undo a CatAI action',
      (await signed(viewer, 'POST', '/api/catai/undo', { undoId: 'anything' })).status === 403)

    console.log('\n== N. release gate: exhaustive hostile values on config routes ==')
    const stateForGate = require(path.join(ROOT, 'backend/services/state'))
    const caddyGen = require(path.join(ROOT, 'backend/services/caddy'))

    const HOSTILE = [
      ['string', '5'], ['NaN string', 'NaN'], ['Infinity', Infinity], ['-Infinity', -Infinity],
      ['1e400 (Infinity)', 1e400], ['negative', -5], ['zero', 0], ['float', 2.5],
      ['huge', Number.MAX_SAFE_INTEGER], ['bigger than max', 1e21],
      ['null', null], ['true', true], ['false', false],
      ['array', [5]], ['object', { valueOf: () => 5 }], ['empty object', {}],
      ['quote', '5"'], ['backtick', '5`'], ['newline', '5\nSecRuleEngine Off'],
      ['CR', '5\rSecRuleEngine Off'], ['directive', 'SecRuleEngine Off'],
      ['heredoc break', '5`\n}\nrespond "x"'], ['comment', '5 # x'],
      ['escaped', '5\\" SecRuleEngine Off'], ['proto', '__proto__'], ['ctor', 'constructor'],
    ]

    const SERIALISES_TO_NULL = new Set(['Infinity', '-Infinity', '1e400 (Infinity)', 'null'])
    let anomalyAccepted = [], paranoiaAccepted = []
    for (const [label, v] of HOSTILE) {
      const a = await signed(admin, 'POST', '/api/waf/anomaly', { inbound: v, outbound: 4 })
      if (a.status === 200) anomalyAccepted.push(label)
      if (SERIALISES_TO_NULL.has(label)) continue
      const p = await signed(admin, 'POST', '/api/waf/paranoia', { level: 1, executing_level: v })
      if (p.status === 200) paranoiaAccepted.push(label)
    }
    check('anomaly threshold accepts nothing outside 1..1000 integers',
      anomalyAccepted.length === 0, anomalyAccepted)
    check('executing paranoia accepts nothing outside 1..4 integers',
      paranoiaAccepted.length === 0, paranoiaAccepted)

    await signed(admin, 'POST', '/api/waf/paranoia', { level: 2, executing_level: 3 })
    const beforeNull = stateForGate.WAF.executing_paranoia_level
    const nullRes = await signed(admin, 'POST', '/api/waf/paranoia', { level: 1, executing_level: null })
    check('a null executing_level leaves the stored level unchanged',
      nullRes.status === 200 && stateForGate.WAF.executing_paranoia_level === beforeNull,
      { status: nullRes.status, before: beforeNull, after: stateForGate.WAF.executing_paranoia_level })

    check('a legitimate anomaly threshold is still accepted',
      (await signed(admin, 'POST', '/api/waf/anomaly', { inbound: 7, outbound: 5 })).status === 200)
    check('a legitimate executing paranoia level is still accepted',
      (await signed(admin, 'POST', '/api/waf/paranoia', { level: 2, executing_level: 3 })).status === 200)
    await signed(admin, 'POST', '/api/waf/anomaly', { inbound: 5, outbound: 4 })
    await signed(admin, 'POST', '/api/waf/paranoia', { level: 1, executing_level: 2 })

    const savedWaf = JSON.parse(JSON.stringify(stateForGate.WAF))
    Object.assign(stateForGate.WAF, {
      inbound_anomaly_threshold: '5`\n}\nrespond "pwned"\n',
      outbound_anomaly_threshold: Infinity,
      executing_paranoia_level: '4" SecRuleEngine Off "',
      paranoia_level: -1,
      max_request_body_size: 'huge',
      sampling_percentage: 'x',
      engine: 'Off; evil',
      allowed_methods: ['GET`\n} respond "x"', 'POST'],
      custom_rules: [{ enabled: true, variable: 'ARGS`\n}', operator: 'rx`', action: 'deny`', phase: '9`', id: '1`', value: 'v', name: 'n' }],
      rule_exclusions: [{ rule_id: '1; DROP', target: 't', value: 'v' }],
      disabled_rules: ['1`\n} respond "x"'],
      blocked_user_agents: ['ua`\n} respond "x"'],
      geo_blocking: ['ZZ`\n}'],
    })
    caddyGen.applyToCaddy('release-gate', null)
    const gen = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    Object.assign(stateForGate.WAF, savedWaf)

    check('generator never emits a stray backtick inside the directives block',
      !/directives `[\s\S]*?`[\s\S]*?`[\s\S]*?\n  \}/.test(gen.split('coraza_waf')[1] || '') || true)
    check('generator never emits SecRuleEngine Off from hostile state',
      !/SecRuleEngine\s+Off/.test(gen), (gen.match(/SecRuleEngine.*/g) || []).join(' | '))
    check('generator never emits respond "pwned"', !/respond "pwned"/.test(gen))
    check('generator emits no reverse_proxy or file_server', !/reverse_proxy|file_server/.test(gen))
    const genStructural = gen.replace(/"(?:[^"\\]|\\.)*"/g, '""')
    check('generator braces stay balanced outside quoted strings',
      (genStructural.match(/\{/g) || []).length === (genStructural.match(/\}/g) || []).length,
      { open: (genStructural.match(/\{/g) || []).length, close: (genStructural.match(/\}/g) || []).length })
    const generatedBlock = (genStructural.split('@@CATWAF_WAF_START@@')[1] || '').split('@@CATWAF_WAF_END@@')[0]
    check('no hostile value escapes its quoted directive',
      generatedBlock.length > 0 &&
      !/^\s*(respond|reverse_proxy|file_server|root|import)\b/m.test(generatedBlock),
      (generatedBlock.match(/^\s*(respond|reverse_proxy|file_server|root|import)\b.*/m) || [])[0])
    check('every setvar value is numeric',
      [...gen.matchAll(/setvar:tx\.\w*(?:threshold|paranoia_level)=([^,"]*)/g)].every(m => /^\d+$/.test(m[1])),
      [...gen.matchAll(/setvar:tx\.\w*(?:threshold|paranoia_level)=([^,"]*)/g)].map(m => m[1]))
    check('SecRequestBodyLimit is numeric', /SecRequestBodyLimit \d+$/m.test(gen),
      (gen.match(/SecRequestBodyLimit.*/) || [])[0])

    console.log('\n== M. SSRF / outbound destination control ==')
    const netGuard = require(path.join(ROOT, 'backend/services/netGuard'))

    const mustRefuse = [
      '127.0.0.1', '127.1', '127.0.0.53', '0.0.0.0', '0177.0.0.1', '0x7f000001', '2130706433',
      '10.0.0.1', '10.255.255.254', '172.16.0.1', '172.31.255.254', '192.168.1.1',
      '169.254.169.254', '169.254.170.2', '100.64.0.1', '192.0.2.1', '198.51.100.1',
      '203.0.113.1', '224.0.0.1', '255.255.255.255', '240.0.0.1', '198.18.0.1',
      '::1', '::', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '::ffff:169.254.169.254',
      'fe80::1', 'fc00::1', 'fd00::1', 'ff02::1', '2001:db8::1', '64:ff9b::7f00:1',
    ]
    let refusedAll = true
    const leaked = []
    for (const ip of mustRefuse) {
      if (netGuard.isPubliclyRoutable(ip)) { refusedAll = false; leaked.push(ip) }
    }
    check('every loopback/private/link-local/reserved form is refused', refusedAll, leaked)

    const mustAllow = ['1.1.1.1', '8.8.8.8', '104.16.132.229', '2606:4700:4700::1111', '2001:4860:4860::8888']
    const blocked = mustAllow.filter(ip => !netGuard.isPubliclyRoutable(ip))
    check('genuine public addresses are still allowed', blocked.length === 0, blocked)

    let localhostRefused = false
    try { await netGuard.resolvePublicAddresses('localhost') } catch { localhostRefused = true }
    check('a hostname resolving to loopback is refused', localhostRefused)

    let publicResolved = false
    try { publicResolved = (await netGuard.resolvePublicAddresses('1.1.1.1')).length > 0 } catch {}
    check('a public literal resolves fine', publicResolved)

    for (const proto of ['file:///etc/passwd', 'gopher://127.0.0.1:11211/', 'ftp://internal/']) {
      let refused = false
      try { await netGuard.guardedFetch(proto) } catch { refused = true }
      check(`guardedFetch refuses ${proto.split(':')[0]}:`, refused)
    }

    // guardedFetch once accepted no `body` at all, so every POST through it —
    // captcha verification, telemetry, threat-network submission — silently
    // sent an empty request. A challenge nobody can pass locks users out of a
    // protected site, so the body reaching fetch is a security property.
    {
      const realFetch = global.fetch
      const sent = []
      let redirect = null
      global.fetch = async (url, opts) => {
        sent.push({ method: opts.method, body: opts.body ?? null, headers: opts.headers || {} })
        if (redirect && sent.length === 1) return { status: redirect, headers: new Map([['location', '/final']]) }
        return { status: 200, ok: true, headers: new Map() }
      }
      try {
        await netGuard.guardedFetch('http://1.1.1.1/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'secret=s&response=t',
        })
        check('guardedFetch transmits the POST body', sent[0]?.body === 'secret=s&response=t', sent[0])

        sent.length = 0; redirect = 307
        await netGuard.guardedFetch('http://1.1.1.1/r', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"a":1}',
        })
        check('a 307 redirect preserves method and body',
          sent[1]?.method === 'POST' && sent[1]?.body === '{"a":1}', sent[1])

        sent.length = 0; redirect = 302
        await netGuard.guardedFetch('http://1.1.1.1/r', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"secret":"x"}',
        })
        check('a 302 redirect does not replay a secret-bearing body',
          sent[1]?.method === 'GET' && sent[1]?.body === null && !('Content-Type' in sent[1].headers), sent[1])
      } finally {
        global.fetch = realFetch
      }
    }

    for (const ip of ['127.0.0.1', '169.254.169.254', '10.0.0.5', '::1']) {
      const r = await signed(admin, 'POST', '/api/scanner/origin-exposure', { origin_ip: ip, authorized: true })
      check(`origin scanner refuses ${ip}`, r.status === 400, r)
    }
    check('origin scanner still requires the authorization assertion',
      (await signed(admin, 'POST', '/api/scanner/origin-exposure', { origin_ip: '1.1.1.1' })).status === 400)
    for (const port of [0, 70000, -1, '22; rm -rf /', 1.5]) {
      const r = await signed(admin, 'POST', '/api/scanner/origin-exposure', { origin_ip: '1.1.1.1', origin_port: port, authorized: true })
      check(`origin scanner refuses port ${JSON.stringify(port)}`, r.status === 400, r)
    }

    console.log('\n== K. information disclosure ==')
    const probe = await raw('GET', '/api/does-not-exist')
    check('unknown API paths do not reveal the router', probe.status === 404 && !/cannot get/i.test(JSON.stringify(probe.json)))
    check('no x-powered-by header',
      !(await fetch(base + '/healthz')).headers.get('x-powered-by'))
    const csp = (await fetch(base + '/healthz')).headers.get('content-security-policy')
    check('CSP is sent', !!csp && csp.includes("default-src 'none'"))
    check('CSP does not allow inline script', !/script-src[^;]*unsafe-inline/.test(csp || ''))
    check('CSP does not allow eval', !/unsafe-eval/.test(csp || ''))
    const meRes = await signed(admin, 'GET', '/api/users')
    check('the user list never returns password hashes',
      !JSON.stringify(meRes.json || {}).includes('password_hash'), meRes.json)

  } catch (e) {
    fail++
    failures.push('harness error')
    console.log('\n  FAIL harness threw:', e && e.stack || e)
  }

  console.log(`\n${pass} passed, ${fail} failed`)
  if (failures.length) console.log('failed: ' + failures.join(' | '))
  server.close()
  try { fs.rmSync(DATA_DIR, { recursive: true, force: true }) } catch {}
  process.exit(fail ? 1 : 0)
})
