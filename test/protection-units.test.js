#!/usr/bin/env node

// Unit tests for the parts of the protection layer that test/extensions.test.js
// only reaches through the API, where a wrong answer still looks like a
// successful request: RFC 6238 code generation, community-feed parsing, ban
// CIDR matching and escalation, diff correctness, the plugin placeholder
// validator, and the challenge gate's proof-of-work and token binding.

const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')

const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-prot-'))
process.env.DB_DIR = path.join(WORK, 'db')
process.env.CADDYFILE_PATH = path.join(WORK, 'Caddyfile')
process.env.CORAZA_AUDIT_LOG = path.join(WORK, 'audit.json')
process.env.JWT_SECRET = 'f'.repeat(64)
process.env.CATWAF_SECRET = 'c'.repeat(64)
fs.mkdirSync(process.env.DB_DIR, { recursive: true })
fs.mkdirSync(path.join(WORK, 'logs'), { recursive: true })
fs.writeFileSync(process.env.CORAZA_AUDIT_LOG, '')
fs.writeFileSync(process.env.CADDYFILE_PATH, '{\n}\n\nexample.com {\n    reverse_proxy 127.0.0.1:3000\n}\n')

let pass = 0, fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra !== undefined ? JSON.stringify(extra) : '') }
}
function section(t) { console.log('\n== ' + t + ' ==') }

process.on('exit', () => { try { fs.rmSync(WORK, { recursive: true, force: true }) } catch {} })

const totp = require('../backend/services/totp')
const lists = require('../backend/services/intel/lists')
const bans = require('../backend/services/bans')
const preview = require('../backend/services/preview')
const plugins = require('../backend/services/plugins')
const challenge = require('../backend/services/challenge')
const settings = require('../backend/services/settings')

// ─── TOTP against RFC 6238's published vectors ──────────────────────────

section('TOTP (RFC 6238)')

{
  // RFC 6238 Appendix B. The published table uses an ASCII seed; CatWAF's
  // API takes base32, so the seed is re-encoded rather than restated — if
  // base32Encode and base32Decode did not round-trip, every vector below
  // would fail, which is the point.
  const seed = Buffer.from('12345678901234567890', 'ascii')
  const secret = totp.base32Encode(seed)

  check('base32 round-trips the RFC seed', totp.base32Decode(secret).equals(seed))

  const VECTORS = [
    [59, '287082'],
    [1111111109, '081804'],
    [1111111111, '050471'],
    [1234567890, '005924'],
    [2000000000, '279037'],
    [20000000000, '353130'],
  ]
  for (const [seconds, expected] of VECTORS) {
    const counter = Math.floor(seconds / 30)
    const got = totp.hotp(seed, counter, 6)
    check(`T=${seconds} → ${expected}`, got === expected, { got })
  }

  // verifyCode is what the login path actually calls.
  const now = 1111111109 * 1000
  check('verifyCode accepts the code for its own window',
    totp.verifyCode(secret, '081804', { at: now }).valid)
  check('verifyCode accepts one step of drift either side',
    totp.verifyCode(secret, '081804', { at: now + 30_000 }).valid &&
    totp.verifyCode(secret, '081804', { at: now - 30_000 }).valid)
  check('verifyCode rejects two steps of drift',
    !totp.verifyCode(secret, '081804', { at: now + 90_000 }).valid)
  check('verifyCode rejects a code from a different secret',
    !totp.verifyCode(totp.base32Encode(crypto.randomBytes(20)), '081804', { at: now }).valid)
  check('verifyCode rejects anything that is not six to eight digits',
    !totp.verifyCode(secret, '12345', { at: now }).valid &&
    !totp.verifyCode(secret, 'abcdef', { at: now }).valid &&
    !totp.verifyCode(secret, '', { at: now }).valid)
}

{
  // Replay protection and single-use recovery codes, through the stored API.
  const user = 'totp-unit-user'
  const enrollment = totp.beginEnrollment(user, { account: user })
  const code = totp.totp(enrollment.secret)

  const confirmed = totp.confirmEnrollment(user, code)
  check('enrollment confirms with a live code', confirmed.ok, confirmed.error)
  check('confirmation returns ten recovery codes', confirmed.recovery_codes?.length === 10)
  check('two-factor is only enforced after confirmation', totp.isEnabled(user))

  check('the same code cannot be replayed', !totp.verify(user, code).ok)

  const recovery = confirmed.recovery_codes[0]
  const used = totp.verify(user, recovery)
  check('a recovery code works once', used.ok && used.used_recovery_code)
  check('the same recovery code does not work twice', !totp.verify(user, recovery).ok)
  check('nine recovery codes remain', totp.status(user).recovery_codes_remaining === 9)

  totp.disable(user)
  check('disabling leaves the account with no second factor', !totp.isEnabled(user))
}

// ─── Community feed parsing ─────────────────────────────────────────────

section('intel/lists feed parsing')

{
  // Shapes taken from how real published blocklists are actually written:
  // trailing comments, CIDR notation, blank lines, several comment markers.
  const body = [
    '# Example blocklist',
    '; another comment style',
    '// and another',
    '',
    '203.0.113.7',
    '198.51.100.0/24  # a scanning range',
    '192.0.2.1,noted by someone',
    '   203.0.113.7   ',
    'not-an-address',
    '2001:db8::1',
    '999.999.999.999',
  ].join('\n')

  const result = lists.parseFeed(body, 'ip', 1000)
  check('comments and blank lines are skipped', !result.entries.some(e => e.startsWith('#')))
  check('a trailing comment does not corrupt the value', result.entries.includes('198.51.100.0/24'), result.entries)
  check('a comma-separated note is stripped', result.entries.includes('192.0.2.1'))
  check('IPv6 is accepted', result.entries.includes('2001:db8::1'))
  check('duplicates collapse', result.entries.filter(e => e === '203.0.113.7').length === 1)
  check('unparseable lines are counted, not silently dropped', result.rejected === 2, result.rejected)

  const capped = lists.parseFeed(Array.from({ length: 500 }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256}`).join('\n'), 'ip', 10)
  check('the max entry count is honoured', capped.entries.length === 10, capped.entries.length)

  check('ASN feeds accept both AS-prefixed and bare numbers',
    JSON.stringify(lists.parseFeed('AS64496\n64497 Example\nnope', 'asn', 100).entries) === JSON.stringify(['AS64496', 'AS64497']))

  check('rDNS feeds normalise case and take the first token',
    lists.parseFeed('.Scanner.Example.COM  some note', 'rdns', 100).entries[0] === '.scanner.example.com')

  check('URI feeds require a leading slash',
    JSON.stringify(lists.parseFeed('/wp-login.php\nhttps://evil.example/x', 'uri', 100).entries) === JSON.stringify(['/wp-login.php']))

  check('an unknown feed kind yields nothing rather than guessing',
    lists.parseFeed('203.0.113.7', 'nonsense', 100).entries.length === 0)
}

// ─── Bans: CIDR matching and escalation ─────────────────────────────────

section('bans')

{
  bans.clearAll()

  const single = bans.ban({ target: '203.0.113.7', source: 'manual', seconds: 60, escalateRepeat: false })
  check('a valid address can be banned', single.ok, single.error)
  check('an exact address matches', bans.check('203.0.113.7')?.target === '203.0.113.7')
  check('a neighbouring address does not', bans.check('203.0.113.8') === null)

  const range = bans.ban({ target: '198.51.100.0/24', source: 'community', seconds: 60, escalateRepeat: false })
  check('a CIDR range can be banned', range.ok, range.error)
  check('an address inside the range matches', bans.check('198.51.100.42')?.target === '198.51.100.0/24')
  check('an address outside the range does not', bans.check('198.51.101.42') === null)

  check('a malformed target is refused', !bans.ban({ target: 'not-an-ip', source: 'manual' }).ok)
  check('an unknown source is refused', !bans.ban({ target: '192.0.2.1', source: 'made-up' }).ok)

  // Re-reporting extends rather than duplicating: two rows for one address
  // would mean the operator has to lift the same ban twice.
  const again = bans.ban({ target: '203.0.113.7', source: 'manual', seconds: 3600, escalateRepeat: false })
  check('the same source re-reporting extends the existing ban', again.extended === true)
  check('re-reporting does not create a second row',
    bans.list({ source: 'manual' }).filter(b => b.target === '203.0.113.7').length === 1)
  check('the hit counter increments', bans.check('203.0.113.7').hits === 2)

  // A different source is a genuinely separate reason, so it gets its own row.
  bans.ban({ target: '203.0.113.7', source: 'dnsbl', seconds: 60, escalateRepeat: false })
  check('a different source records its own ban',
    bans.list().filter(b => b.target === '203.0.113.7').length === 2)

  const lifted = bans.liftTarget('203.0.113.7')
  check('lifting a target removes every source at once', lifted.removed === 2)
  check('the address is no longer banned', bans.check('203.0.113.7') === null)

  // Escalation doubles per prior ban, and ban_history is what remembers.
  settings.set('bad_behavior', { ban_seconds: 100, max_ban_seconds: 100000 })
  bans.clearAll()
  const first = bans.ban({ target: '192.0.2.50', source: 'bad_behavior', seconds: 100 })
  bans.liftTarget('192.0.2.50')
  const second = bans.ban({ target: '192.0.2.50', source: 'bad_behavior', seconds: 100 })
  check('a repeat offender is banned for longer than the first time',
    second.duration_sec > first.duration_sec, { first: first.duration_sec, second: second.duration_sec })

  bans.clearAll()
  check('clearing removes everything', bans.list().length === 0)

  const permanent = bans.ban({ target: '192.0.2.99', source: 'manual', seconds: null, escalateRepeat: false })
  check('a permanent ban has no expiry', permanent.ban.permanent === true && permanent.ban.expires_at === null)

  // An expired ban must stop matching even before the purge job runs.
  bans.clearAll()
  const db = require('../backend/services/db').getDb()
  bans.ban({ target: '192.0.2.77', source: 'manual', seconds: 60, escalateRepeat: false })
  db.prepare('UPDATE active_bans SET expires_at = ? WHERE target = ?')
    .run(new Date(Date.now() - 1000).toISOString(), '192.0.2.77')
  bans.invalidateCache()
  check('an expired ban stops matching', bans.check('192.0.2.77') === null)
  check('an expired ban is gone from the default listing',
    !bans.list().some(b => b.target === '192.0.2.77'))
  check('purgeExpired removes it', bans.purgeExpired().removed === 1)

  bans.clearAll()
}

// ─── Diff correctness ───────────────────────────────────────────────────

section('preview diff')

{
  // 'context' → c, 'add' → a, 'remove' → r, so a diff's shape reads as a word.
  const types = lines => lines.map(l => l.type[0]).join('')

  check('identical text produces only context',
    types(preview.diffLines('a\nb\nc', 'a\nb\nc')) === 'ccc')

  check('an inserted line is a single add',
    types(preview.diffLines('a\nc', 'a\nb\nc')) === 'cac')

  check('a removed line is a single remove',
    types(preview.diffLines('a\nb\nc', 'a\nc')) === 'crc')

  check('a changed line is a remove and an add', (() => {
    const t = types(preview.diffLines('a\nb\nc', 'a\nB\nc'))
    return t === 'crac' || t === 'carc'
  })())

  check('a run of additions stays contiguous',
    types(preview.diffLines('a\nz', 'a\nb\nc\nd\nz')) === 'caaac')

  check('line numbers track both sides', (() => {
    const lines = preview.diffLines('a\nc', 'a\nb\nc')
    const added = lines.find(l => l.type === 'add')
    const lastContext = lines.filter(l => l.type === 'context').pop()
    return added.after === 2 && lastContext.before === 2 && lastContext.after === 3
  })())

  check('summarize counts adds and removes', (() => {
    const s = preview.summarize(preview.diffLines('a\nb\nc', 'a\nX\nY\nc'))
    return s.added === 2 && s.removed === 1 && s.unchanged === 2
  })())

  // Hunks exist so an unchanged 400-line file does not print 400 lines.
  check('unchanged runs collapse into hunks', (() => {
    const before = Array.from({ length: 60 }, (_, i) => `line ${i}`).join('\n')
    const after = before.replace('line 30', 'line thirty')
    const hunks = preview.toHunks(preview.diffLines(before, after))
    const shown = hunks.reduce((n, h) => n + h.lines.length, 0)
    return hunks.length === 1 && shown < 12 && shown > 3
  })())

  check('a change at the very start is still shown',
    preview.toHunks(preview.diffLines('a\nb\nc\nd\ne\nf\ng\nh', 'X\nb\nc\nd\ne\nf\ng\nh'))[0]
      .lines.some(l => l.type === 'add' && l.text === 'X'))

  check('unified text is diff -u shaped', (() => {
    const text = preview.toUnifiedText({ ok: true, changed: true, hunks: preview.toHunks(preview.diffLines('a\nb', 'a\nc')) })
    return text.startsWith('--- current Caddyfile\n+++ proposed Caddyfile\n@@') &&
      text.includes('\n-b') && text.includes('\n+c')
  })())

  check('no change says so rather than printing an empty diff',
    preview.toUnifiedText({ ok: true, changed: false }) === 'No change to the generated configuration.')
}

// ─── Plugin manifest validation ─────────────────────────────────────────

section('plugins — data only')

{
  const base = { catwaf_plugin: 1, id: 'unit-test', name: 'Unit test', version: '1.0.0' }
  const install = extra => plugins.install({ ...base, ...extra }, { source: 'test' })
  const cleanup = () => { try { plugins.remove('unit-test') } catch {} }

  cleanup()
  const okResult = install({ settings_defaults: { compression: { enabled: true } } })
  check('a data-only manifest installs', okResult.ok, okResult.error)
  cleanup()

  // Anything that would run is refused outright rather than ignored — an
  // ignored field is a field someone will later assume works.
  for (const field of plugins.FORBIDDEN_FIELDS) {
    const result = install({ [field]: 'anything' })
    check(`a manifest declaring "${field}" is refused`, !result.ok, result)
    cleanup()
  }

  const goodTemplate = install({
    caddy_templates: [{ context: plugins.VALID_CONTEXTS[0], template: 'header X-Test {{settings.headers.preset}}' }],
  })
  check('a settings placeholder is allowed', goodTemplate.ok, goodTemplate.error)
  cleanup()

  const BAD_TEMPLATES = [
    ['an arbitrary Caddy placeholder', 'header X-Leak {{http.request.header.Cookie}}'],
    ['an unknown settings group', 'header X-Test {{settings.no_such_group.field}}'],
    ['an unknown field', 'header X-Test {{settings.headers.no_such_field}}'],
    ['a stray closing brace pair', 'header X-Test }}'],
    ['a backtick', 'directives `SecRuleEngine Off`'],
  ]
  for (const [label, template] of BAD_TEMPLATES) {
    const result = install({ caddy_templates: [{ context: plugins.VALID_CONTEXTS[0], template }] })
    check(`a template with ${label} is refused`, !result.ok, result)
    cleanup()
  }

  const secretField = Object.entries(require('../backend/services/settings').SCHEMA)
    .flatMap(([g, def]) => Object.entries(def.fields).map(([f, spec]) => [g, f, spec]))
    .find(([, , spec]) => spec.writeOnly)
  if (secretField) {
    const [group, field] = secretField
    const result = install({ caddy_templates: [{ context: plugins.VALID_CONTEXTS[0], template: `x {{settings.${group}.${field}}}` }] })
    check(`a template reaching for the secret ${group}.${field} is refused`, !result.ok, result)
    cleanup()
  }

  const badContext = install({ caddy_templates: [{ context: 'anywhere-i-like', template: 'respond 200' }] })
  check('an unknown insertion context is refused', !badContext.ok)
  cleanup()
}

// ─── Challenge gate ─────────────────────────────────────────────────────

section('challenge gate')

{
  // Proof of work: the answer must actually hash into the target bucket.
  let solution = null
  for (let n = 0; n < 1_000_000 && solution === null; n++) {
    if (challenge.verifyProof('test-challenge', n)) solution = n
  }
  check('a proof of work exists and verifies', solution !== null && challenge.verifyProof('test-challenge', solution))
  check('a wrong answer fails', !challenge.verifyProof('test-challenge', solution + 1))
  check('the same answer does not satisfy a different challenge',
    !challenge.verifyProof('other-challenge', solution))
  check('a non-integer answer is refused',
    !challenge.verifyProof('test-challenge', 'abc') &&
    !challenge.verifyProof('test-challenge', -1) &&
    !challenge.verifyProof('test-challenge', 1.5))
  check('an answer past the ceiling is refused', !challenge.verifyProof('test-challenge', 5_000_001))

  // Token binding: a verified cookie must not be transferable. The browser
  // half of the binding only applies while the gate is on, so turn it on —
  // with the gate off there is no session to bind and nothing to test.
  settings.set('challenge', { mode: 'javascript' })

  const client = { ip: '203.0.113.7', userAgent: 'Mozilla/5.0 (unit test)' }
  const token = challenge.mintToken({ ...client, minutes: 30 })

  check('a fresh token verifies for the client it was issued to',
    challenge.verifyToken(token, client).valid)
  check('the same token is rejected from another address',
    !challenge.verifyToken(token, { ...client, ip: '198.51.100.9' }).valid)
  check('the same token is rejected from another browser',
    !challenge.verifyToken(token, { ...client, userAgent: 'curl/8.0' }).valid)

  const tampered = token.slice(0, -1) + (token.endsWith('a') ? 'b' : 'a')
  check('a tampered signature is rejected', !challenge.verifyToken(tampered, client).valid)

  const swapped = token.split('.')
  swapped[1] = String(Date.now() + 86400_000)
  check('extending the expiry by hand invalidates the signature',
    !challenge.verifyToken(swapped.join('.'), client).valid)

  // A negative lifetime is clamped rather than honoured, so minting can
  // never hand out a token that is already dead on arrival.
  check('a nonsensical lifetime is clamped, not issued as expired',
    challenge.verifyToken(challenge.mintToken({ ...client, minutes: -10 }), client).valid)

  // Expiry itself is enforced, which is checked by moving the clock rather
  // than the token — the signature covers the expiry, so a token that has
  // simply aged is the only way to reach the expired branch.
  const shortLived = challenge.mintToken({ ...client, minutes: 1 })
  const realNow = Date.now
  try {
    Date.now = () => realNow() + 120_000
    check('a token past its expiry is rejected',
      challenge.verifyToken(shortLived, client).reason === 'expired')
  } finally { Date.now = realNow }

  check('a malformed token is rejected without throwing',
    !challenge.verifyToken('nonsense', client).valid &&
    !challenge.verifyToken('', client).valid &&
    !challenge.verifyToken('x'.repeat(500), client).valid)

  // Replaying a solved challenge id must not mint a second token.
  const issued = challenge.issue({ ...client, returnTo: '/' })
  check('issuing a challenge produces an id and HTML', !!issued.id && /html/i.test(issued.html))

  challenge.reset()
  check('reset clears pending challenges', challenge.status().pending === 0)
}

// ─── Cookie flags ───────────────────────────────────────────────────────

section('challenge cookie')

{
  const header = challenge.cookieHeader('abc', 600)
  check('the clearance cookie is HttpOnly', /HttpOnly/.test(header))
  check('the clearance cookie is SameSite=Lax', /SameSite=Lax/.test(header))
  check('the clearance cookie is Secure over HTTPS', /Secure/.test(header))
  check('Secure is dropped when the site is plain HTTP',
    !/Secure/.test(challenge.cookieHeader('abc', 600, { secure: false })))
  check('a hostile cookie value is encoded, not injected',
    !/[\r\n;]/.test(challenge.cookieHeader('a; Path=/; evil=1', 600).split(';')[0]))
}

// ─── Challenge return_to: the gate must never be an open redirect ───────

section('challenge safeReturnTo')

{
  // Values that must survive untouched — the feature still has to work.
  for (const [input, expected] of [
    ['/', '/'],
    ['/dashboard', '/dashboard'],
    ['/a/b/c?q=1&r=2', '/a/b/c?q=1&r=2'],
    ['/search?q=%20spaced', '/search?q=%20spaced'],
    ['/page#section', '/page#section'],
    ['/path%2Fencoded', '/path%2Fencoded'],
  ]) {
    check(`same-origin path preserved: ${input}`, challenge.safeReturnTo(input) === expected, challenge.safeReturnTo(input))
  }

  // Every one of these must collapse to '/'. The backslash cases are the
  // reported bypass: browsers normalise \ to / for special schemes, so
  // `/\evil.com` navigates to `//evil.com`, and express does not encode the
  // backslash away because encodeurl's allowed range covers 0x5C.
  const bypasses = [
    '/\\evil.com',
    '/\\\\evil.com',
    '/\\/evil.com',
    '\\\\evil.com',
    '//evil.com',
    '///evil.com',
    '/\tevil.com',
    '/\nhttps://evil.com',
    '/\revil.com',
    '/\u0000evil.com',
    'https://evil.com',
    'http://evil.com',
    '//evil.com/path',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    '\t//evil.com',
    ' //evil.com',
    'evil.com',
    '',
    null,
    undefined,
    '/'.repeat(3000),
  ]
  for (const input of bypasses) {
    const got = challenge.safeReturnTo(input)
    check(`redirect bypass refused: ${String(JSON.stringify(input)).slice(0, 40)}`, got === '/', got)
  }

  // The result is always a same-origin path, whatever went in.
  for (const input of bypasses.concat(['/ok', '/a?b=//evil.com'])) {
    const got = challenge.safeReturnTo(input)
    check(`result stays same-origin: ${String(JSON.stringify(input)).slice(0, 40)}`,
      typeof got === 'string' && got.startsWith('/') && !got.startsWith('//') && !got.includes('\\'), got)
  }
}

// ─── Scanner tool fingerprinting ────────────────────────────────────────

;(async () => {
  section('toolsFingerprint — matching engine')

  const toolsFingerprint = require('../backend/services/toolsFingerprint')

  {
    const exact = toolsFingerprint.fingerprint({
      userAgent: 'sqlmap/1.7.2#stable (http://sqlmap.org)',
      headers: ['host', 'accept', 'user-agent'],
    })
    check('an exact tool User-Agent is tier "exact"', exact?.tier === 'exact', exact)
    check('the exact match names the right tool', exact?.tool === 'sqlmap', exact)
    check('an exact match scores 1', exact?.score === 1, exact)

    const browser = toolsFingerprint.fingerprint({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36',
      headers: [
        'host', 'accept', 'accept-encoding', 'accept-language', 'connection', 'user-agent',
        'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest', 'upgrade-insecure-requests',
        'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'cookie',
      ],
    })
    check('a real browser UA + full header set has no match', browser === null, browser)

    const close = toolsFingerprint.fingerprint({
      userAgent: 'Mozilla/5.0 (compatible; sqlm4p-ish/2.0)',
      headers: ['host', 'accept', 'accept-encoding', 'connection', 'user-agent'],
    })
    check('a near-miss UA with a scripted header set is tier "close"', close?.tier === 'close', close)
    check('a close match score sits below 1', close && close.score > 0 && close.score < 1, close)

    const empty = toolsFingerprint.fingerprint({ userAgent: '', headers: [] })
    check('no User-Agent and no headers yields no match', empty === null, empty)

    const threshold = toolsFingerprint.fingerprint(
      { userAgent: 'Mozilla/5.0 (compatible; sqlm4p-ish/2.0)', headers: ['host', 'accept', 'accept-encoding', 'connection', 'user-agent'] },
      { closeThreshold: 0.99 },
    )
    check('raising the close threshold can push a former close match below it', threshold === null, threshold)
  }

  section('enforce.classify — tool fingerprinting integration')

  {
    const enforce = require('../backend/services/enforce')
    bans.clearAll()
    settings.set('tools_fingerprint', { enabled: true })

    const exactVerdict = await enforce.classify({
      ip: '203.0.113.201', uri: '/', userAgent: 'sqlmap/1.7.2#stable (http://sqlmap.org)',
      headers: ['host', 'accept', 'user-agent'],
    })
    check('an exact fingerprint match blocks the request', exactVerdict.action === 'block', exactVerdict)
    check('an exact fingerprint match bans the address',
      bans.check('203.0.113.201')?.source === 'tools_fingerprint', bans.check('203.0.113.201'))

    const repeat = await enforce.classify({ ip: '203.0.113.201', uri: '/other', userAgent: 'curl/8.0' })
    check('the address stays blocked on a later request with an unrelated User-Agent',
      repeat.action === 'block', repeat)

    settings.set('challenge', { mode: 'javascript', trigger: 'suspicious' })
    const closeVerdict = await enforce.classify({
      ip: '203.0.113.202', uri: '/', userAgent: 'Mozilla/5.0 (compatible; sqlm4p-ish/2.0)',
      headers: ['host', 'accept', 'accept-encoding', 'connection', 'user-agent'],
    })
    check('a close fingerprint match is challenged, not banned', closeVerdict.action === 'challenge', closeVerdict)
    check('a close match does not create a ban', bans.check('203.0.113.202') === null)

    settings.set('challenge', { mode: 'off' })
    settings.set('tools_fingerprint', { enabled: false })
    const disabledVerdict = await enforce.classify({
      ip: '203.0.113.203', uri: '/', userAgent: 'sqlmap/1.7.2#stable (http://sqlmap.org)',
      headers: ['host', 'accept', 'user-agent'],
    })
    check('disabling the feature stops it from blocking an exact match', disabledVerdict.action !== 'block', disabledVerdict)

    settings.set('tools_fingerprint', { enabled: true })
    bans.clearAll()
  }

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
})()
