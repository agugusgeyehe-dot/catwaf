#!/usr/bin/env node

const fs = require('fs')
const os = require('os')
const path = require('path')
const { execFileSync } = require('child_process')

const ROOT = path.join(__dirname, '..')
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-waftools-'))

process.env.DB_DIR = path.join(WORK, 'db')
process.env.CADDYFILE_PATH = path.join(WORK, 'Caddyfile')
process.env.CORAZA_AUDIT_LOG = path.join(WORK, 'logs', 'audit.json')
process.env.JWT_SECRET = 't'.repeat(64)
// Never let a reload reach a Caddy the developer is running locally:
// `caddy reload` targets CADDY_ADMIN_URL, which defaults to :2019.
process.env.CADDY_ADMIN_URL = 'http://127.0.0.1:19918'

fs.mkdirSync(process.env.DB_DIR, { recursive: true })
fs.mkdirSync(path.join(WORK, 'logs'), { recursive: true })

const BASE_CADDYFILE = [
  '{',
  '    order coraza_waf first',
  '}',
  '',
  ':9990 {',
  '    respond "upstream" 200',
  '}',
  '',
].join('\n')
fs.writeFileSync(process.env.CADDYFILE_PATH, BASE_CADDYFILE)

let pass = 0, fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra !== undefined ? JSON.stringify(extra) : '') }
}
function section(t) { console.log('\n== ' + t + ' ==') }
process.on('exit', () => { try { fs.rmSync(WORK, { recursive: true, force: true }) } catch {} })

const state = require(path.join(ROOT, 'backend/services/state.js'))
const db = require(path.join(ROOT, 'backend/services/db.js'))
const caddySvc = require(path.join(ROOT, 'backend/services/caddy.js'))
const rulesSvc = require(path.join(ROOT, 'backend/services/rules.js'))
const eventsSvc = require(path.join(ROOT, 'backend/services/events.js'))
const modesSvc = require(path.join(ROOT, 'backend/services/modes.js'))
const snapshotsSvc = require(path.join(ROOT, 'backend/services/snapshots.js'))
const configTx = require(path.join(ROOT, 'backend/services/configTx.js'))
const requestLog = require(path.join(ROOT, 'backend/services/requestLog.js'))
const simulateSvc = require(path.join(ROOT, 'backend/services/simulate.js'))
const healthcheckSvc = require(path.join(ROOT, 'backend/services/healthcheck.js'))
const securityTestSvc = require(path.join(ROOT, 'backend/services/securityTest.js'))

function caddyWithCoraza() {
  try { return execFileSync('caddy', ['list-modules'], { timeout: 8000 }).toString().includes('http.handlers.waf') }
  catch { return false }
}
const HAVE_CADDY = caddyWithCoraza()

function seedEvent(overrides = {}) {
  const row = {
    id: overrides.id || require('crypto').randomBytes(6).toString('hex'),
    ts: overrides.ts || new Date().toISOString(),
    ip: '203.0.113.9',
    method: 'GET',
    uri: '/?password=hunter2&id=1+UNION+SELECT+1--',
    status: 403,
    action: 'block',
    attack_type: 'SQLi',
    rule_ids: JSON.stringify(['942100', '942190', '949110']),
    score: 18,
    user_agent: 'curl/8.0',
    severity: 'critical',
    reason: 'SQL Injection Attack Detected via libinjection',
    matched_var: 'ARGS:id',
    ...overrides,
  }
  db.getDb().prepare(`
    INSERT OR REPLACE INTO request_log (id, ts, ip, method, uri, status, action, attack_type, rule_ids, score, user_agent, severity, reason, matched_var)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(row.id, row.ts, row.ip, row.method, row.uri, row.status, row.action, row.attack_type, row.rule_ids, row.score, row.user_agent, row.severity, row.reason, row.matched_var)
  return row.id
}

;(async () => {

  section('CRS rule index')
  const idx = rulesSvc.getIndex()
  check('rule index builds without throwing', !!idx)
  check('isValidRuleId accepts a CRS id', rulesSvc.isValidRuleId('942100'))
  check('isValidRuleId rejects path traversal', !rulesSvc.isValidRuleId('../../etc/passwd'))
  check('isValidRuleId rejects command injection', !rulesSvc.isValidRuleId('942100; rm -rf /'))
  check('isValidRuleId rejects an empty string', !rulesSvc.isValidRuleId(''))
  check('validateRuleIdOrThrow throws on bad input', (() => {
    try { rulesSvc.validateRuleIdOrThrow('abc'); return false } catch { return true }
  })())

  const parsed = rulesSvc.parseConfFile(
    `SecRule ARGS "@rx foo" \\\n  "id:942100,\\\n  phase:2,\\\n  msg:'Test SQLi rule',\\\n  severity:'CRITICAL',\\\n  tag:'paranoia-level/2',\\\n  ver:'OWASP_CRS/4.0.0'"`,
    'TEST.conf'
  )
  check('conf parser extracts the rule id', parsed[0]?.id === '942100', parsed[0])
  check('conf parser extracts the message', parsed[0]?.msg === 'Test SQLi rule', parsed[0])
  check('conf parser extracts severity', parsed[0]?.severity === 'critical', parsed[0])
  check('conf parser extracts the paranoia level tag', parsed[0]?.paranoia_level === 2, parsed[0])

  const desc = rulesSvc.describe('942100')
  check('describe returns a stable shape', 'id' in desc && 'enabled' in desc && 'category' in desc)
  check('unknown rule ids are reported as unknown, not invented', rulesSvc.describe('9999999').known === false)

  section('rule search and list')
  // The rule index is built from CRS .conf files on disk. A Caddy binary with
  // Coraza compiled in embeds the CRS instead of shipping those files, and
  // this test runs against an isolated temp database so there is no observed
  // traffic to fall back on either — on a clean install there is simply
  // nothing to search. Assert the real behaviour when an index exists and say
  // so plainly when it does not, rather than failing an install that is fine
  // or faking an index that isn't there.
  const indexed = rulesSvc.list({ limit: 1 }).total > 0
  if (indexed) {
    const search = rulesSvc.search('942100')
    check('exact rule id search finds the rule', search.rules.some(r => r.id === '942100'), search.total)
  } else {
    console.log('  SKIP  no CRS rule index on this host (no rule files, no observed traffic).')
    console.log('        Set CATWAF_CRS_PATH to a CRS rules directory to exercise this.')
  }
  check('empty query returns nothing', rulesSvc.search('').total === 0)
  const listed = rulesSvc.list({ limit: 5 })
  check('list respects the limit', listed.rules.length <= 5)
  check('list reports a total', typeof listed.total === 'number')

  section('rule enable/disable changes real configuration')
  const before = JSON.parse(JSON.stringify(state.WAF.disabled_rules || []))
  const txDisable = configTx.apply({
    label: 'test.disable',
    reload: false,
    mutate: () => rulesSvc.setRuleEnabled('941110', false),
  })
  check('disabling a rule succeeds', txDisable.ok, txDisable.error)
  check('disabled_rules records the rule', (state.WAF.disabled_rules || []).includes('941110'))
  check('rule reports itself disabled', rulesSvc.describe('941110').enabled === false)

  const caddyfileBody = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
  check('Caddyfile contains a real SecRuleRemoveById directive', caddyfileBody.includes('SecRuleRemoveById 941110'))
  check('a backup was written before the change', !!txDisable.backup && fs.existsSync(txDisable.backup))

  const txDouble = configTx.apply({
    label: 'test.disable-again',
    reload: false,
    mutate: () => {
      const r = rulesSvc.setRuleEnabled('941110', false)
      if (!r.changed) throw new Error(r.reason)
      return r
    },
  })
  check('disabling an already-disabled rule is refused', !txDouble.ok && /already disabled/.test(txDouble.error || ''), txDouble.error)
  check('the refused change rolled back cleanly', txDouble.rolledBack === true)

  const txEnable = configTx.apply({
    label: 'test.enable',
    reload: false,
    mutate: () => rulesSvc.setRuleEnabled('941110', true),
  })
  check('re-enabling the rule succeeds', txEnable.ok, txEnable.error)
  check('the directive is gone again', !fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8').includes('SecRuleRemoveById 941110'))
  check('disabled_rules is back to its original value',
    JSON.stringify(state.WAF.disabled_rules) === JSON.stringify(before), state.WAF.disabled_rules)

  section('failed configuration rolls back automatically')
  const goodBody = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
  const plBefore = state.WAF.paranoia_level
  const txBad = configTx.apply({
    label: 'test.invalid',
    reload: false,
    mutate: (s) => { s.WAF.paranoia_level = 99; return { bad: true } },
    validate: (s) => (s.WAF.paranoia_level > 4 ? { ok: false, error: 'paranoia level out of range' } : { ok: true }),
  })
  check('invalid change is rejected', txBad.ok === false)
  check('rollback is reported', txBad.rolledBack === true)
  check('in-memory state was restored', state.WAF.paranoia_level === plBefore, state.WAF.paranoia_level)
  check('the Caddyfile was restored byte-for-byte', fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8') === goodBody)

  section('Caddyfile injection targets a site block, never global options')
  check('refuses a Caddyfile with only global options', caddySvc.lastSiteBlockClose('{\n  order coraza_waf first\n}\n') === -1)
  check('finds the site block when one exists', caddySvc.lastSiteBlockClose('{\n}\n\n:80 {\n  file_server\n}\n') > 0)
  check('handles a Caddyfile with no global block', caddySvc.lastSiteBlockClose(':80 {\n  file_server\n}\n') > 0)

  section('operating modes')
  check('four modes are defined', modesSvc.listModes().length === 4)
  check('learning mode is declared non-blocking', modesSvc.MODES.learning.blocks === false)
  check('learning mode carries an explicit warning', /DOES NOT BLOCK/i.test(modesSvc.MODES.learning.warning || ''))
  check('lockdown mode warns about false positives', /false positive/i.test(modesSvc.MODES.lockdown.warning || ''))
  check('maintenance mode keeps blocking on', modesSvc.MODES.maintenance.settings.engine === 'On')
  check('maintenance mode does not weaken paranoia', modesSvc.MODES.maintenance.settings.paranoia_level >= 1)
  check('an unknown mode is rejected', modesSvc.setMode('bogus').ok === false)

  const lock = modesSvc.setMode('lockdown', { reload: false })
  check('lockdown applies', lock.ok, lock.error)
  check('lockdown really raises paranoia to 4', state.WAF.paranoia_level === 4, state.WAF.paranoia_level)
  check('lockdown is reflected in the Caddyfile',
    fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8').includes('blocking_paranoia_level=4'))

  const learn = modesSvc.setMode('learning', { reload: false })
  check('learning applies', learn.ok, learn.error)
  check('learning sets DetectionOnly in real config',
    fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8').includes('SecRuleEngine DetectionOnly'))
  check('current() reports learning as non-blocking', modesSvc.current().blocks === false)

  modesSvc.setMode('normal', { reload: false })
  check('normal restores enforcement', state.WAF.engine === 'On' && state.WAF.paranoia_level === 1)
  check('current() reports the declared mode', modesSvc.current().mode === 'normal')

  state.WAF.paranoia_level = 3
  check('drift from the declared mode is detected', modesSvc.current().drifted === true)
  modesSvc.setMode('normal', { reload: false })

  section('paranoia levels are real CRS configuration')
  for (const lvl of [1, 2, 3, 4]) {
    const tx = configTx.apply({
      label: `test.pl${lvl}`,
      reload: false,
      mutate: (s) => { s.WAF.paranoia_level = lvl; if (s.WAF.executing_paranoia_level < lvl) s.WAF.executing_paranoia_level = lvl },
    })
    const body = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
    check(`PL${lvl} writes tx.blocking_paranoia_level=${lvl}`, tx.ok && body.includes(`blocking_paranoia_level=${lvl}`), tx.error)
  }
  const txPl = configTx.apply({
    label: 'test.pl-invalid',
    reload: false,
    mutate: (s) => { s.WAF.executing_paranoia_level = 1; s.WAF.paranoia_level = 4 },
    validate: (s) => (s.WAF.executing_paranoia_level < s.WAF.paranoia_level ? { ok: false, error: 'detection below blocking' } : { ok: true }),
  })
  check('detection level below blocking level is rejected', txPl.ok === false)
  modesSvc.setMode('normal', { reload: false })

  section('snapshots')
  state.WAF.alerts.slack_webhook = 'https://hooks.slack.com/services/SECRETVALUE'
  const snap = snapshotsSvc.create({ label: 'test-snapshot' })
  check('snapshot has an id and timestamp', !!snap.id && !!snap.timestamp)
  check('snapshot ids validate', snapshotsSvc.isValidSnapshotId(snap.id))
  check('bogus snapshot ids are rejected', !snapshotsSvc.isValidSnapshotId('../../etc/passwd'))
  check('unknown snapshot returns an error, not a throw', snapshotsSvc.view('deadbeef').ok === false)

  const viewed = snapshotsSvc.view(snap.id)
  check('snapshot view redacts secrets', viewed.state.alerts.slack_webhook === '[REDACTED]', viewed.state.alerts)
  check('snapshot list includes the new snapshot', snapshotsSvc.list().some(s => s.id === snap.id))

  modesSvc.setMode('lockdown', { reload: false })
  const d = snapshotsSvc.diff(snap.id)
  check('diff detects the paranoia change', d.changes.some(c => c.key === 'paranoia_level'), d.changes.map(c => c.key))
  check('diff never prints secret values', !JSON.stringify(d).includes('SECRETVALUE'))

  const restored = snapshotsSvc.restore(snap.id, { reload: false })
  check('restore succeeds', restored.ok, restored.error)
  check('restore actually reverts paranoia', state.WAF.paranoia_level === 1, state.WAF.paranoia_level)
  check('restore creates a safety snapshot first', !!restored.safety_snapshot)

  const badSnapId = seedEvent({ id: 'aaaaaaaaaaaa' })
  check('restoring a non-snapshot id fails cleanly', snapshotsSvc.restore('ffffffffffff').ok === false)

  section('explain')
  const evtId = seedEvent()
  const ex = eventsSvc.explain({ id: evtId })
  check('explain finds a seeded event', ex.ok, ex.error)
  check('explain reports the event id', ex.event.id === evtId)
  check('explain reports the attack type', ex.event.attack_type === 'SQLi')
  check('explain reports severity', ex.event.severity === 'critical')
  check('explain reports the anomaly score', ex.event.anomaly_score === 18)
  check('explain reports the paranoia level', ex.waf.paranoia_level === state.WAF.paranoia_level)
  check('explain lists matched rules', ex.matched_rules.length === 3, ex.matched_rules.length)
  check('explain picks the decisive rule from the attack category', ex.primary_rule === '942100', ex.primary_rule)
  check('explain reports the matched component from the real matched variable', /"id"/.test(ex.matched_component || ''), ex.matched_component)
  check('explain gives remediation advice', ex.remediation.length > 0)
  check('explain explains why', /interrupted|never reached/.test(ex.why))

  check('explain REDACTS sensitive query parameters', ex.event.uri.includes('password=[REDACTED]'), ex.event.uri)
  check('explain never leaks the secret value', !JSON.stringify(ex).includes('hunter2'))
  check('explain records which keys were redacted', ex.event.redacted_query_keys.includes('password'))

  check('explain rejects a traversal-style event id', eventsSvc.explain({ id: '../../etc/passwd' }).ok === false)
  check('explain rejects an injection-style event id', eventsSvc.explain({ id: 'a; rm -rf /' }).ok === false)
  check('explain reports a missing event honestly', eventsSvc.explain({ id: 'abcdef123456' }).ok === false)

  const exLast = eventsSvc.explain({ last: true })
  check('explain --last returns the most recent event', exLast.ok)

  section('sanitization helpers')
  const s1 = eventsSvc.sanitizeUri('/x?token=abc&q=1')
  check('token query parameters are redacted', s1.uri.includes('token=[REDACTED]'))
  check('non-sensitive parameters are preserved', s1.uri.includes('q=1'))
  const s2 = eventsSvc.sanitizeUri('/plain/path')
  check('paths without a query are unchanged', s2.uri === '/plain/path')

  const red = simulateSvc.redactHeaders({ Authorization: 'Bearer abc', Cookie: 'a=b', 'User-Agent': 'curl' })
  check('Authorization header is stripped', !('authorization' in red.headers))
  check('Cookie header is stripped', !('cookie' in red.headers))
  check('benign headers survive', red.headers['user-agent'] === 'curl')
  check('stripped headers are reported', red.redacted.includes('authorization') && red.redacted.includes('cookie'))

  section('simulate input validation (SSRF and injection surface)')
  check('rejects a non-URL', simulateSvc.parseTargetUrl('not a url').ok === false)
  check('rejects file:// scheme', simulateSvc.parseTargetUrl('file:///etc/passwd').ok === false)
  check('rejects gopher:// scheme', simulateSvc.parseTargetUrl('gopher://x/').ok === false)
  check('accepts http', simulateSvc.parseTargetUrl('http://example.com/a?b=1').ok === true)
  check('accepts https', simulateSvc.parseTargetUrl('https://example.com/').ok === true)
  check('rejects an over-long URL', simulateSvc.parseTargetUrl('http://e.com/' + 'a'.repeat(9000)).ok === false)
  const parsedUrl = simulateSvc.parseTargetUrl('http://internal.example/admin?x=1')
  check('URL parsing extracts only method/target, never fetches', parsedUrl.target === '/admin?x=1' && parsedUrl.method === 'GET')
  check('URL simulation documents that it does not fetch', /does not fetch/i.test(parsedUrl.note || ''))

  const reqFile = simulateSvc.parseRequestFile('POST /login HTTP/1.1\nHost: x.test\nAuthorization: Bearer secret\n\n{"a":1}')
  check('request file parses the method', reqFile.method === 'POST')
  check('request file parses the target', reqFile.target === '/login')
  check('request file extracts Host separately', reqFile.host === 'x.test')
  check('request file rejects an unsupported method', simulateSvc.parseRequestFile('EVIL / HTTP/1.1\nHost: x\n').ok === false)
  check('request file rejects a malformed first line', simulateSvc.parseRequestFile('garbage\n').ok === false)
  check('request file rejects an oversized body',
    simulateSvc.parseRequestFile('POST / HTTP/1.1\nHost: x\n\n' + 'a'.repeat(300 * 1024)).ok === false)

  section('replay input validation')
  check('replay rejects a bad event id', (await eventsSvc.replay({ id: '../../x' })).ok === false)
  check('replay rejects an unknown event', (await eventsSvc.replay({ id: 'abcdef123456' })).ok === false)
  check('replay refuses a non-sandbox target', (await eventsSvc.replay({ id: evtId, target: 'production' })).ok === false)
  const replayReq = eventsSvc.buildReplayRequest({ uri: '/?password=x&id=1', method: 'GET', user_agent: 'curl' })
  check('replay request redacts secrets from the URI', replayReq.target.includes('[REDACTED]'), replayReq.target)

  section('audit summary and windows')
  check('parseWindow understands hours', requestLog.parseWindow('24h') === 86400000)
  check('parseWindow understands minutes', requestLog.parseWindow('30m') === 1800000)
  check('parseWindow understands days', requestLog.parseWindow('7d') === 604800000)
  check('parseWindow understands weeks', requestLog.parseWindow('2w') === 1209600000)
  check('parseWindow rejects nonsense', requestLog.parseWindow('bogus') === null)
  check('parseWindow rejects a negative window', requestLog.parseWindow('-5h') === null)
  check('parseWindow rejects an absurd window', requestLog.parseWindow('999999h') === null)

  seedEvent({ attack_type: 'XSS', severity: 'warning', score: 8, rule_ids: JSON.stringify(['941100']) })
  seedEvent({ attack_type: 'XSS', severity: 'critical', score: 12, rule_ids: JSON.stringify(['941100', '941110']) })
  const sum = requestLog.summarize({ sinceMs: 86400000 })
  check('summary counts total requests', sum.total_requests >= 3, sum.total_requests)
  check('summary counts blocked requests', sum.blocked_requests >= 3)
  check('summary computes a block rate', sum.block_rate > 0 && sum.block_rate <= 1, sum.block_rate)
  check('summary lists top attack types', sum.top_attack_types.length >= 2, sum.top_attack_types)
  check('summary lists severity distribution', sum.severity_distribution.length >= 1)
  check('summary lists top rules', sum.top_rules.length >= 1, sum.top_rules.slice(0, 2))
  check('summary computes anomaly statistics', sum.anomaly_score.average != null)
  check('summary has stable ISO timestamps', !Number.isNaN(Date.parse(sum.since)) && !Number.isNaN(Date.parse(sum.until)))

  const filtered = requestLog.summarize({ sinceMs: 86400000, attackType: 'XSS' })
  check('attack-type filter narrows results', filtered.total_requests === 2, filtered.total_requests)
  const sevFiltered = requestLog.summarize({ sinceMs: 86400000, severity: 'warning' })
  check('severity filter narrows results', sevFiltered.total_requests === 1, sevFiltered.total_requests)

  const old = seedEvent({ ts: new Date(Date.now() - 40 * 86400000).toISOString() })
  const recentOnly = requestLog.summarize({ sinceMs: 3600000 })
  const allTime = requestLog.summarize({ sinceMs: 60 * 86400000 })
  check('time windows exclude older events', allTime.total_requests > recentOnly.total_requests, { recentOnly: recentOnly.total_requests, allTime: allTime.total_requests })

  section('health check')
  const health = await healthcheckSvc.run()
  check('health returns a status', ['healthy', 'degraded', 'unhealthy'].includes(health.status), health.status)
  check('health returns an exit code matching the status',
    (health.status === 'healthy' && health.exit_code === 0) ||
    (health.status === 'degraded' && health.exit_code === 1) ||
    (health.status === 'unhealthy' && health.exit_code === 2), health)
  check('health includes component checks', health.checks.length >= 8, health.checks.length)
  check('health reports on Caddy', health.checks.some(c => c.name === 'Caddy'))
  check('health reports on Coraza', health.checks.some(c => /Coraza/.test(c.name)))
  check('health reports on the database', health.checks.some(c => c.name === 'Database'))
  check('health reports on WAF interception', health.checks.some(c => /interception/i.test(c.name)))
  check('worst() escalates correctly', healthcheckSvc.worst(['healthy', 'degraded', 'unhealthy']) === 'unhealthy')
  check('worst() of all healthy is healthy', healthcheckSvc.worst(['healthy', 'healthy']) === 'healthy')

  section('security self-test')
  const sec = await securityTestSvc.run()
  check('security test returns severity counts', typeof sec.counts.critical === 'number')
  check('security test returns findings and passes', Array.isArray(sec.findings) && Array.isArray(sec.passed))
  check('security test exit code reflects severity',
    (sec.counts.critical > 0 && sec.exit_code === 2) ||
    (sec.counts.critical === 0 && sec.counts.high > 0 && sec.exit_code === 1) ||
    (sec.counts.critical === 0 && sec.counts.high === 0 && sec.exit_code === 0), sec.counts)
  check('security test does not claim absolute security', /does not mean|not a substitute/i.test(sec.disclaimer))
  check('security test checks the docker socket', JSON.stringify(sec).toLowerCase().includes('docker socket'))
  check('security test never prints secret values', !JSON.stringify(sec).includes(process.env.JWT_SECRET))

  section('live WAF simulation (real Coraza)')
  if (!HAVE_CADDY) {
    console.log('  SKIP  caddy with the Coraza module is unavailable — simulation cannot be faked')
  } else {
    modesSvc.setMode('normal', { reload: false })
    const benign = await simulateSvc.simulate({ url: 'http://example.test/products?page=2' })
    check('benign request simulates as allowed', benign.ok && benign.blocked === false, benign.error || benign)
    check('benign simulation reaches the local sink, not upstream', benign.upstreamReached === true)
    check('simulation is labelled as simulation', benign.simulation === true)
    check('simulation states it never contacted upstream', /never contacted|does not fetch/i.test(benign.note))

    const evil = await simulateSvc.simulate({ url: 'http://example.test/?id=1+UNION+SELECT+1,2,3--' })
    check('SQLi simulates as blocked', evil.ok && evil.blocked === true, evil.error || evil)
    check('blocked simulation never reached the sink', evil.upstreamReached === false)
    check('simulation reports matched rules', evil.rule_ids.length > 0, evil.rule_ids)
    check('simulation classifies the attack', evil.attack_type === 'SQLi', evil.attack_type)
    check('simulation reports severity', !!evil.severity)
    check('simulation reports an anomaly score', evil.anomaly_score != null)
    check('simulation reports the paranoia level used', evil.paranoia_level === state.WAF.paranoia_level)

    const raw = await simulateSvc.simulate({
      requestText: 'GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\nHost: example.test\nAuthorization: Bearer supersecret\n',
    })
    check('raw request file simulation works', raw.ok, raw.error)
    check('raw request simulates as blocked', raw.blocked === true)
    check('Authorization was stripped before simulation', !JSON.stringify(raw).includes('supersecret'))

    section('replay against the sandbox (real Coraza)')
    const replayed = await eventsSvc.replay({ id: evtId })
    check('replay runs', replayed.ok, replayed.error)
    check('replay is labelled as simulation', replayed.simulation === true)
    check('replay targets the sandbox', /sandbox/i.test(replayed.target))
    check('replay compares old and new detection', 'original' in replayed && 'current' in replayed)
    check('replay produces a verdict', ['still-blocked', 'regression', 'now-blocked', 'still-allowed'].includes(replayed.verdict), replayed.verdict)
    check('replay still detects the historical SQLi', replayed.current.blocked === true, replayed.current)
    check('replay never leaks the redacted secret', !JSON.stringify(replayed).includes('hunter2'))

    const txOff = configTx.apply({
      label: 'test.disable-sqli-category',
      reload: false,
      mutate: (s) => { s.RULE_CATEGORIES['942'].enabled = false },
    })
    check('disabling the SQLi category applies', txOff.ok, txOff.error)
    const regressed = await eventsSvc.replay({ id: evtId })
    check('replay detects a detection regression', regressed.ok && regressed.verdict === 'regression', regressed.verdict)
    check('regression verdict warns the user', /WARNING/i.test(regressed.verdict_text || ''))
    check('replay lists rules that stopped matching', regressed.changes.rules_no_longer_matching.length > 0)
    configTx.apply({ label: 'test.restore-sqli-category', reload: false, mutate: (s) => { s.RULE_CATEGORIES['942'].enabled = true } })
  }

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
})().catch(e => {
  console.error('\nharness error:', e.stack || e.message)
  process.exit(1)
})
