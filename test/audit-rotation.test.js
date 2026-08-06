#!/usr/bin/env node
// test/audit-rotation.test.js — Coraza audit-log rotation and retention.
//
// Coraza appends to its audit log forever and prunes nothing, so without
// rotation the disk eventually fills and the WAF stops.
//
// Rotation cannot rename-and-reopen: Coraza caches its audit writer by path,
// so the only way to retire a file without truncating it or restarting Caddy
// is to point SecAuditLog at a new one. These tests pin that behaviour and
// the guarantees around it — nothing is truncated, nothing is ingested
// twice, and the active log is never deleted.
//
// Each scenario runs in its own child process because the audit-log path is
// resolved when services/caddy.js is first required.

const fs = require('fs')
const os = require('os')
const path = require('path')
const { execFileSync } = require('child_process')

const ROOT = path.join(__dirname, '..')

let pass = 0, fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; console.log('  FAIL ' + name, extra !== undefined ? JSON.stringify(extra) : '') }
}
function section(t) { console.log('\n== ' + t + ' ==') }

const IS_ROOT = typeof process.getuid === 'function' && process.getuid() === 0

// A Coraza-shaped audit entry. `id` is what dedupe keys on.
function entry(id, uri = '/x') {
  return JSON.stringify({
    transaction: {
      id, timestamp: '2026/08/02 01:00:00', unix_timestamp: Date.now() * 1e6,
      client_ip: '10.0.0.1', is_interrupted: true,
      request: { method: 'GET', uri, headers: { 'User-Agent': 'test' } },
      response: { status: 403 },
    },
    messages: [{ message: 'x', error_message: '[id "942100"] [severity "critical"] [msg "SQLi"]' }],
  })
}

// Runs `body` in a child process against a throwaway install.
// `env` overrides; `files` seeds the audit-log directory.
function run(body, { env = {}, auditLines = null, caddyfile = null } = {}) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-rot-'))
  const logDir = path.join(work, 'logs')
  fs.mkdirSync(logDir, { recursive: true })
  const auditPath = path.join(logDir, 'coraza-audit.json')
  if (auditLines !== null) fs.writeFileSync(auditPath, auditLines)

  const caddyPath = path.join(work, 'Caddyfile')
  fs.writeFileSync(caddyPath, caddyfile !== null ? caddyfile : [
    '{', '    order coraza_waf first', '}', '',
    ':19993 {',
    '    respond "x" 200',
    '    coraza_waf {',
    '      directives `',
    `      SecAuditLog ${auditPath}`,
    '      `',
    '    }',
    '}', '',
  ].join('\n'))

  const script = `
    const fs = require('fs'), path = require('path')
    const ROOT = ${JSON.stringify(ROOT)}
    const WORK = ${JSON.stringify(work)}
    process.env.DB_DIR = path.join(WORK, 'db')
    process.env.CADDYFILE_PATH = ${JSON.stringify(caddyPath)}
    process.env.CORAZA_AUDIT_LOG = ${JSON.stringify(auditPath)}
    process.env.JWT_SECRET = 'a'.repeat(64)
    process.env.CADDY_ADMIN_URL = 'http://127.0.0.1:19915'
    fs.mkdirSync(process.env.DB_DIR, { recursive: true })
    const auditLogSvc = require(path.join(ROOT, 'backend/services/auditLog.js'))
    const caddySvc = require(path.join(ROOT, 'backend/services/caddy.js'))
    const requestLog = require(path.join(ROOT, 'backend/services/requestLog.js'))
    const AUDIT = ${JSON.stringify(auditPath)}
    const OUT = {}
    ;(function(){ ${body} })()
    console.log('@@' + JSON.stringify(OUT))
  `
  try {
    const out = execFileSync(process.execPath, ['--experimental-sqlite', '-e', script], {
      encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...env },
    })
    const line = out.split('\n').filter(l => l.startsWith('@@')).pop()
    return { ...JSON.parse(line.slice(2)), _work: work, _audit: auditPath, _caddy: caddyPath }
  } catch (e) {
    return { _error: String(e.stderr || e.message), _work: work, _audit: auditPath, _caddy: caddyPath }
  }
}
function cleanup(r) { try { fs.rmSync(r._work, { recursive: true, force: true }) } catch {} }

const { spawn } = require('child_process')
function haveCaddy() {
  try { execFileSync('caddy', ['version'], { timeout: 5000 }); return true } catch { return false }
}
const HAVE_CADDY = haveCaddy()
const sleep = ms => new Promise(r => setTimeout(r, ms))

// Rotation only completes if the proxy actually reloads onto the new path,
// so these scenarios run against a real Caddy rather than mocking the one
// step that makes rotation real.
async function runWithCaddy(body, { auditLines = null, sitePort, adminPort } = {}) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-rotlive-'))
  const logDir = path.join(work, 'logs')
  fs.mkdirSync(logDir, { recursive: true })
  const auditPath = path.join(logDir, 'coraza-audit.json')
  fs.writeFileSync(auditPath, auditLines || '')
  const caddyPath = path.join(work, 'Caddyfile')
  fs.writeFileSync(caddyPath, [
    '{', `    admin 127.0.0.1:${adminPort}`, '    order coraza_waf first', '}', '',
    `:${sitePort} {`,
    '    respond "x" 200',
    '    coraza_waf {',
    '      directives `',
    '      SecRuleEngine On',
    '      SecAuditEngine RelevantOnly',
    `      SecAuditLog ${auditPath}`,
    '      SecAuditLogFormat JSON',
    '      `',
    '    }',
    '}', '',
  ].join('\n'))

  const proc = spawn('caddy', ['run', '--config', caddyPath], { stdio: 'ignore' })
  // wait for the admin endpoint
  for (let i = 0; i < 60; i++) {
    try { execFileSync('curl', ['-sf', `http://127.0.0.1:${adminPort}/config/`], { timeout: 2000, stdio: 'ignore' }); break }
    catch { await sleep(250) }
  }

  const script = `
    const fs = require('fs'), path = require('path')
    const ROOT = ${JSON.stringify(ROOT)}
    process.env.DB_DIR = ${JSON.stringify(path.join(work, 'db'))}
    process.env.CADDYFILE_PATH = ${JSON.stringify(caddyPath)}
    process.env.CORAZA_AUDIT_LOG = ${JSON.stringify(auditPath)}
    process.env.JWT_SECRET = 'a'.repeat(64)
    process.env.CADDY_ADMIN_URL = 'http://127.0.0.1:${adminPort}'
    fs.mkdirSync(process.env.DB_DIR, { recursive: true })
    const auditLogSvc = require(path.join(ROOT, 'backend/services/auditLog.js'))
    const caddySvc = require(path.join(ROOT, 'backend/services/caddy.js'))
    const requestLog = require(path.join(ROOT, 'backend/services/requestLog.js'))
    const AUDIT = ${JSON.stringify(auditPath)}
    const OUT = {}
    ;(function(){ ${body} })()
    console.log('@@' + JSON.stringify(OUT))
  `
  let out
  try {
    out = execFileSync(process.execPath, ['--experimental-sqlite', '-e', script],
      { encoding: 'utf8', timeout: 60000, stdio: ['ignore', 'pipe', 'pipe'] })
  } catch (e) {
    try { proc.kill('SIGKILL') } catch {}
    return { _error: String(e.stderr || e.message), _work: work, _audit: auditPath }
  }
  try { proc.kill('SIGKILL') } catch {}
  const line = out.split('\n').filter(l => l.startsWith('@@')).pop()
  return { ...JSON.parse(line.slice(2)), _work: work, _audit: auditPath, _caddy: caddyPath, _sitePort: sitePort }
}

;(async () => {
  section('configuration defaults and clamping')
  {
    const r = run(`
      OUT.defaults = auditLogSvc.config({})
      OUT.custom = auditLogSvc.config({ CATWAF_AUDIT_RETENTION_DAYS: '7', CATWAF_AUDIT_MAX_SIZE_MB: '5', CATWAF_AUDIT_MAX_FILES: '3' })
      OUT.garbage = auditLogSvc.config({ CATWAF_AUDIT_RETENTION_DAYS: 'nonsense', CATWAF_AUDIT_MAX_SIZE_MB: '-9', CATWAF_AUDIT_MAX_FILES: '99999999' })
    `)
    check('defaults are 30 days / 100MB / 10 files',
      r.defaults.retentionDays === 30 && r.defaults.maxSizeMb === 100 && r.defaults.maxFiles === 10, r.defaults)
    check('explicit settings are honoured',
      r.custom.retentionDays === 7 && r.custom.maxSizeMb === 5 && r.custom.maxFiles === 3, r.custom)
    check('nonsense values fall back or clamp rather than disabling rotation',
      r.garbage.retentionDays === 30 && r.garbage.maxSizeMb === 1 && r.garbage.maxFiles === 1000, r.garbage)
    cleanup(r)
  }

  section('rotation by size')
  {
    const big = entry('a1') + '\n' + entry('a2') + '\n'
    const r = run(`
      OUT.before = auditLogSvc.needsRotation({ CATWAF_AUDIT_MAX_SIZE_MB: '100' })
      OUT.after = auditLogSvc.needsRotation({ CATWAF_AUDIT_MAX_SIZE_MB: '1' })
      // 1MB limit vs a tiny file -> no rotation; a 0-size limit is clamped to 1MB
      fs.appendFileSync(AUDIT, 'x'.repeat(1024 * 1024 + 10))
      OUT.overLimit = auditLogSvc.needsRotation({ CATWAF_AUDIT_MAX_SIZE_MB: '1' })
      OUT.size = fs.statSync(AUDIT).size
    `, { auditLines: big })
    check('a small log does not trigger rotation', r.before.rotate === false, r.before)
    check('a log under the limit does not trigger rotation', r.after.rotate === false, r.after)
    check('exceeding the size limit triggers rotation', r.overLimit.rotate === true, r.overLimit)
    check('the reason names the size limit', /size .*limit/.test(r.overLimit.reason || ''), r.overLimit.reason)
    cleanup(r)
  }

  section('rotation by age')
  {
    const r = run(`
      const old = Date.now() - 40 * 86400000
      fs.utimesSync(AUDIT, new Date(old), new Date(old))
      const base = caddySvc.baseAuditLogPath()
      auditLogSvc.writeState(base, { active: base, activeSince: new Date(old).toISOString() })
      OUT.aged = auditLogSvc.needsRotation({ CATWAF_AUDIT_RETENTION_DAYS: '30', CATWAF_AUDIT_MAX_SIZE_MB: '100' })
      OUT.young = auditLogSvc.needsRotation({ CATWAF_AUDIT_RETENTION_DAYS: '3650', CATWAF_AUDIT_MAX_SIZE_MB: '100' })
    `, { auditLines: entry('age1') + '\n' })
    check('an old active log triggers rotation', r.aged.rotate === true, r.aged)
    check('the reason names the retention window', /retention/.test(r.aged.reason || ''), r.aged.reason)
    check('a young log does not', r.young.rotate === false, r.young)
    cleanup(r)
  }

  section('rotation retires the old file without truncating it, and drains it')
  if (!HAVE_CADDY) {
    console.log('  SKIP  caddy binary not on PATH — rotation needs a real reload.')
  } else {
    const seed = entry('rr01', '/one') + '\n' + entry('rr02', '/two') + '\n'
    const r = await runWithCaddy(`
      const before = fs.readFileSync(AUDIT, 'utf8')
      const res = auditLogSvc.rotate({ reason: 'test' })
      OUT.ok = res.ok
      OUT.error = res.error || null
      OUT.from = res.from
      OUT.to = res.to
      OUT.ingested = res.ingested
      OUT.oldStillExists = fs.existsSync(res.from || '')
      OUT.oldContentUnchanged = OUT.oldStillExists && fs.readFileSync(res.from, 'utf8') === before
      OUT.newExists = fs.existsSync(res.to || '')
      OUT.newIsEmpty = OUT.newExists && fs.statSync(res.to).size === 0
      OUT.caddyfilePointsAtNew = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8').includes('SecAuditLog ' + res.to)
      OUT.caddyfileHasOld = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8').includes('SecAuditLog ' + res.from)
      OUT.rows = requestLog.getRecent(50).length
      OUT.activeAfter = auditLogSvc.activePath()
      OUT.resolvedAfter = caddySvc.resolveAuditLogPath()
    `, { auditLines: seed, sitePort: 19971, adminPort: 19961 })

    check('rotation succeeded', r.ok === true, r.error || r._error)
    check('the retired file still exists', r.oldStillExists === true)
    check('the retired file was NOT truncated or altered', r.oldContentUnchanged === true)
    check('a fresh active file was created', r.newExists === true)
    check('the new active file starts empty', r.newIsEmpty === true)
    check('SecAuditLog now points at the new file', r.caddyfilePointsAtNew === true)
    check('no reference to the retired file remains', r.caddyfileHasOld === false)
    check('the retired file was drained into the database', r.ingested === 2, r.ingested)
    check('both events are stored', r.rows === 2, r.rows)
    check('activePath() reports the new file', r.activeAfter === r.to, { active: r.activeAfter, to: r.to })
    check('caddy.js resolves the rotated path (so ingestion follows it)', r.resolvedAfter === r.to, r.resolvedAfter)
    cleanup(r)
  }

  section('no duplicate ingestion across rotation or restart')
  if (!HAVE_CADDY) {
    console.log('  SKIP  caddy binary not on PATH.')
  } else {
    const seed = entry('dd01') + '\n' + entry('dd02') + '\n' + entry('dd03') + '\n'
    const r = await runWithCaddy(`
      requestLog.ingestNewEntries()
      OUT.afterFirst = requestLog.getRecent(100).length
      const res = auditLogSvc.rotate({ reason: 'test' })
      OUT.rotated = res.ok
      OUT.afterRotate = requestLog.getRecent(100).length
      // simulate a restart: fresh offset state, drain the archive again
      requestLog.drainFile(res.from)
      requestLog.drainFile(res.from)
      requestLog.ingestNewEntries()
      OUT.afterRedrain = requestLog.getRecent(100).length
    `, { auditLines: seed, sitePort: 19972, adminPort: 19962 })
    check('the three events ingest once', r.afterFirst === 3, r.afterFirst)
    check('rotation does not re-add them', r.afterRotate === 3, r.afterRotate)
    check('re-draining the archive adds nothing (restart-safe)', r.afterRedrain === 3, r.afterRedrain)
    cleanup(r)
  }

  section('a partially written trailing line survives rotation')
  {
    // A complete entry followed by a half-written one, as Coraza mid-write.
    const seed = entry('pp01') + '\n' + entry('pp02').slice(0, 40)
    const r = run(`
      const r1 = requestLog.ingestNewEntries()
      OUT.firstIngest = r1.ingested
      OUT.rowsBefore = requestLog.getRecent(50).length
      // the writer finishes the line
      fs.appendFileSync(AUDIT, ${JSON.stringify(entry('pp02').slice(40))} + '\\n')
      const r2 = requestLog.ingestNewEntries()
      OUT.secondIngest = r2.ingested
      OUT.rowsAfter = requestLog.getRecent(50).length
      OUT.ids = requestLog.getRecent(50).map(x => x.id).sort()
    `, { auditLines: seed })
    check('the partial line is not ingested yet', r.firstIngest === 1, r.firstIngest)
    check('only the complete entry is stored', r.rowsBefore === 1, r.rowsBefore)
    check('once completed, the entry is ingested', r.secondIngest === 1, r.secondIngest)
    check('no entry was lost or duplicated', r.rowsAfter === 2 && r.ids.join(',') === 'pp01,pp02', r.ids)
    cleanup(r)
  }

  section('retention deletes old archives but never the active log')
  {
    const r = run(`
      const base = caddySvc.baseAuditLogPath()
      const dir = path.dirname(base)
      // five archives, three of them old
      const names = []
      for (let i = 1; i <= 5; i++) {
        const p = path.join(dir, 'coraza-audit-2026010' + i + 'T000000Z.json')
        fs.writeFileSync(p, ${JSON.stringify(entry('arc'))} + '\\n')
        const age = i <= 3 ? Date.now() - 60 * 86400000 : Date.now()
        fs.utimesSync(p, new Date(age), new Date(age))
        names.push(p)
      }
      OUT.before = auditLogSvc.listFiles(base).length
      const pruned = auditLogSvc.prune({ CATWAF_AUDIT_RETENTION_DAYS: '30', CATWAF_AUDIT_MAX_FILES: '10' })
      OUT.deleted = pruned.deleted.map(d => d.reason)
      OUT.activeStillThere = fs.existsSync(auditLogSvc.activePath())
      OUT.remaining = auditLogSvc.listFiles(base).length

      // now cap the count
      const pruned2 = auditLogSvc.prune({ CATWAF_AUDIT_RETENTION_DAYS: '3650', CATWAF_AUDIT_MAX_FILES: '1' })
      OUT.deleted2 = pruned2.deleted.length
      OUT.remaining2 = auditLogSvc.listFiles(base).length
      OUT.activeStillThere2 = fs.existsSync(auditLogSvc.activePath())
    `, { auditLines: entry('active') + '\n' })
    check('all six files are tracked', r.before === 6, r.before)
    check('the three aged archives are deleted', r.deleted.length === 3 && r.deleted.every(d => /retention/.test(d)), r.deleted)
    check('the active log survives retention pruning', r.activeStillThere === true)
    check('capping the file count deletes the excess', r.deleted2 === 1, r.deleted2)
    check('the active log survives count pruning', r.activeStillThere2 === true)
    check('one archive plus the active log remain', r.remaining2 === 2, r.remaining2)
    cleanup(r)
  }

  section('a crash mid-rotation recovers safely')
  {
    const seed = entry('c1') + '\n'
    const r = run(`
      const base = caddySvc.baseAuditLogPath()
      const next = auditLogSvc.nextActivePath(base)
      fs.writeFileSync(next, '')
      // Marker written, Caddyfile NOT yet repointed — the crash window.
      auditLogSvc.writeState(base, { active: base, pending: { from: base, to: next, startedAt: new Date().toISOString() } })
      const rec = auditLogSvc.recover(base)
      OUT.outcome = rec.outcome
      OUT.activeAfter = auditLogSvc.activePath()
      OUT.stillBase = OUT.activeAfter === base
      OUT.orphanRemoved = !fs.existsSync(next)

      // Now the other half: Caddyfile already repointed when we crashed.
      const next2 = auditLogSvc.nextActivePath(base, new Date(Date.now() + 60000))
      fs.writeFileSync(next2, '')
      fs.writeFileSync(process.env.CADDYFILE_PATH,
        fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8').replace('SecAuditLog ' + base, 'SecAuditLog ' + next2))
      auditLogSvc.writeState(base, { active: base, pending: { from: base, to: next2, startedAt: new Date().toISOString() } })
      const rec2 = auditLogSvc.recover(base)
      OUT.outcome2 = rec2.outcome
      OUT.activeAfter2 = auditLogSvc.activePath()
      OUT.completedToNext = OUT.activeAfter2 === next2
      OUT.drained = requestLog.getRecent(50).length
    `, { auditLines: seed })
    check('an unstarted rotation is reverted', r.outcome === 'reverted', r.outcome)
    check('the active log stays put after a revert', r.stillBase === true, r.activeAfter)
    check('the orphaned empty file is cleaned up', r.orphanRemoved === true)
    check('a rotation whose repoint landed is completed', r.outcome2 === 'completed', r.outcome2)
    check('the active path moves to the new file', r.completedToNext === true, r.activeAfter2)
    check('the retired file was drained during recovery', r.drained === 1, r.drained)
    cleanup(r)
  }

  section('rotation refuses rather than half-applying when the config cannot be repointed')
  {
    const r = run(`
      // A Caddyfile that never mentions the audit log: nothing to repoint.
      fs.writeFileSync(process.env.CADDYFILE_PATH, '{\\n    order coraza_waf first\\n}\\n\\n:19994 {\\n    respond "x" 200\\n}\\n')
      const res = auditLogSvc.rotate({ reason: 'test' })
      OUT.ok = res.ok
      OUT.error = res.error
      OUT.rolledBack = res.rolledBack
      OUT.activeUnchanged = auditLogSvc.activePath() === caddySvc.baseAuditLogPath()
      OUT.noStrayFiles = auditLogSvc.listFiles(caddySvc.baseAuditLogPath()).length === 1
    `, { auditLines: entry('n1') + '\n' })
    check('rotation fails rather than half-applying', r.ok === false, r)
    check('the failure explains itself', /does not reference/.test(r.error || ''), r.error)
    check('it rolled back', r.rolledBack === true)
    check('the active path is unchanged', r.activeUnchanged === true)
    check('no stray rotated file is left behind', r.noStrayFiles === true)
    cleanup(r)
  }

  section('permission failures are reported clearly')
  if (IS_ROOT) {
    console.log('  SKIP  running as root — permission failures cannot be exercised.')
  } else {
    const r = run(`
      const dir = path.dirname(AUDIT)
      fs.chmodSync(dir, 0o500)
      let status, res
      try {
        status = auditLogSvc.status()
        res = auditLogSvc.rotate({ reason: 'test' })
      } finally { fs.chmodSync(dir, 0o700) }
      OUT.writable = status.writable
      OUT.ok = res.ok
      OUT.error = res.error || null
    `, { auditLines: entry('perm1') + '\n' })
    check('status reports the directory as not writable', r.writable === false, r.writable)
    check('rotation fails instead of throwing', r.ok === false, r)
    check('the error names the path and the reason', /Cannot create|EACCES|permission/i.test(r.error || ''), r.error)
    cleanup(r)
  }

  section('status reports what the CLI needs')
  {
    const r = run(`
      const base = caddySvc.baseAuditLogPath()
      fs.writeFileSync(path.join(path.dirname(base), 'coraza-audit-20260101T000000Z.json'), 'x')
      const s = auditLogSvc.status({ CATWAF_AUDIT_MAX_SIZE_MB: '1', CATWAF_AUDIT_MAX_FILES: '4', CATWAF_AUDIT_RETENTION_DAYS: '9' })
      OUT.keys = Object.keys(s).sort()
      OUT.activePath = s.activePath
      OUT.rotatedFiles = s.rotatedFiles
      OUT.retention = s.retention
      OUT.writable = s.writable
      OUT.serialised = JSON.stringify(s)
    `, { auditLines: entry('s1') + '\n' })
    check('status exposes the active path', r.activePath === r._audit, r.activePath)
    check('status counts rotated files', r.rotatedFiles === 1, r.rotatedFiles)
    check('status reports the retention configuration',
      r.retention.maxSizeMb === 1 && r.retention.maxFiles === 4 && r.retention.retentionDays === 9, r.retention)
    check('status reports writability', r.writable === true)
    check('status carries no secrets', !/JWT|SECRET|PASSWORD|TOKEN/i.test(r.serialised || ''))
    cleanup(r)
  }

  section('Docker-style explicit audit path is honoured')
  {
    // The compose default: CORAZA_AUDIT_LOG set to a volume path.
    const r = run(`
      OUT.base = caddySvc.baseAuditLogPath()
      OUT.active = auditLogSvc.activePath()
      const next = auditLogSvc.nextActivePath(OUT.base)
      OUT.nextInSameDir = path.dirname(next) === path.dirname(OUT.base)
      OUT.nextName = path.basename(next)
      OUT.stateFileInLogDir = path.dirname(auditLogSvc.stateFileFor(OUT.base)) === path.dirname(OUT.base)
    `, { auditLines: entry('dk1') + '\n' })
    check('the explicit path is used as the base', r.base === r._audit, r.base)
    check('the active path starts as the base', r.active === r._audit)
    check('rotated files stay in the same directory (works with a mounted volume)', r.nextInSameDir === true)
    check('rotated names are timestamped', /^coraza-audit-\d{8}T\d{6}Z\.json$/.test(r.nextName || ''), r.nextName)
    check('rotation state lives beside the logs, not in the database', r.stateFileInLogDir === true)
    cleanup(r)
  }

  section('maintain() is safe to call repeatedly and never throws')
  {
    const r = run(`
      const a = auditLogSvc.maintain({ env: { CATWAF_AUDIT_MAX_SIZE_MB: '100' } })
      const b = auditLogSvc.maintain({ env: { CATWAF_AUDIT_MAX_SIZE_MB: '100' } })
      OUT.a = { ok: a.ok, rotated: a.rotated }
      OUT.b = { ok: b.ok, rotated: b.rotated }
      OUT.files = auditLogSvc.listFiles(caddySvc.baseAuditLogPath()).length
    `, { auditLines: entry('m1') + '\n' })
    check('maintain succeeds without rotating a small log', r.a.ok === true && r.a.rotated === false, r.a)
    check('a second call is a no-op', r.b.ok === true && r.b.rotated === false, r.b)
    check('no files were created', r.files === 1, r.files)
    cleanup(r)
  }

  console.log(`\n${pass} passed, ${fail} failed\n`)
  process.exit(fail ? 1 : 0)
})()
