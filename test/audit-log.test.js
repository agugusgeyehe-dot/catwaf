#!/usr/bin/env node
// test/audit-log.test.js — Coraza audit-log preparation.
//
// Coraza opens SecAuditLog when the config is PROVISIONED, so `caddy
// validate` fails outright if the path cannot be opened. On a clean
// host-native install /var/log/coraza does not exist and an unprivileged
// CatWAF cannot create it, which made every apply fail with:
//
//   invalid WAF config from audit log:
//   open /var/log/coraza/audit.json: no such file or directory
//
// Each scenario runs in its own child process because the audit-log path
// and whether it was explicitly configured are resolved when
// services/caddy.js is first required.

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

function haveCaddy() {
  try { execFileSync('caddy', ['version'], { timeout: 5000 }); return true } catch { return false }
}
const HAVE_CADDY = haveCaddy()

// Runs `body` in a child process with a controlled environment and returns
// whatever it prints as JSON on the last line.
function run(body, env = {}) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-auditlog-'))
  const script = `
    const fs = require('fs'), path = require('path')
    const ROOT = ${JSON.stringify(ROOT)}
    const WORK = ${JSON.stringify(work)}
    process.env.DB_DIR = path.join(WORK, 'db')
    process.env.CADDYFILE_PATH = path.join(WORK, 'Caddyfile')
    process.env.JWT_SECRET = 'a'.repeat(64)
    // never reach a locally running Caddy on the default :2019
    process.env.CADDY_ADMIN_URL = 'http://127.0.0.1:19916'
    fs.mkdirSync(process.env.DB_DIR, { recursive: true })
    fs.writeFileSync(process.env.CADDYFILE_PATH, '{\\n}\\n\\n:19991 {\\n    respond "x" 200\\n}\\n')
    const caddySvc = require(path.join(ROOT, 'backend/services/caddy.js'))
    const applySvc = require(path.join(ROOT, 'backend/services/proxy/apply.js'))
    const state = require(path.join(ROOT, 'backend/services/state.js'))
    state.WAF.engine = 'On'; state.WAF.audit_log = true
    const route = {
      name: 'app', containerName: 'app_nginx', containerId: 'a1',
      listenPort: 18099, upstream: '127.0.0.1:19991', upstreamBasis: 'published-host-port',
      runtime: null, framework: null, phpConfidence: null, warnings: [],
    }
    const OUT = {}
    ;(function(){ ${body} })()
    console.log('@@' + JSON.stringify(OUT))
  `
  const childEnv = { ...process.env, ...env }
  // a fresh install has this unset
  if (env.CORAZA_AUDIT_LOG === undefined) delete childEnv.CORAZA_AUDIT_LOG

  try {
    const out = execFileSync(process.execPath, ['--experimental-sqlite', '-e', script], {
      encoding: 'utf8', timeout: 60000, env: childEnv, stdio: ['ignore', 'pipe', 'pipe'],
    })
    const line = out.split('\n').filter(l => l.startsWith('@@')).pop()
    return { ...JSON.parse(line.slice(2)), _work: work }
  } catch (e) {
    return { _error: String(e.stderr || e.message), _work: work }
  }
}

function cleanup(r) { try { fs.rmSync(r._work, { recursive: true, force: true }) } catch {} }

;(async () => {
  section('prerequisites')
  check('caddy binary present (validation is real)', HAVE_CADDY)
  check('/var/log/coraza is absent or unwritable for this user (the clean-install case)',
    IS_ROOT || !(() => { try { fs.accessSync('/var/log/coraza', fs.constants.W_OK); return true } catch { return false } })())

  if (IS_ROOT) {
    console.log('  SKIP  running as root — the unprivileged fallback cannot be exercised.')
    console.log(`\n${pass} passed, ${fail} failed\n`)
    process.exit(fail ? 1 : 0)
  }

  section('clean install: default audit path is unusable, apply still succeeds')
  {
    const r = run(`
      OUT.candidates = caddySvc.auditLogCandidates()
      const res = applySvc.apply({ routes: [route], waf: state.WAF, dryRun: false })
      OUT.ok = res.ok
      OUT.error = res.error || null
      OUT.auditPath = res.auditLog && res.auditLog.path
      OUT.fellBack = res.auditLog && res.auditLog.fellBack
      OUT.fileExists = OUT.auditPath ? fs.existsSync(OUT.auditPath) : false
      OUT.exported = caddySvc.AUDIT_LOG_PATH
      const body = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
      OUT.secAuditLog = (body.match(/SecAuditLog (.*)/) || [])[1]
      OUT.routeWritten = body.includes(':18099 {')
    `)
    check('apply succeeded on a clean install', r.ok === true, r.error || r._error)
    check('the default /var/log path was tried first', (r.candidates || [])[0] === '/var/log/coraza/audit.json', r.candidates)
    check('it fell back to a writable location', r.fellBack === true, r.auditPath)
    check('fallback lives under CatWAF\'s data dir', /\/db\/logs\/coraza-audit\.json$/.test(r.auditPath || ''), r.auditPath)
    check('the audit log file was actually created', r.fileExists === true)
    check('generated config points at the effective path', r.secAuditLog === r.auditPath, { generated: r.secAuditLog, effective: r.auditPath })
    check('exported AUDIT_LOG_PATH matches (so ingestion reads the same file)', r.exported === r.auditPath, { exported: r.exported })
    check('the protected route was written', r.routeWritten === true)
    cleanup(r)
  }

  section('--dry-run predicts the same path without creating anything')
  {
    const r = run(`
      const status = caddySvc.auditLogStatus()
      const res = applySvc.apply({ routes: [route], waf: state.WAF, dryRun: true })
      OUT.ok = res.ok
      OUT.predicted = res.auditLog && res.auditLog.path
      OUT.statusPath = status.path
      OUT.createdAnything = fs.existsSync(path.join(process.env.DB_DIR, 'logs'))
      OUT.caddyfileTouched = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8').includes('CATWAF_AUTO')
    `)
    check('dry-run succeeds', r.ok === true, r._error)
    check('dry-run predicts the fallback path', /coraza-audit\.json$/.test(r.predicted || ''), r.predicted)
    check('dry-run agrees with auditLogStatus()', r.predicted === r.statusPath)
    check('dry-run created no audit log', r.createdAnything === false)
    check('dry-run did not touch the Caddyfile', r.caddyfileTouched === false)
    cleanup(r)
  }

  section('an explicitly configured audit log is created and used verbatim')
  {
    const explicit = path.join(os.tmpdir(), `catwaf-explicit-${process.pid}`, 'nested', 'audit.json')
    const r = run(`
      const res = applySvc.apply({ routes: [route], waf: state.WAF, dryRun: false })
      OUT.ok = res.ok
      OUT.error = res.error || null
      OUT.auditPath = res.auditLog && res.auditLog.path
      OUT.fellBack = res.auditLog && res.auditLog.fellBack
      OUT.fileExists = fs.existsSync(process.env.CORAZA_AUDIT_LOG)
    `, { CORAZA_AUDIT_LOG: explicit })
    check('apply succeeded', r.ok === true, r.error || r._error)
    check('the configured path was used exactly', r.auditPath === explicit, r.auditPath)
    check('no silent relocation', r.fellBack === false)
    check('missing parent directories were created', r.fileExists === true)
    try { fs.rmSync(path.dirname(path.dirname(explicit)), { recursive: true, force: true }) } catch {}
    cleanup(r)
  }

  section('an unwritable explicit audit log fails loudly and changes nothing')
  {
    const ro = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-ro-'))
    fs.chmodSync(ro, 0o500)
    const r = run(`
      const before = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
      const res = applySvc.apply({ routes: [route], waf: state.WAF, dryRun: false })
      OUT.ok = res.ok
      OUT.error = res.error || null
      OUT.message = res.message || null
      OUT.caddyfileUnchanged = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8') === before
    `, { CORAZA_AUDIT_LOG: path.join(ro, 'sub', 'audit.json') })
    check('apply failed rather than silently relocating', r.ok === false, r)
    check('the error names the audit log', /audit log/i.test(r.error || ''), r.error)
    check('the message tells the user what to set', /CORAZA_AUDIT_LOG/.test(r.message || ''), r.message)
    check('the working configuration was preserved', r.caddyfileUnchanged === true)
    fs.chmodSync(ro, 0o700); fs.rmSync(ro, { recursive: true, force: true })
    cleanup(r)
  }

  section('repeated runs are idempotent and never truncate the log')
  {
    const r = run(`
      const first = applySvc.apply({ routes: [route], waf: state.WAF, dryRun: false })
      fs.appendFileSync(first.auditLog.path, '{"pre-existing":true}\\n')
      const sizeBefore = fs.statSync(first.auditLog.path).size
      const second = applySvc.apply({ routes: [route], waf: state.WAF, dryRun: false })
      OUT.firstOk = first.ok
      OUT.secondOk = second.ok
      OUT.samePath = first.auditLog.path === second.auditLog.path
      OUT.sizeBefore = sizeBefore
      OUT.sizeAfter = fs.statSync(second.auditLog.path).size
      const body = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
      OUT.regions = (body.match(/@@CATWAF_AUTO_START@@/g) || []).length
    `)
    check('first apply ok', r.firstOk === true, r._error)
    check('second apply ok', r.secondOk === true)
    check('same audit path on re-run', r.samePath === true)
    check('existing audit content was not truncated', r.sizeAfter >= r.sizeBefore, { before: r.sizeBefore, after: r.sizeAfter })
    check('still exactly one managed region', r.regions === 1, r.regions)
    cleanup(r)
  }

  section('a pre-existing managed WAF block with a stale path is refreshed')
  {
    // Regression: `catwaf setup` writes a @@CATWAF_WAF_START@@ block. If it
    // was written before the audit path was resolvable it still says
    // /var/log/coraza/audit.json. Caddy provisions EVERY block, so that one
    // stale line failed validation for the whole file and `catwaf auto`
    // reported "Configuration validation failed: ... open
    // /var/log/coraza/audit.json: no such file or directory" — even though
    // the newly generated auto routes were correct.
    const r = run(`
      const STALE = [
        '{', '}', '',
        'http://localhost:18100 {',
        '    reverse_proxy 127.0.0.1:19991',
        '',
        '# @@CATWAF_WAF_START@@',
        '# CatWAF WAF Rules — auto-generated, do not edit manually',
        '',
        '  coraza_waf {',
        '    load_owasp_crs',
        '    directives \`',
        '      Include @coraza.conf-recommended',
        '      Include @crs-setup.conf.example',
        '      Include @owasp_crs/*.conf',
        '      SecRuleEngine On',
        '      SecAuditEngine RelevantOnly',
        '      SecAuditLogParts ABCEFHZ',
        '      SecAuditLogType Serial',
        '      SecAuditLog /var/log/coraza/audit.json',
        '      SecAuditLogFormat JSON',
        '    \`',
        '  }',
        '',
        '# @@CATWAF_WAF_END@@',
        '}',
        '',
      ].join('\\n')
      fs.writeFileSync(process.env.CADDYFILE_PATH, STALE)
      OUT.staleBefore = /SecAuditLog \\/var\\/log\\/coraza/.test(STALE)

      const res = applySvc.apply({ routes: [route], waf: state.WAF, dryRun: false })
      OUT.ok = res.ok
      OUT.error = res.error || null
      OUT.effective = res.auditLog && res.auditLog.path
      const body = fs.readFileSync(process.env.CADDYFILE_PATH, 'utf8')
      OUT.auditLines = (body.match(/SecAuditLog .*/g) || []).map(l => l.trim().replace(/^SecAuditLog /, ''))
      OUT.staleRemaining = /SecAuditLog \\/var\\/log\\/coraza/.test(body)
      OUT.userConfigKept = body.includes('http://localhost:18100')
      OUT.wafRegions = (body.match(/@@CATWAF_WAF_START@@/g) || []).length
      OUT.autoRegions = (body.match(/@@CATWAF_AUTO_START@@/g) || []).length
    `)
    check('the fixture really did start stale', r.staleBefore === true)
    check('apply succeeded despite the stale block', r.ok === true, r.error || r._error)
    check('NO SecAuditLog still points at /var/log/coraza', r.staleRemaining === false, r.auditLines)
    check('every SecAuditLog uses the effective path',
      (r.auditLines || []).length > 0 && (r.auditLines || []).every(l => l === r.effective),
      { lines: r.auditLines, effective: r.effective })
    check('both managed regions are present', r.wafRegions === 1 && r.autoRegions === 1, { waf: r.wafRegions, auto: r.autoRegions })
    check('user-authored config outside the markers is untouched', r.userConfigKept === true)
    cleanup(r)
  }

  section('read-only commands resolve the effective path without ensureAuditLog()')
  {
    // Regression: `catwaf audit` / `health` / `doctor` never call
    // ensureAuditLog(), so if the path were only corrected there they would
    // read /var/log/coraza, find nothing, and report zero events while
    // Coraza was writing to the fallback.
    const r = run(`
      // simulate a previous run having created the fallback log
      const fallback = path.join(process.env.DB_DIR, 'logs', 'coraza-audit.json')
      fs.mkdirSync(path.dirname(fallback), { recursive: true })
      fs.writeFileSync(fallback, '')
      delete require.cache[require.resolve(path.join(ROOT, 'backend/services/caddy.js'))]
      const fresh = require(path.join(ROOT, 'backend/services/caddy.js'))
      OUT.pathOnLoad = fresh.AUDIT_LOG_PATH
      OUT.fallback = fallback
    `)
    check('a fresh process resolves the fallback with no ensure call', r.pathOnLoad === r.fallback,
      { resolved: r.pathOnLoad, expected: r.fallback })
    cleanup(r)
  }

  section('configTx (WAF settings path) also prepares the audit log')
  {
    const r = run(`
      const configTx = require(path.join(ROOT, 'backend/services/configTx.js'))
      // a site block must exist for the WAF block to be inserted into
      const res = configTx.apply({ label: 'test.paranoia', mutate: (s) => { s.WAF.paranoia_level = 2 }, reload: false })
      OUT.ok = res.ok
      OUT.phase = res.phase || null
      OUT.error = res.error || null
      OUT.auditExists = fs.existsSync(caddySvc.AUDIT_LOG_PATH)
      OUT.auditPath = caddySvc.AUDIT_LOG_PATH
    `)
    check('WAF settings apply succeeded on a clean install', r.ok === true, { phase: r.phase, error: r.error, err: r._error })
    check('the audit log was prepared there too', r.auditExists === true, r.auditPath)
    cleanup(r)
  }

  console.log(`\n${pass} passed, ${fail} failed\n`)
  process.exit(fail ? 1 : 0)
})()
