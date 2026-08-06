const fs = require('fs')
const path = require('path')

const PROJECT_ROOT = path.join(__dirname, '..', '..')
const BACKEND_DIR = path.join(PROJECT_ROOT, 'backend')

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', cyan: '\x1b[36m',
}
const useColor = process.stdout.isTTY && !process.env.NO_COLOR
const c = (s, ...codes) => useColor ? codes.join('') + s + C.reset : s

const OK = 'ok', WARN = 'warn', FAIL = 'fail', INFO = 'info'

function sym(status) {
  if (status === OK) return c('✓', C.green)
  if (status === WARN) return c('!', C.yellow)
  if (status === FAIL) return c('✗', C.red)
  return c('·', C.dim)
}

function makeReporter() {
  const results = []
  return {
    results,
    add(status, label, detail, recommendation) {
      results.push({ status, label, detail: detail || null, recommendation: recommendation || null })
    },
  }
}

async function collect() {
  const r = makeReporter()
  const envSvc = require(path.join(BACKEND_DIR, 'services', 'environment.js'))
  const env = await envSvc.detect()

  r.add(env.os.supported ? OK : WARN,
    `Operating system: ${env.os.prettyName || env.os.platform} (${env.os.arch})`,
    null,
    env.os.supported ? null : 'CatWAF is developed against Linux and macOS. Other platforms are untested.')

  r.add(env.runtime.nodeOk ? OK : FAIL,
    `Node.js ${env.runtime.node}`,
    env.runtime.npm ? `npm ${env.runtime.npm}` : null,
    env.runtime.nodeOk ? null : 'CatWAF requires Node 22 or newer (it uses the built-in node:sqlite module). Install Node 22+ and re-run.')

  r.add(env.runtime.hasSqlite ? OK : FAIL, 'node:sqlite module available', null,
    env.runtime.hasSqlite ? null : 'Your Node build lacks node:sqlite. Use an official Node 22+ build.')

  if (env.caddy.present) {
    r.add(OK, `Caddy detected: ${env.caddy.version || 'version unknown'}`, env.caddy.path)
    r.add(env.caddy.corazaModule ? OK : FAIL,
      env.caddy.corazaModule ? 'Coraza WAF module present (http.handlers.waf)' : 'Coraza WAF module MISSING from this Caddy build',
      null,
      env.caddy.corazaModule ? null : 'This Caddy cannot run the WAF. Rebuild it:\n    xcaddy build --with github.com/corazawaf/coraza-caddy/v2\n  or run `npm install` in the CatWAF directory to fetch a prebuilt binary.')
    r.add(env.caddy.running ? OK : WARN,
      env.caddy.running ? 'Caddy process is running' : 'Caddy is not currently running',
      null,
      env.caddy.running ? null : 'Nothing is being filtered while Caddy is down. Start it with `catwaf start`, or `caddy run --config <Caddyfile>`.')
  } else {
    r.add(FAIL, 'Caddy not found on PATH', null,
      'CatWAF needs Caddy built with the Coraza module. Run `npm install` in the CatWAF directory, or see docs/installation.md.')
  }

  const caddySvc = require(path.join(BACKEND_DIR, 'services', 'caddy.js'))
  const cfPath = caddySvc.CADDYFILE_PATH
  const cfExists = fs.existsSync(cfPath)
  r.add(cfExists ? OK : WARN,
    `Caddyfile: ${cfPath}${caddySvc.CADDYFILE_SOURCE === 'auto-detected' ? ' (auto-detected)' : ''}`,
    null,
    cfExists ? null : 'No Caddyfile at that path yet. `catwaf setup` creates one, or set CADDYFILE_PATH to an existing file.')

  if (cfExists) {
    let writable = false
    try { fs.accessSync(cfPath, fs.constants.W_OK); writable = true } catch {}
    r.add(writable ? OK : FAIL,
      writable ? 'Caddyfile is writable' : 'Caddyfile is NOT writable by this user',
      null,
      writable ? null : `WAF changes will fail. Either run CatWAF as a user that can write ${cfPath}, or point CADDYFILE_PATH at a file you can write.`)

    const body = fs.readFileSync(cfPath, 'utf8')
    const hasWafBlock = body.includes('@@CATWAF_WAF_START@@')
    r.add(hasWafBlock ? OK : INFO,
      hasWafBlock ? 'CatWAF manages a WAF block in this Caddyfile' : 'No CatWAF WAF block in the Caddyfile yet',
      null,
      hasWafBlock ? null : 'Apply any WAF setting (dashboard or CLI) and CatWAF will insert its block automatically.')

    const hasOrder = /order\s+coraza_waf\s+first/.test(body)
    r.add(hasOrder ? OK : (hasWafBlock ? FAIL : INFO),
      hasOrder ? 'Global `order coraza_waf first` directive present' : 'Missing global `order coraza_waf first` directive',
      null,
      hasOrder ? null : 'Without this, requests can bypass Coraza entirely. CatWAF adds it on the next apply, or add it to the global options block yourself.')

    if (env.caddy.present) {
      const { execFileSync } = require('child_process')
      let valid = false, validErr = null
      try {
        execFileSync('caddy', ['validate', '--config', cfPath, '--adapter', 'caddyfile'], { timeout: 20000, stdio: ['ignore', 'pipe', 'pipe'] })
        valid = true
      } catch (e) {
        validErr = (e.stderr?.toString() || e.message || '').split('\n').filter(l => /Error|error/.test(l))[0] || 'see `caddy validate` output'
      }
      r.add(valid ? OK : FAIL,
        valid ? 'Caddyfile syntax and modules validate' : 'Caddyfile FAILED validation',
        valid ? null : validErr,
        valid ? null : 'Caddy will refuse to load this config. Fix the error above before starting.')
    }
  }

  const auditPath = caddySvc.AUDIT_LOG_PATH
  const auditDir = path.dirname(auditPath)
  const auditDirExists = fs.existsSync(auditDir)
  r.add(auditDirExists ? OK : FAIL,
    `Coraza audit log directory: ${auditDir}`,
    null,
    auditDirExists ? null : `Caddy refuses to start the WAF handler when this directory is missing ("invalid WAF config from audit log"). Create it:\n    sudo mkdir -p ${auditDir}`)
  if (auditDirExists) {
    const auditExists = fs.existsSync(auditPath)
    r.add(auditExists ? OK : INFO,
      auditExists ? `Audit log present (${fs.statSync(auditPath).size} bytes)` : 'Audit log not written yet',
      null,
      auditExists ? null : 'Normal on a fresh install. It appears once Coraza logs its first relevant request.')

    // Rotation health: Coraza never prunes its own log, so an audit log
    // near its limit that CatWAF cannot rotate will fill the disk.
    try {
      const auditLogSvc = require(path.join(BACKEND_DIR, "services", "auditLog.js"))
      const a = auditLogSvc.status()
      const mb = n => `${(n / 1024 / 1024).toFixed(1)}MB`

      if (!a.writable) {
        r.add(FAIL,
          `Audit log cannot be rotated: ${path.dirname(a.activePath)} is not writable`,
          null,
          'CatWAF cannot rotate or prune the audit log, so it will grow until the disk fills. Give CatWAF write access to that directory, or point CORAZA_AUDIT_LOG somewhere it can write.')
      } else if (a.percentOfMax >= 90) {
        r.add(WARN,
          `Audit log is at ${a.percentOfMax}% of its rotation limit (${mb(a.sizeBytes)} of ${a.retention.maxSizeMb}MB)`,
          null,
          'It will rotate automatically on the next maintenance pass. Raise CATWAF_AUDIT_MAX_SIZE_MB if you want larger files.')
      } else {
        r.add(OK,
          `Audit log rotation: ${a.rotatedFiles} rotated file(s), ${mb(a.totalBytes)} total, ${a.percentOfMax}% of the ${a.retention.maxSizeMb}MB limit`)
      }

      if (a.rotationPending) {
        r.add(WARN, 'An audit log rotation was interrupted', null,
          'CatWAF finishes or reverts it automatically on the next maintenance pass; no data is lost.')
      }
    } catch (e) {
      r.add(INFO, `Audit log rotation status unavailable: ${e.message}`)
    }
  }

  let dbOk = false, dbDetail = null
  try {
    const db = require(path.join(BACKEND_DIR, 'services', 'db.js'))
    db.getDb().prepare('SELECT 1').get()
    dbOk = true
    dbDetail = db.DB_PATH
  } catch (e) { dbDetail = e.message }
  r.add(dbOk ? OK : FAIL, dbOk ? 'Database accessible' : 'Database NOT accessible', dbDetail,
    dbOk ? null : 'Check DB_DIR/DB_PATH and that the directory is writable by this user.')

  if (dbOk) {
    try {
      const db = require(path.join(BACKEND_DIR, 'services', 'db.js'))
      const cols = db.getDb().prepare('PRAGMA table_info(request_log)').all().map(x => x.name)
      const needed = ['ts', 'action', 'attack_type', 'rule_ids', 'severity', 'reason']
      const missing = needed.filter(n => !cols.includes(n))
      r.add(missing.length === 0 ? OK : FAIL,
        missing.length === 0 ? 'request_log schema is current' : `request_log schema is missing columns: ${missing.join(', ')}`,
        null,
        missing.length === 0 ? null : 'Restart CatWAF once — the schema migration runs at startup.')
    } catch (e) {
      r.add(WARN, 'Could not inspect request_log schema', e.message)
    }
  }

  let authDetail = null, authStatus = WARN
  try {
    const auth = require(path.join(BACKEND_DIR, 'middleware', 'auth.js'))
    if (auth.needsBootstrap()) {
      authStatus = WARN
      authDetail = 'no accounts exist yet'
    } else {
      const admins = auth.USERS.filter(u => u.role === 'admin').length
      authStatus = admins > 0 ? OK : FAIL
      authDetail = `${auth.USERS.length} account(s), ${admins} admin`
    }
  } catch (e) { authStatus = FAIL; authDetail = e.message }
  r.add(authStatus,
    authStatus === OK ? `Authentication configured (${authDetail})` : `Authentication: ${authDetail}`,
    null,
    authStatus === OK ? null : 'Run `catwaf setup` (or `catwaf user add --admin`) to create an admin account. CatWAF ships with no default credentials.')

  const secretSet = !!process.env.JWT_SECRET && process.env.JWT_SECRET.length >= 32
  r.add(secretSet ? OK : WARN,
    secretSet ? 'JWT_SECRET is set' : 'JWT_SECRET is not set (a random one is generated at each boot)',
    null,
    secretSet ? null : 'Every restart invalidates all sessions. Set a persistent value:\n    openssl rand -hex 32')

  if (env.container.inContainer) r.add(INFO, 'Running inside a container')
  r.add(env.container.dockerAvailable ? INFO : INFO,
    `Docker: ${env.container.dockerAvailable ? 'available' : 'not installed'}${env.container.composeAvailable ? ' (compose available)' : ''}`)
  r.add(INFO, `Init system: ${env.init.systemd ? 'systemd' : env.init.launchd ? 'launchd' : 'none detected'}`,
    null,
    env.init.systemd || env.init.launchd ? null : 'No supported service manager found — `catwaf start` will run CatWAF as a detached background process instead.')

  const others = []
  if (env.nginx.present) others.push(`nginx ${env.nginx.version || ''}`.trim() + (env.nginx.running ? ' (running)' : ''))
  if (env.apache.present) others.push(`Apache ${env.apache.version || ''}`.trim() + (env.apache.running ? ' (running)' : ''))
  if (others.length) {
    r.add(INFO, `Other web servers present: ${others.join(', ')}`, null,
      'CatWAF filters traffic through Caddy+Coraza. If another server owns port 80/443, see docs/reverse-proxy.md for how to chain them.')
  }

  if (env.controlPanel) {
    const panel = env[env.controlPanel]
    r.add(WARN, `Control panel detected: ${env.controlPanel}${panel.version ? ' ' + panel.version : ''}`,
      panel.sites && panel.sites.length ? `${panel.sites.length} site(s) discovered` : null,
      'Automatic integration is NOT available. CatWAF will not modify panel, Apache, DNS, or firewall configuration. Use the reverse-proxy path: docs/reverse-proxy.md')
  }

  for (const [port, info] of Object.entries(env.ports)) {
    if (!info.inUse) continue
    const known = { 80: 'HTTP', 443: 'HTTPS', 2019: 'Caddy admin API', 3000: 'dashboard dev server', 8000: 'CatWAF API', 8081: 'protected app' }[port]
    const owner = info.owner ? ` — held by ${info.owner.command || 'unknown process'}${info.owner.pid ? ` (pid ${info.owner.pid})` : ''}` : ''
    r.add(INFO, `Port ${port} is in use${known ? ` (${known})` : ''}${owner}`)
  }

  const apiPort = Number(process.env.PORT || 8000)
  if (env.ports[apiPort] && env.ports[apiPort].inUse) {
    const owner = env.ports[apiPort].owner
    const ownedBy = owner ? ` It is currently held by ${owner.command || 'an unknown process'}${owner.pid ? ` (pid ${owner.pid})` : ''}.` : ''
    r.add(INFO, `CatWAF API port ${apiPort} already has a listener`, null,
      `That is expected if CatWAF is already running.${ownedBy} If it is not CatWAF, another service owns the port — change PORT or stop the conflicting service.`)
  }

  if (!env.existing.frontendBuilt) {
    r.add(WARN, 'Dashboard has not been built', null,
      'The web UI will 404 until you build it:\n    npm run build\n  (Not needed if you only want the WAF and CLI — see Minimal mode.)')
  } else {
    r.add(OK, 'Dashboard build present')
  }

  addCaddyCapabilityChecks(r)

  return { env, results: r.results }
}

// What the installed Caddy build can actually do, and what CatWAF had to
// leave out of the generated configuration because of it.
//
// This is the single most useful thing doctor can tell you about a feature
// that looks switched on but is not doing anything: CatWAF skips a directive
// whose module is missing rather than emitting one Caddy would reject, so
// without this report a missing module looks like a silent no-op.
function addCaddyCapabilityChecks(r) {
  let modules
  let renderReport
  try {
    modules = require(path.join(BACKEND_DIR, 'services', 'caddyModules.js')).summary()
    renderReport = require(path.join(BACKEND_DIR, 'services', 'caddy.js')).lastRenderReport()
  } catch (e) {
    r.add(INFO, 'Caddy capability report unavailable', e.message)
    return
  }

  if (!modules.binary_available) {
    r.add(WARN, 'Cannot ask Caddy what it supports', 'The caddy binary was not found on PATH.',
      'Optional features are skipped rather than guessed at. Install Caddy, or set CADDY_BIN to its path.')
    return
  }

  r.add(OK, `Caddy ${modules.version || 'present'} — ${modules.module_count} modules`)

  const missing = Object.entries(modules.features).filter(([, f]) => !f.ok)
  if (!missing.length) {
    r.add(OK, 'Every optional Caddy module CatWAF can use is present')
  } else {
    for (const [name, f] of missing) {
      r.add(INFO, `Optional module missing: ${f.label || name}`, f.module, f.hint)
    }
  }

  const skipped = renderReport?.skipped || []
  if (skipped.length) {
    for (const s of skipped) {
      r.add(WARN, `Enabled but not in effect: ${s.feature}`, s.reason,
        s.module
          ? `CatWAF left this out of the generated configuration rather than emitting a directive Caddy would reject. Needs: ${s.module}`
          : 'CatWAF left this out of the generated configuration rather than emitting a directive Caddy would reject.')
    }
  } else {
    r.add(OK, 'Every enabled setting made it into the generated configuration')
  }
}

function summarize(results) {
  return {
    ok: results.filter(x => x.status === OK).length,
    warn: results.filter(x => x.status === WARN).length,
    fail: results.filter(x => x.status === FAIL).length,
    info: results.filter(x => x.status === INFO).length,
  }
}

async function run(opts = {}) {
  const { json = false, verbose = false } = opts
  let collected
  try {
    collected = await collect()
  } catch (e) {
    if (json) {
      console.log(JSON.stringify({ error: e.message, healthy: false }, null, 2))
    } else {
      console.error(c('CatWAF Doctor failed to run: ' + e.message, C.red))
    }
    return 2
  }

  const { env, results } = collected
  const counts = summarize(results)
  const healthy = counts.fail === 0

  if (json) {
    console.log(JSON.stringify({
      healthy,
      counts,
      checks: results,
      environment: verbose ? env : {
        platform: env.os.platform,
        primaryWebServer: env.primaryWebServer,
        controlPanel: env.controlPanel,
        suggestedDashboardHost: env.suggestedDashboardHost,
      },
    }, null, 2))
    return healthy ? 0 : 1
  }

  console.log('\n' + c('CatWAF Doctor', C.bold, C.cyan) + '\n')

  const shown = verbose ? results : results.filter(x => x.status !== INFO)
  for (const x of shown) {
    console.log(`${sym(x.status)} ${x.label}${x.detail ? c('  — ' + x.detail, C.dim) : ''}`)
  }

  const actionable = results.filter(x => x.recommendation && (x.status === FAIL || x.status === WARN))
  if (actionable.length) {
    console.log('\n' + c('Recommendations', C.bold))
    for (const x of actionable) {
      console.log(`\n${sym(x.status)} ${x.label}`)
      console.log('  ' + x.recommendation.split('\n').join('\n  '))
    }
  }

  if (env.suggestedDashboardHost) {
    console.log('\n' + c('Dashboard hostname', C.bold))
    console.log(`  Detected base domain: ${c(env.baseDomain, C.cyan)}`)
    console.log(`  Suggested dashboard:  ${c(env.suggestedDashboardHost, C.cyan)}`)
    console.log(c('  Run `catwaf provision --print` to see the config for your web server.', C.dim))
  }

  console.log('')
  const parts = [
    c(`${counts.ok} ok`, C.green),
    counts.warn ? c(`${counts.warn} warning`, C.yellow) : null,
    counts.fail ? c(`${counts.fail} failed`, C.red) : null,
  ].filter(Boolean)
  console.log(parts.join(c(' · ', C.dim)))
  if (!verbose && counts.info) console.log(c(`${counts.info} informational check(s) hidden — re-run with --verbose`, C.dim))
  console.log(healthy ? c('\nCatWAF looks healthy.\n', C.green) : c('\nOne or more checks failed — see recommendations above.\n', C.red))

  return healthy ? 0 : 1
}

module.exports = { run, collect, summarize }
