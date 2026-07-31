const fs = require('fs')
const net = require('net')
const path = require('path')

const state = require('./state')
const db = require('./db')
const caddySvc = require('./caddy')
const authMod = require('../middleware/auth')

const PROJECT_ROOT = path.join(__dirname, '..', '..')

const CRITICAL = 'critical'
const HIGH = 'high'
const MEDIUM = 'medium'
const LOW = 'low'
const INFO = 'info'

const SECRET_VALUE_RE = /(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/

function checkPort(port, host, timeout = 700) {
  return new Promise(resolve => {
    const sock = new net.Socket()
    let done = false
    const finish = v => { if (!done) { done = true; try { sock.destroy() } catch {} ; resolve(v) } }
    sock.setTimeout(timeout)
    sock.once('connect', () => finish(true))
    sock.once('timeout', () => finish(false))
    sock.once('error', () => finish(false))
    sock.connect(port, host)
  })
}

function modeOf(p) {
  try { return fs.statSync(p).mode & 0o777 } catch { return null }
}

async function collect() {
  const findings = []
  const passed = []

  const fail = (severity, title, detail, remediation) => findings.push({ severity, title, detail, remediation })
  const pass = (title, detail) => passed.push({ title, detail: detail || null })

  const bindHost = process.env.HOST || '127.0.0.1'
  if (bindHost === '0.0.0.0' || bindHost === '::') {
    fail(HIGH, 'CatWAF API is bound to all interfaces',
      `HOST=${bindHost} exposes the admin API on every network interface.`,
      'Bind to 127.0.0.1 and put the dashboard behind Caddy, or restrict access with a firewall.')
  } else {
    pass('API bind address', `${bindHost} (loopback)`)
  }

  const adminUrl = caddySvc.CADDY_ADMIN_URL
  try {
    const u = new URL(adminUrl)
    const isLocal = ['127.0.0.1', 'localhost', '::1'].includes(u.hostname)
    const reachableExternally = !isLocal && await checkPort(Number(u.port || 2019), u.hostname)
    if (!isLocal && reachableExternally) {
      fail(HIGH, 'Caddy admin API is not on loopback',
        `CADDY_ADMIN_URL points at ${u.host}. Caddy's admin API is unauthenticated by design.`,
        'Keep the admin API on loopback or an internal-only container network. Never publish port 2019.')
    } else {
      pass('Caddy admin API scope', isLocal ? 'loopback only' : `${u.host} (not reachable from here)`)
    }
  } catch {
    fail(LOW, 'Caddy admin URL is not a valid URL', adminUrl, 'Set CADDY_ADMIN_URL to a valid http(s) URL.')
  }

  const compose = path.join(PROJECT_ROOT, 'docker-compose.yml')
  if (fs.existsSync(compose)) {
    const body = fs.readFileSync(compose, 'utf8')
    if (/\/var\/run\/docker\.sock/.test(body)) {
      fail(CRITICAL, 'Docker socket is mounted into a container',
        'docker-compose.yml mounts /var/run/docker.sock, which is effectively root on the host.',
        'Remove the socket mount. CatWAF reloads Caddy over the admin API and does not need it.')
    } else {
      pass('Docker socket', 'not mounted')
    }
    if (/privileged:\s*true/.test(body)) {
      fail(HIGH, 'A container runs privileged', 'privileged: true found in docker-compose.yml',
        'Remove privileged mode; CatWAF does not require it.')
    } else {
      pass('Privileged containers', 'none')
    }
    if (/2019:2019|"2019"/.test(body)) {
      fail(HIGH, 'Caddy admin port is published to the host',
        'Port 2019 appears in a published ports list.',
        'Remove it. The admin API is unauthenticated and must stay on the internal network.')
    } else {
      pass('Admin port publication', 'port 2019 not published')
    }
  }

  const jwt = process.env.JWT_SECRET || ''
  if (!jwt) {
    fail(HIGH, 'JWT_SECRET is not set',
      'A random secret is generated at every boot, so all sessions are invalidated on restart.',
      'Set a persistent value: openssl rand -hex 32')
  } else if (jwt.length < 32) {
    fail(HIGH, 'JWT_SECRET is too short', `${jwt.length} characters.`, 'Use at least 32 characters: openssl rand -hex 32')
  } else if (/^(changeme|secret|password|test|catwaf)/i.test(jwt)) {
    fail(CRITICAL, 'JWT_SECRET looks like a placeholder', 'The configured secret matches a common placeholder pattern.',
      'Replace it immediately: openssl rand -hex 32')
  } else {
    pass('JWT secret', `set (${jwt.length} chars)`)
  }

  let users = []
  try { users = authMod.listUsers() } catch {}
  if (!users.length) {
    fail(HIGH, 'No administrator account exists',
      'Nobody can administer CatWAF, and the bootstrap path is open until an account is created.',
      'Run `catwaf setup` or `catwaf user add <name> --role admin`.')
  } else {
    const admins = users.filter(u => u.role === 'admin')
    if (!admins.length) {
      fail(HIGH, 'No account has the admin role', `${users.length} account(s), none admin.`,
        'Promote one: catwaf user role <name> admin')
    } else {
      pass('Admin authentication', `${users.length} account(s), ${admins.length} admin`)
    }
    const weak = users.filter(u => ['admin', 'test', 'demo', 'root'].includes(u.username) && u.role === 'admin')
    if (weak.length) {
      findings.push({
        severity: LOW,
        title: 'Predictable administrator username',
        detail: `Account(s): ${weak.map(u => u.username).join(', ')}`,
        remediation: 'A guessable username makes credential-stuffing marginally easier. Not dangerous on its own given rate limiting, but worth avoiding.',
      })
    }
  }

  const cors = process.env.CORS_ORIGIN || ''
  if (cors.trim() === '*') {
    fail(HIGH, 'CORS allows any origin', 'CORS_ORIGIN is "*".',
      'Set CORS_ORIGIN to your exact dashboard URL.')
  } else if (!cors) {
    fail(LOW, 'CORS_ORIGIN is not set',
      'CatWAF defaults to http://localhost:3000, which is only correct for local development.',
      'Set CORS_ORIGIN to your real dashboard URL before exposing CatWAF.')
  } else {
    pass('CORS policy', cors)
  }

  const dbPath = db.DB_PATH
  const dbMode = modeOf(dbPath)
  if (dbMode != null && (dbMode & 0o077)) {
    fail(MEDIUM, 'Database file is readable by other users',
      `${dbPath} has mode ${dbMode.toString(8)}. It contains password hashes and audit history.`,
      `Restrict it: chmod 600 ${dbPath}`)
  } else if (dbMode != null) {
    pass('Database permissions', `mode ${dbMode.toString(8)}`)
  }

  const envPath = path.join(PROJECT_ROOT, '.env')
  if (fs.existsSync(envPath)) {
    const envMode = modeOf(envPath)
    if (envMode != null && (envMode & 0o077)) {
      fail(HIGH, '.env is readable by other users',
        `${envPath} has mode ${envMode.toString(8)} and holds secrets.`,
        `chmod 600 ${envPath}`)
    } else {
      pass('.env permissions', `mode ${envMode?.toString(8) || 'unknown'}`)
    }
  }

  const cfPath = caddySvc.CADDYFILE_PATH
  if (fs.existsSync(cfPath)) {
    const body = fs.readFileSync(cfPath, 'utf8')
    if (SECRET_VALUE_RE.test(body)) {
      fail(CRITICAL, 'A credential appears to be present in the Caddyfile',
        'A pattern matching an API key or private key was found in the generated configuration.',
        'Remove it and rotate the credential. CatWAF never needs secrets in the Caddyfile.')
    } else {
      pass('Caddyfile secret scan', 'no credential patterns found')
    }

    const hasOrder = /order\s+coraza_waf\s+first/.test(body)
    const hasBlock = body.includes('@@CATWAF_WAF_START@@')
    if (!hasBlock) {
      fail(HIGH, 'WAF is not present in the Caddyfile',
        'No CatWAF WAF block was found, so Coraza is not inspecting traffic through this config.',
        'Apply any WAF setting from the CLI or dashboard to generate it.')
    } else if (!hasOrder) {
      fail(CRITICAL, 'WAF may be bypassable',
        'The Caddyfile has a Coraza block but no `order coraza_waf first` directive, so requests can be handled before the WAF runs.',
        'Add `order coraza_waf first` to the global options block.')
    } else {
      pass('WAF interception', 'coraza_waf ordered first')
    }
  } else {
    fail(MEDIUM, 'No Caddyfile found', `Expected at ${cfPath}.`, 'Run `catwaf setup`.')
  }

  if (state.WAF.engine === 'Off') {
    fail(CRITICAL, 'WAF engine is Off', 'No requests are being inspected.',
      'Turn it on: catwaf mode normal')
  } else if (state.WAF.engine === 'DetectionOnly') {
    fail(MEDIUM, 'WAF is in detection-only mode',
      'Attacks are logged but not blocked. This is correct for learning mode and dangerous if unintentional.',
      'Return to enforcement when finished: catwaf mode normal')
  } else {
    pass('WAF engine', `On at paranoia level ${state.WAF.paranoia_level}`)
  }

  if (!state.WAF.audit_log) {
    fail(LOW, 'Audit logging is disabled',
      'Blocked requests are not being recorded, so the dashboard and `catwaf audit` will show nothing.',
      'Re-enable it (maintenance mode disables it deliberately): catwaf mode normal')
  } else {
    pass('Audit logging', 'enabled')
  }

  if (!state.WAF.rate_limit || !state.WAF.rate_limit.enabled) {
    fail(LOW, 'Per-IP rate limiting is disabled',
      'Brute-force and scraping traffic is limited only by the WAF rules.',
      'Enable it from the dashboard, or ask CatAI to "enable rate limiting".')
  } else {
    pass('Rate limiting', `${state.WAF.rate_limit.requests_per_min}/min per IP`)
  }

  const disabledCats = Object.entries(state.RULE_CATEGORIES).filter(([, v]) => v.enabled === false)
  if (disabledCats.length) {
    fail(MEDIUM, 'Whole CRS rule categories are disabled',
      `Disabled: ${disabledCats.map(([k, v]) => `${k} (${v.name})`).join(', ')}`,
      'Disabling an entire category removes broad coverage. Prefer disabling the specific rule that misfires.')
  } else {
    pass('CRS categories', 'all enabled')
  }

  const disabledRules = Array.isArray(state.WAF.disabled_rules) ? state.WAF.disabled_rules : []
  if (disabledRules.length > 20) {
    fail(MEDIUM, 'A large number of individual rules are disabled',
      `${disabledRules.length} rules are disabled.`,
      'Review them: catwaf rules list --disabled')
  } else if (disabledRules.length) {
    findings.push({
      severity: INFO,
      title: 'Individual CRS rules are disabled',
      detail: `${disabledRules.length}: ${disabledRules.slice(0, 10).join(', ')}${disabledRules.length > 10 ? '…' : ''}`,
      remediation: 'Expected if you have tuned false positives. Review with `catwaf rules list --disabled`.',
    })
  } else {
    pass('Individual rules', 'none disabled')
  }

  const serverSource = fs.readFileSync(path.join(PROJECT_ROOT, 'backend', 'server.js'), 'utf8')
  const headerChecks = [
    ['contentSecurityPolicy', 'Content-Security-Policy'],
    ['hsts', 'Strict-Transport-Security'],
    ['frameguard', 'X-Frame-Options'],
    ['noSniff', 'X-Content-Type-Options'],
  ]
  const missingHeaders = headerChecks.filter(([k]) => !new RegExp(k).test(serverSource)).map(([, n]) => n)
  if (missingHeaders.length) {
    fail(MEDIUM, 'Security headers may not be configured', `Not found in server config: ${missingHeaders.join(', ')}`,
      'Confirm helmet is configured with these directives.')
  } else {
    pass('Security headers', 'CSP, HSTS, frameguard and noSniff configured')
  }
  if (/connectSrc/.test(serverSource)) {
    pass('CSP connect-src', 'explicitly set')
  } else {
    fail(MEDIUM, 'CSP has no explicit connect-src',
      'With default-src \'none\', the dashboard cannot call its own API.',
      'Add connectSrc to the helmet CSP directives.')
  }

  const trustProxy = process.env.TRUST_PROXY_HOPS
  if (trustProxy && Number(trustProxy) > 3) {
    fail(MEDIUM, 'Proxy trust depth is unusually high',
      `TRUST_PROXY_HOPS=${trustProxy}. Client IPs can be spoofed if this exceeds your real proxy count.`,
      'Set it to the actual number of proxies in front of CatWAF.')
  } else {
    pass('Proxy trust', `TRUST_PROXY_HOPS=${trustProxy ?? '1 (default)'}`)
  }

  const backupsDir = path.join(path.dirname(db.DB_PATH), 'backups')
  if (fs.existsSync(backupsDir)) {
    const bMode = modeOf(backupsDir)
    if (bMode != null && (bMode & 0o077)) {
      fail(MEDIUM, 'Configuration backup directory is world/group readable',
        `${backupsDir} has mode ${bMode.toString(8)}.`,
        `chmod 700 ${backupsDir}`)
    } else {
      pass('Backup directory permissions', `mode ${bMode?.toString(8) || 'unknown'}`)
    }
  }

  return { findings, passed }
}

async function run() {
  const { findings, passed } = await collect()
  const counts = {
    critical: findings.filter(f => f.severity === CRITICAL).length,
    high: findings.filter(f => f.severity === HIGH).length,
    medium: findings.filter(f => f.severity === MEDIUM).length,
    low: findings.filter(f => f.severity === LOW).length,
    info: findings.filter(f => f.severity === INFO).length,
  }
  const exitCode = counts.critical > 0 ? 2 : (counts.high > 0 ? 1 : 0)
  return {
    counts,
    findings,
    passed,
    checked_at: new Date().toISOString(),
    exit_code: exitCode,
    disclaimer: 'These checks cover CatWAF\'s own configuration and deployment posture. Passing them does not mean the protected application is secure, and it is not a substitute for a penetration test.',
  }
}

module.exports = { run, collect, CRITICAL, HIGH, MEDIUM, LOW, INFO }
