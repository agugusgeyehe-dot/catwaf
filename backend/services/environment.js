const fs = require('fs')
const os = require('os')
const net = require('net')
const path = require('path')
const { execFileSync } = require('child_process')

const PROJECT_ROOT = path.join(__dirname, '..', '..')

function run(cmd, args, opts = {}) {
  try {
    return execFileSync(cmd, args, {
      encoding: 'utf8',
      timeout: opts.timeout || 4000,
      stdio: ['ignore', 'pipe', opts.wantStderr ? 'pipe' : 'ignore'],
    }).toString()
  } catch (e) {
    if (opts.wantStderr && e.stderr) return e.stderr.toString()
    if (opts.wantStdout && e.stdout) return e.stdout.toString()
    return null
  }
}

// Pure PATH scan rather than `sh -c "command -v …"`: the old form interpolated
// the binary name into a shell string, so any future caller passing anything
// other than a hardcoded literal would have had a command-injection primitive
// on its hands. Every current caller is a fixed literal; this keeps it that
// way by construction.
function which(bin) {
  if (typeof bin !== 'string' || !bin || bin.includes('/')) return null
  const dirs = (process.env.PATH || '').split(path.delimiter).filter(Boolean)
  for (const dir of dirs) {
    const candidate = path.join(dir, bin)
    try {
      fs.accessSync(candidate, fs.constants.X_OK)
      const st = fs.statSync(candidate)
      if (st.isFile()) return candidate
    } catch { /* not here — keep scanning */ }
  }
  return null
}

function readFileSafe(p, maxBytes = 512 * 1024) {
  try {
    const st = fs.statSync(p)
    if (!st.isFile() || st.size > maxBytes) return null
    return fs.readFileSync(p, 'utf8')
  } catch { return null }
}

function listDirSafe(p) {
  try { return fs.readdirSync(p) } catch { return [] }
}

function exists(p) {
  try { fs.accessSync(p); return true } catch { return false }
}

function detectOs() {
  const info = {
    platform: process.platform,
    arch: process.arch,
    release: os.release(),
    hostname: os.hostname(),
    distro: null,
    prettyName: null,
  }
  const osRelease = readFileSafe('/etc/os-release')
  if (osRelease) {
    const get = k => {
      const m = new RegExp(`^${k}=(.*)$`, 'm').exec(osRelease)
      return m ? m[1].replace(/^"|"$/g, '') : null
    }
    info.distro = get('ID')
    info.prettyName = get('PRETTY_NAME')
  }
  if (process.platform === 'darwin' && !info.prettyName) {
    const v = run('sw_vers', ['-productVersion'])
    info.prettyName = v ? `macOS ${v.trim()}` : 'macOS'
  }
  info.supported = process.platform === 'linux' || process.platform === 'darwin'
  return info
}

function detectRuntime() {
  const nodeMajor = parseInt(process.versions.node.split('.')[0], 10)
  return {
    node: process.version,
    nodeMajor,
    nodeOk: nodeMajor >= 22,
    npm: (run('npm', ['--version']) || '').trim() || null,
    hasSqlite: (() => { try { require('node:sqlite'); return true } catch { return false } })(),
  }
}

function detectContainer() {
  const inDocker = exists('/.dockerenv')
    || /docker|containerd|kubepods/.test(readFileSafe('/proc/1/cgroup') || '')
  return {
    inContainer: !!inDocker,
    dockerAvailable: !!which('docker'),
    composeAvailable: !!(run('docker', ['compose', 'version']) || which('docker-compose')),
  }
}

function detectInitSystem() {
  const hasSystemctl = !!which('systemctl')
  let systemdRunning = false
  if (hasSystemctl) {
    systemdRunning = exists('/run/systemd/system')
  }
  return {
    systemd: hasSystemctl && systemdRunning,
    systemctlPresent: hasSystemctl,
    launchd: process.platform === 'darwin' && !!which('launchctl'),
  }
}

function detectCaddy() {
  const bin = which('caddy')
  const result = { present: !!bin, path: bin, version: null, corazaModule: false, running: false, adminReachable: false, configPath: null }
  if (bin) {
    const v = run('caddy', ['version'])
    result.version = v ? v.trim().split('\n')[0] : null
    const mods = run('caddy', ['list-modules'], { timeout: 8000 })
    result.corazaModule = !!mods && mods.includes('http.handlers.waf')
  }
  result.running = !!run('pgrep', ['-x', 'caddy'])
  const unit = run('systemctl', ['cat', 'caddy'])
  if (unit) {
    const m = /^ExecStart=.*?--config\s+(\S+)/m.exec(unit)
    if (m) result.configPath = m[1]
  }
  return result
}

function parseNginxServerNames(text) {
  const names = new Set()
  const re = /server_name\s+([^;]+);/g
  let m
  while ((m = re.exec(text)) !== null) {
    for (const raw of m[1].trim().split(/\s+/)) {
      const n = raw.trim()
      if (!n || n === '_' || n.startsWith('~')) continue
      names.add(n.replace(/^\*\./, ''))
    }
  }
  return [...names]
}

function detectNginx() {
  const bin = which('nginx')
  const result = {
    present: !!bin, path: bin, version: null, running: false,
    configPath: null, configTestOk: null, sitesDirs: [], domains: [],
  }
  if (!bin) {
    result.running = !!run('pgrep', ['-x', 'nginx'])
    return result
  }
  const v = run('nginx', ['-v'], { wantStderr: true })
  if (v) {
    const m = /nginx\/([\d.]+)/.exec(v)
    result.version = m ? m[1] : v.trim()
  }
  const V = run('nginx', ['-V'], { wantStderr: true }) || ''
  const confPath = /--conf-path=(\S+)/.exec(V)
  result.configPath = confPath ? confPath[1] : ['/etc/nginx/nginx.conf', '/usr/local/nginx/conf/nginx.conf', '/opt/homebrew/etc/nginx/nginx.conf'].find(exists) || null
  result.running = !!run('pgrep', ['-x', 'nginx'])

  const candidateDirs = [
    '/etc/nginx/sites-enabled',
    '/etc/nginx/conf.d',
    '/usr/local/nginx/conf/conf.d',
    '/opt/homebrew/etc/nginx/servers',
  ].filter(exists)
  result.sitesDirs = candidateDirs

  const domains = new Set()
  for (const dir of candidateDirs) {
    for (const f of listDirSafe(dir)) {
      const body = readFileSafe(path.join(dir, f))
      if (body) for (const d of parseNginxServerNames(body)) domains.add(d)
    }
  }
  const mainConf = result.configPath ? readFileSafe(result.configPath) : null
  if (mainConf) for (const d of parseNginxServerNames(mainConf)) domains.add(d)
  result.domains = [...domains].sort()
  return result
}

function detectApache() {
  const bin = which('apache2') || which('httpd') || which('apache2ctl') || which('apachectl')
  const result = { present: !!bin, path: bin, version: null, running: false, sitesDirs: [], domains: [] }
  if (bin) {
    const v = run(path.basename(bin), ['-v'], { wantStderr: true, wantStdout: true })
    if (v) {
      const m = /Apache\/([\d.]+)/.exec(v)
      result.version = m ? m[1] : null
    }
  }
  result.running = !!(run('pgrep', ['-x', 'apache2']) || run('pgrep', ['-x', 'httpd']))
  const dirs = ['/etc/apache2/sites-enabled', '/etc/httpd/conf.d', '/etc/apache2/vhosts.d'].filter(exists)
  result.sitesDirs = dirs
  const domains = new Set()
  for (const dir of dirs) {
    for (const f of listDirSafe(dir)) {
      const body = readFileSafe(path.join(dir, f))
      if (!body) continue
      const re = /^\s*(?:ServerName|ServerAlias)\s+(\S+)/gmi
      let m
      while ((m = re.exec(body)) !== null) domains.add(m[1].replace(/^\*\./, ''))
    }
  }
  result.domains = [...domains].sort()
  return result
}

const CPANEL_TYPES = new Set(['main', 'sub', 'addon', 'parked', 'alias'])
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/
const IPV6_RE = /^[0-9a-f:]+:[0-9a-f:]*$/i

function parseUserDataDomains(text) {
  const sites = []
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const idx = trimmed.indexOf(':')
    if (idx === -1) continue
    const domain = trimmed.slice(0, idx).trim()
    const rest = trimmed.slice(idx + 1).trim()
    if (!domain) continue

    const parts = rest.split('==').map(p => p.trim())
    sites.push({
      domain,
      user: parts[0] || null,
      type: parts.find(p => CPANEL_TYPES.has(p.toLowerCase())) || null,
      docroot: parts.find(p => p.startsWith('/')) || null,
      ip: parts.find(p => IPV4_RE.test(p) || IPV6_RE.test(p)) || null,
    })
  }
  return sites
}

function detectCpanel() {
  const result = {
    detected: false,
    version: null,
    sites: [],
    users: [],
    automationSupported: false,
    note: null,
  }

  const markers = [
    '/usr/local/cpanel/cpanel',
    '/usr/local/cpanel/version',
    '/var/cpanel',
    '/etc/wwwacct.conf',
  ]
  const found = markers.filter(exists)
  if (!found.length) return result

  result.detected = true
  const ver = readFileSafe('/usr/local/cpanel/version')
  if (ver) result.version = ver.trim()

  const udd = readFileSafe('/etc/userdatadomains')
  if (udd) {
    result.sites = parseUserDataDomains(udd)
  } else {
    const userdataRoot = '/var/cpanel/userdata'
    for (const user of listDirSafe(userdataRoot)) {
      for (const f of listDirSafe(path.join(userdataRoot, user))) {
        if (f === 'main' || f.endsWith('.cache') || f.endsWith('.db')) continue
        if (!f.includes('.')) continue
        result.sites.push({ domain: f.replace(/_SSL$/, ''), user, type: null, docroot: null, ip: null })
      }
    }
  }

  result.users = [...new Set(result.sites.map(s => s.user).filter(Boolean))].sort()
  result.sites = result.sites
    .filter(s => /^[a-z0-9.*-]+\.[a-z]{2,}$/i.test(s.domain))
    .filter((s, i, arr) => arr.findIndex(x => x.domain === s.domain) === i)
    .sort((a, b) => a.domain.localeCompare(b.domain))

  result.automationSupported = false
  result.note = 'Detected — manual configuration required. CatWAF does not modify cPanel, Apache, DNS, or firewall configuration automatically.'
  return result
}

function detectPlesk() {
  const detected = exists('/usr/local/psa') || exists('/etc/psa')
  return { detected, automationSupported: false, note: detected ? 'Detected — manual configuration required.' : null }
}

function detectDirectAdmin() {
  const detected = exists('/usr/local/directadmin')
  return { detected, automationSupported: false, note: detected ? 'Detected — manual configuration required.' : null }
}

function checkPort(port, host = '127.0.0.1', timeout = 600) {
  return new Promise(resolve => {
    const sock = new net.Socket()
    let done = false
    const finish = inUse => { if (!done) { done = true; try { sock.destroy() } catch {} ; resolve(inUse) } }
    sock.setTimeout(timeout)
    sock.once('connect', () => finish(true))
    sock.once('timeout', () => finish(false))
    sock.once('error', () => finish(false))
    sock.connect(port, host)
  })
}

// "Something is listening on :8000" is not actionable on its own — the
// operator still has to go find out what and kill or reconfigure it
// themselves. `lsof` (or `fuser` where lsof is not installed) can name the
// process directly, so doctor's port report does it for them. Best-effort
// only: a locked-down host may have neither tool, or may deny an
// unprivileged CatWAF permission to see other users' sockets — in that case
// this quietly reports nothing rather than failing the whole check.
function portOwner(port) {
  try {
    const out = execFileSync('lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN'], { timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] }).toString()
    const line = out.split('\n').find(l => /LISTEN/.test(l))
    if (line) {
      const cols = line.trim().split(/\s+/)
      if (cols[0] && cols[1]) return { command: cols[0], pid: Number(cols[1]) || null }
    }
  } catch {}
  try {
    const out = execFileSync('fuser', ['-n', 'tcp', String(port)], { timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] }).toString()
    const pid = Number(out.trim().split(/\s+/)[0])
    if (Number.isFinite(pid)) {
      let command = null
      try { command = execFileSync('ps', ['-o', 'comm=', '-p', String(pid)], { timeout: 2000, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim() || null } catch {}
      return { command, pid }
    }
  } catch {}
  return null
}

async function detectPorts(ports = [80, 443, 2019, 8000, 8081, 8082]) {
  const out = {}
  await Promise.all(ports.map(async p => {
    const inUse = await checkPort(p)
    out[p] = { inUse, owner: inUse ? portOwner(p) : null }
  }))
  return out
}

function detectExistingInstall() {
  const envPath = path.join(PROJECT_ROOT, '.env')
  const dbDir = process.env.DB_DIR || path.join(PROJECT_ROOT, 'data')
  const result = {
    projectRoot: PROJECT_ROOT,
    envFile: exists(envPath),
    database: exists(path.join(dbDir, 'catwaf.db')),
    frontendBuilt: exists(path.join(PROJECT_ROOT, 'frontend', 'dist', 'index.html')),
    systemdUnit: exists('/etc/systemd/system/catwaf.service'),
    cliOnPath: !!which('catwaf'),
  }
  result.installed = result.envFile || result.database || result.systemdUnit
  return result
}

function pickWebServer(env) {
  if (env.caddy.present && env.caddy.corazaModule) return 'caddy'
  if (env.cpanel.detected) return 'cpanel'
  if (env.nginx.present) return 'nginx'
  if (env.apache.present) return 'apache'
  if (env.caddy.present) return 'caddy'
  return 'none'
}

function guessBaseDomain(env) {
  const skip = /^(localhost|localhost\.localdomain)$/i
  const pools = [
    env.cpanel.sites.map(s => s.domain),
    env.nginx.domains,
    env.apache.domains,
  ]
  for (const pool of pools) {
    const usable = (pool || [])
      .filter(d => d && !skip.test(d) && d.includes('.') && !d.startsWith('catwaf.'))
      .sort((a, b) => a.split('.').length - b.split('.').length || a.length - b.length)
    if (usable.length) return usable[0]
  }
  return null
}

async function detect() {
  const env = {
    os: detectOs(),
    runtime: detectRuntime(),
    container: detectContainer(),
    init: detectInitSystem(),
    caddy: detectCaddy(),
    nginx: detectNginx(),
    apache: detectApache(),
    cpanel: detectCpanel(),
    plesk: detectPlesk(),
    directadmin: detectDirectAdmin(),
    existing: detectExistingInstall(),
    ports: await detectPorts(),
  }
  env.primaryWebServer = pickWebServer(env)
  env.baseDomain = guessBaseDomain(env)
  env.suggestedDashboardHost = env.baseDomain ? `catwaf.${env.baseDomain}` : null
  env.controlPanel = env.cpanel.detected ? 'cpanel'
    : env.plesk.detected ? 'plesk'
    : env.directadmin.detected ? 'directadmin'
    : null
  return env
}

module.exports = {
  detect,
  detectOs, detectRuntime, detectContainer, detectInitSystem,
  detectCaddy, detectNginx, detectApache,
  detectCpanel, detectPlesk, detectDirectAdmin,
  detectExistingInstall, detectPorts, checkPort,
  parseNginxServerNames, parseUserDataDomains,
  pickWebServer, guessBaseDomain,
}
