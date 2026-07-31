const fs = require('fs')
const path = require('path')
const { spawn, execFileSync } = require('child_process')

const PROJECT_ROOT = path.join(__dirname, '..', '..')
const UNIT_PATH = '/etc/systemd/system/catwaf.service'

function dataDir() {
  const dir = process.env.DB_DIR || path.join(PROJECT_ROOT, 'data')
  try { fs.mkdirSync(dir, { recursive: true }) } catch {}
  return dir
}

function pidFile() {
  return path.join(dataDir(), 'catwaf.pid')
}

function logFile() {
  return path.join(dataDir(), 'catwaf.log')
}

function hasSystemdUnit() {
  try { fs.accessSync(UNIT_PATH); return true } catch { return false }
}

function systemdUsable() {
  if (!hasSystemdUnit()) return false
  try {
    execFileSync('systemctl', ['--version'], { timeout: 3000, stdio: 'ignore' })
  } catch { return false }
  try { fs.accessSync('/run/systemd/system'); return true } catch { return false }
}

function systemctl(args, timeout = 15000) {
  try {
    const out = execFileSync('systemctl', args, { encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'] })
    return { ok: true, out: out.toString().trim() }
  } catch (e) {
    return { ok: false, out: (e.stdout?.toString() || '').trim(), error: (e.stderr?.toString() || e.message || '').trim() }
  }
}

function pidAlive(pid) {
  if (!pid || !Number.isFinite(pid)) return false
  try { process.kill(pid, 0); return true } catch (e) { return e.code === 'EPERM' }
}

function readPid() {
  try {
    const raw = fs.readFileSync(pidFile(), 'utf8').trim()
    const pid = parseInt(raw, 10)
    return Number.isFinite(pid) ? pid : null
  } catch { return null }
}

function clearPid() {
  try { fs.unlinkSync(pidFile()) } catch {}
}

function status() {
  if (systemdUsable()) {
    const active = systemctl(['is-active', 'catwaf'], 5000)
    const enabled = systemctl(['is-enabled', 'catwaf'], 5000)
    const running = active.out === 'active'
    let pid = null
    const show = systemctl(['show', 'catwaf', '--property=MainPID', '--value'], 5000)
    if (show.ok) {
      const n = parseInt(show.out, 10)
      if (Number.isFinite(n) && n > 0) pid = n
    }
    return { manager: 'systemd', running, pid, enabled: enabled.out === 'enabled', detail: active.out || active.error || null }
  }

  const pid = readPid()
  const running = pidAlive(pid)
  if (pid && !running) clearPid()
  return { manager: 'process', running, pid: running ? pid : null, enabled: false, detail: running ? null : 'not running' }
}

function start() {
  const current = status()
  if (current.running) {
    return { ok: true, alreadyRunning: true, manager: current.manager, pid: current.pid, message: 'CatWAF is already running.' }
  }

  if (systemdUsable()) {
    const r = systemctl(['start', 'catwaf'])
    if (!r.ok) return { ok: false, manager: 'systemd', error: r.error || 'systemctl start failed' }
    const after = status()
    return { ok: after.running, manager: 'systemd', pid: after.pid, error: after.running ? null : (after.detail || 'service did not become active') }
  }

  const out = fs.openSync(logFile(), 'a')
  const child = spawn(process.execPath, [path.join(PROJECT_ROOT, 'backend', 'server.js')], {
    cwd: PROJECT_ROOT,
    detached: true,
    stdio: ['ignore', out, out],
    env: process.env,
  })
  child.unref()
  try { fs.closeSync(out) } catch {}

  if (!child.pid) return { ok: false, manager: 'process', error: 'failed to spawn backend process' }
  fs.writeFileSync(pidFile(), String(child.pid), 'utf8')
  return { ok: true, manager: 'process', pid: child.pid, logFile: logFile() }
}


function caddyUnitPresent() {
  const r = systemctl(['cat', 'caddy'], 5000)
  return r.ok
}

function caddyRunning() {
  try { execFileSync('pgrep', ['-x', 'caddy'], { timeout: 3000, stdio: 'ignore' }); return true }
  catch { return false }
}

function caddyBinary() {
  for (const candidate of ['caddy', path.join(PROJECT_ROOT, 'bin', 'vendor', 'caddy')]) {
    try {
      execFileSync(candidate, ['version'], { timeout: 5000, stdio: 'ignore' })
      return candidate
    } catch {}
  }
  return null
}

function caddyfilePath() {
  if (process.env.CADDYFILE_PATH) return process.env.CADDYFILE_PATH
  return path.join(PROJECT_ROOT, 'Caddyfile')
}

function wafStatus() {
  if (caddyUnitPresent() && systemdUsable()) {
    const active = systemctl(['is-active', 'caddy'], 5000)
    return { manager: 'systemd', running: active.out === 'active', detail: active.out || null }
  }
  return { manager: 'process', running: caddyRunning(), detail: null }
}

function startWaf() {
  const current = wafStatus()
  if (current.running) {
    return { ok: true, alreadyRunning: true, manager: current.manager, message: 'The WAF (Caddy) is already running.' }
  }

  if (caddyUnitPresent() && systemdUsable()) {
    const r = systemctl(['start', 'caddy'])
    if (!r.ok) return { ok: false, manager: 'systemd', error: r.error || 'systemctl start caddy failed' }
    return { ok: wafStatus().running, manager: 'systemd', error: null }
  }

  const bin = caddyBinary()
  if (!bin) {
    return { ok: false, code: 'NO_CADDY', error: 'Caddy is not installed or not on PATH. Run `catwaf doctor` for details.' }
  }
  const config = caddyfilePath()
  if (!fs.existsSync(config)) {
    return { ok: false, code: 'NO_CADDY', error: `No Caddyfile at ${config}. Run \`catwaf setup\` to generate one.` }
  }

  const out = fs.openSync(path.join(dataDir(), 'caddy.log'), 'a')
  const child = spawn(bin, ['run', '--config', config, '--adapter', 'caddyfile'], {
    cwd: PROJECT_ROOT, detached: true, stdio: ['ignore', out, out], env: process.env,
  })
  child.unref()
  try { fs.closeSync(out) } catch {}
  if (!child.pid) return { ok: false, manager: 'process', error: 'failed to spawn caddy' }
  return { ok: true, manager: 'process', pid: child.pid }
}

async function waitUntilStopped(pid, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (!pidAlive(pid)) return true
    await new Promise(r => setTimeout(r, 150))
  }
  return !pidAlive(pid)
}

async function stop() {
  const current = status()
  if (!current.running) {
    clearPid()
    return { ok: true, alreadyStopped: true, message: 'CatWAF is not running.' }
  }

  if (current.manager === 'systemd') {
    const r = systemctl(['stop', 'catwaf'])
    if (!r.ok) return { ok: false, manager: 'systemd', error: r.error || 'systemctl stop failed' }
    return { ok: !status().running, manager: 'systemd' }
  }

  const pid = current.pid
  try { process.kill(pid, 'SIGTERM') } catch (e) {
    if (e.code === 'ESRCH') { clearPid(); return { ok: true, manager: 'process' } }
    return { ok: false, manager: 'process', error: e.message }
  }

  let stopped = await waitUntilStopped(pid, 8000)
  if (!stopped) {
    try { process.kill(pid, 'SIGKILL') } catch {}
    stopped = await waitUntilStopped(pid, 3000)
  }
  if (stopped) clearPid()
  return { ok: stopped, manager: 'process', pid, error: stopped ? null : 'process did not exit' }
}

async function restart() {
  const s = await stop()
  if (!s.ok) return { ok: false, phase: 'stop', error: s.error }
  await new Promise(r => setTimeout(r, 300))
  const st = start()
  return st.ok ? { ok: true, manager: st.manager, pid: st.pid } : { ok: false, phase: 'start', error: st.error }
}

function logs({ lines = 50, follow = false } = {}) {
  if (systemdUsable()) {
    const args = ['-u', 'catwaf', '-n', String(lines), '--no-pager']
    if (follow) args.push('-f')
    return { mode: 'journalctl', command: 'journalctl', args }
  }
  return { mode: 'file', file: logFile(), lines, follow }
}

module.exports = {
  status, start, stop, restart, logs,
  startWaf, wafStatus, caddyRunning, caddyUnitPresent,
  pidFile, logFile, hasSystemdUnit, systemdUsable, UNIT_PATH,
}
