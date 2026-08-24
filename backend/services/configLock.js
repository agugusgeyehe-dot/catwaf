// configLock.js — cross-process mutual exclusion for everything that
// read-modify-writes the WAF configuration: the `waf` state blob in SQLite,
// the extended settings rows, and the Caddyfile itself.
//
// CatWAF routinely runs as more than one process — the API server, plus any
// `catwaf …` CLI invocation, plus scheduled job runs. Every writer used to
// load-modify-persist a whole blob with no coordination, so two concurrent
// writers silently overwrote each other and interleaved Caddyfile edits
// could corrupt or drop each other's marker regions.
//
// The primitive is a lock file in the data directory:
//   * O_EXCL creation makes acquisition atomic across processes.
//   * The holder writes its pid and acquire time; release only unlinks when
//     the token is still ours, so a stale-broken lock can never delete a
//     newer holder's file.
//   * A crashed process cannot hold it forever: locks older than `staleMs`
//     are broken on sight (the holder is by definition dead or wedged; every
//     real mutation completes in well under a second).
//   * In-process re-entrancy is a depth counter — apply() paths never nest
//     today, but the guard costs nothing and removes the failure mode where
//     a future refactor deadlocks against itself.

const fs = require('fs')
const path = require('path')

const PROJECT_ROOT = path.join(__dirname, '..', '..')
const LOCK_DIR = process.env.DB_DIR || path.join(PROJECT_ROOT, 'data')
const LOCK_PATH = path.join(LOCK_DIR, 'config.lock')

const DEFAULTS = { timeoutMs: 30_000, staleMs: 60_000 }

let depth = 0
const TOKEN = { pid: process.pid, id: Math.random().toString(36).slice(2), at: 0 }
let heldSince = 0

// Contended acquisition has to WAIT without yielding to the event loop,
// because every critical section in this codebase is synchronous (routes,
// configTx, Caddyfile patches are plain sync functions whose callers read
// their return values immediately). Blocking waits here are rare and short:
// holders finish in well under a second, and contention itself is unusual.
function blockMs(ms) {
  try {
    // Sub-process sleep: keeps semantics honest without busy-burning CPU.
    const { execFileSync } = require('child_process')
    execFileSync(process.execPath, ['-e', `setTimeout(()=>{},${ms})`], { timeout: ms + 1000 })
  } catch { /* best effort */ }
}

function lockInfo() {
  try { return JSON.parse(fs.readFileSync(LOCK_PATH, 'utf8')) } catch { return null }
}

function pidAlive(pid) {
  try { process.kill(pid, 0); return true } catch (e) { return e.code === 'EPERM' }
}

function tryAcquire(staleMs) {
  fs.mkdirSync(LOCK_DIR, { recursive: true })
  const payload = JSON.stringify({ ...TOKEN, at: Date.now() })
  let fd
  try {
    fd = fs.openSync(LOCK_PATH, 'wx', 0o600)
  } catch (e) {
    if (e.code !== 'EEXIST') throw e

    // Held by someone else. Breaking a LIVE lock means two writers inside,
    // which is exactly the corruption this module exists to prevent — so
    // every break condition must be conservative:
    //   * the token names a dead pid            -> broken immediately
    //   * the recorded timestamp exceeds staleMs -> broken
    //   * the file is mid-write (empty/unparseable) -> judged by mtime, and
    //     only broken once it is older than staleMs (open->write takes
    //     microseconds; a 60s-old empty file is a crashed holder)
    const info = lockInfo()
    let broken = false
    if (info && Number.isFinite(info.pid)) {
      if (!pidAlive(info.pid)) broken = true
      else if (Number.isFinite(info.at) && Date.now() - info.at > staleMs) broken = true
    } else {
      try { broken = Date.now() - fs.statSync(LOCK_PATH).mtimeMs > staleMs } catch { broken = false }
    }

    if (broken) {
      try { fs.unlinkSync(LOCK_PATH) } catch {}
      try {
        fd = fs.openSync(LOCK_PATH, 'wx', 0o600)
      } catch { /* someone re-acquired between unlink and open — retry later */ }
    }
    return typeof fd === 'number'
  }
  // Write the payload IMMEDIATELY, then confirm we still own the file: a
  // competitor that read this file in its empty open->write gap would have
  // stale-broken us and re-acquired. Detecting that here turns a silent
  // double-holder into a simple retry.
  fs.writeSync(fd, payload)
  fs.closeSync(fd)
  TOKEN.at = Date.now()
  const own = lockInfo()
  if (!own || own.id !== TOKEN.id || own.pid !== process.pid) return false
  return true
}

function withConfigLock(fn, opts = {}) {
  if (depth > 0) {
    // Re-entrant within this process: the outermost holder owns the file.
    depth++
    try { return fn() } finally { depth-- }
  }

  const { timeoutMs, staleMs } = { ...DEFAULTS, ...opts }
  const deadline = Date.now() + timeoutMs
  for (;;) {
    if (tryAcquire(staleMs)) break
    if (Date.now() > deadline) {
      const info = lockInfo()
      const holder = info ? `pid ${info.pid}` : 'an unknown holder'
      throw new Error(`Timed out waiting for the configuration lock (held by ${holder}). No changes were made.`)
    }
    blockMs(20)
  }

  depth++
  heldSince = Date.now()
  if (process.env.CATWAF_LOCK_TRACE) trace(`acquire pid=${process.pid} id=${TOKEN.id}`)
  try {
    return fn()
  } finally {
    depth--
    if (depth === 0) {
      if (process.env.CATWAF_LOCK_TRACE) trace(`release  pid=${process.pid} id=${TOKEN.id}`)
      release()
    }
  }
}

function trace(line) {
  try {
    // O_APPEND writes are atomic at the OS level even across processes.
    fs.appendFileSync(process.env.CATWAF_LOCK_TRACE, `${Date.now()} ${line}\n`)
  } catch {}
}

function release() {
  // Only unlink while the file still holds OUR token — after a stale-break,
  // a competing process may legitimately own it now.
  const info = lockInfo()
  if (info && info.id === TOKEN.id && info.pid === process.pid) {
    try { fs.unlinkSync(LOCK_PATH) } catch {}
  }
}

// Crash-safe replace for shared config files (the Caddyfile above all): the
// previous writeFileSync-in-place left a truncated half-file behind if the
// process died mid-write, and readers on other processes saw the tear.
// Write sibling temp file, fsync, rename over the target — POSIX gives
// rename atomicity, so every reader sees old-or-new, never torn.
function atomicWriteFileSync(filePath, data, { mode = 0o644 } = {}) {
  const dir = path.dirname(filePath)
  fs.mkdirSync(dir, { recursive: true })
  const tmp = path.join(dir, `.${path.basename(filePath)}.tmp-${process.pid}-${Math.random().toString(36).slice(2, 8)}`)
  try {
    const fd = fs.openSync(tmp, 'w', mode)
    try {
      fs.writeSync(fd, data)
      fs.fsyncSync(fd)
    } finally {
      fs.closeSync(fd)
    }
    // Preserve an existing file's mode when we created the tmp with defaults.
    try {
      const st = fs.statSync(filePath)
      if ((st.mode & 0o7777) !== mode) fs.chmodSync(tmp, st.mode & 0o7777)
      if (st.gid !== undefined && process.getuid && process.getuid() === 0) fs.chownSync(tmp, st.uid, st.gid)
    } catch { /* target may not exist yet */ }
    fs.renameSync(tmp, filePath)
  } catch (e) {
    try { fs.unlinkSync(tmp) } catch {}
    throw e
  }
}

module.exports = { withConfigLock, atomicWriteFileSync, LOCK_PATH, _internal: { release, tryAcquire, lockInfo } }
