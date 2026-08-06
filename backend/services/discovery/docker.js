// discovery/docker.js — thin, defensive wrapper around the `docker` CLI.
//
// CatWAF never talks to the Docker socket directly (see docker-compose.yml's
// "NO DOCKER SOCKET" note) — everything here shells out to the `docker`
// binary, exactly like backend/services/environment.js and provision.js do
// for Caddy/nginx/Apache. Every call is defensive: a missing binary, a
// permission-denied socket, a container that exits mid-inspect, or
// malformed JSON must never throw past this module.

const { execFileSync } = require('child_process')

function realExec(args, opts = {}) {
  return execFileSync('docker', args, {
    encoding: 'utf8',
    timeout: opts.timeout || 8000,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).toString()
}

// classify a failed docker CLI invocation without leaking stack traces
function reason(e) {
  if (e && e.code === 'ENOENT') return { code: 'NOT_INSTALLED', message: 'Docker CLI not found on PATH.' }
  const stderr = String(e && (e.stderr || e.message) || '')
  if (/permission denied/i.test(stderr) || /dial unix.*permission/i.test(stderr)) {
    return { code: 'PERMISSION_DENIED', message: 'Permission denied talking to the Docker daemon. Add this user to the `docker` group or run with sufficient privileges.' }
  }
  if (/cannot connect to the docker daemon/i.test(stderr) || /is the docker daemon running/i.test(stderr)) {
    return { code: 'DAEMON_UNAVAILABLE', message: 'Docker daemon is not reachable (is it running?).' }
  }
  if (e && (e.signal === 'SIGTERM' || /timed out/i.test(stderr))) {
    return { code: 'TIMEOUT', message: 'Docker command timed out.' }
  }
  return { code: 'UNKNOWN', message: stderr.split('\n')[0] || (e && e.message) || 'Unknown Docker error.' }
}

function parseJsonLines(text) {
  const out = []
  for (const line of String(text || '').split('\n')) {
    const trimmed = line.trim()
    if (!trimmed) continue
    try { out.push(JSON.parse(trimmed)) } catch { /* skip a malformed/partial line rather than failing the whole scan */ }
  }
  return out
}

function createDockerClient(exec = realExec) {
  function isAvailable() {
    try {
      exec(['version', '--format', '{{.Server.Version}}'], { timeout: 5000 })
      return { ok: true }
    } catch (e) {
      const r = reason(e)
      return { ok: false, code: r.code, message: r.message }
    }
  }

  // one line of summary JSON per container — cheap, always available even
  // when a deeper `inspect` on a specific container fails later.
  function listContainers() {
    try {
      const out = exec(['ps', '-a', '--format', '{{json .}}'], { timeout: 10000 })
      return { ok: true, containers: parseJsonLines(out) }
    } catch (e) {
      const r = reason(e)
      return { ok: false, code: r.code, message: r.message, containers: [] }
    }
  }

  // full metadata for one container; returns null (not a throw) if the
  // container vanished or inspect fails for any reason.
  function inspectContainer(idOrName) {
    try {
      const out = exec(['inspect', idOrName], { timeout: 8000 })
      const parsed = JSON.parse(out)
      return Array.isArray(parsed) ? (parsed[0] || null) : parsed
    } catch {
      return null
    }
  }

  function inspectNetwork(name) {
    try {
      const out = exec(['network', 'inspect', name], { timeout: 8000 })
      const parsed = JSON.parse(out)
      return Array.isArray(parsed) ? (parsed[0] || null) : parsed
    } catch {
      return null
    }
  }

  // host-visible process list for a container (works without extra
  // privileges in the common case — same mechanism `docker top` always uses).
  function topProcesses(idOrName) {
    try {
      const out = exec(['top', idOrName], { timeout: 5000 })
      const lines = out.split('\n').filter(Boolean)
      return lines.slice(1).map(l => l.trim())
    } catch {
      return null
    }
  }

  // best-effort read-only probe inside a container's filesystem. Never
  // mutates anything; swallows every failure (no shell, read-only rootfs,
  // container stopped, exec disabled, permission denied, ...).
  function execTest(idOrName, testExpr, opts = {}) {
    try {
      exec(['exec', idOrName, 'sh', '-c', testExpr], { timeout: opts.timeout || 3000 })
      return true
    } catch {
      return false
    }
  }

  // same as execTest but returns captured stdout instead of a boolean —
  // used for one-shot filesystem probes that check several paths at once.
  //
  // A non-zero exit does NOT mean there was no output: these probes chain
  // several `cat`s over paths that may not exist, and the exit status
  // reflects only the last one. Discarding stdout on a non-zero exit threw
  // away perfectly good config, so partial output is always returned.
  function execCapture(idOrName, shellCmd, opts = {}) {
    try {
      return { ok: true, stdout: exec(['exec', idOrName, 'sh', '-c', shellCmd], { timeout: opts.timeout || 4000 }) }
    } catch (e) {
      const partial = String((e && e.stdout) || '')
      return { ok: partial.trim().length > 0, stdout: partial }
    }
  }

  // Attach a container to a Docker network. This is the one mutating
  // operation in this module — it is what lets CatWAF's proxy actually
  // reach a discovered app. It adds a network interface to CatWAF's own
  // proxy container and never touches the application's containers.
  function networkConnect(network, container) {
    try {
      exec(['network', 'connect', network, container], { timeout: 10000 })
      return { ok: true }
    } catch (e) {
      const r = reason(e)
      const stderr = String(e && (e.stderr || '') || '')
      if (/already exists in network/i.test(stderr)) return { ok: true, alreadyAttached: true }
      return { ok: false, code: r.code, error: r.message }
    }
  }

  return {
    isAvailable, listContainers, inspectContainer, inspectNetwork,
    topProcesses, execTest, execCapture, networkConnect,
  }
}

module.exports = { createDockerClient, ...createDockerClient() }
