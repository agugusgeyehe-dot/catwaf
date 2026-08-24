// clamav.js — malware scanning for uploaded request bodies, via a local
// clamd daemon.
//
// This is a first-party optional module, not a plugin. CatWAF's plugins are
// data-only by design (see plugins.js's header), and an antivirus integration
// needs to run code on the request path — so it lives here, inside the same
// trust boundary as the rest of the backend, rather than widening the plugin
// contract to allow execution.
//
// We speak clamd's socket protocol directly rather than shelling out to
// `clamdscan`. Three reasons: INSTREAM hands the bytes over in memory, so an
// upload never has to be written to a temp file the scanner then re-reads;
// there is no shell to quote anything into; and a request-path scan cannot
// afford a process spawn per upload.
//
// CatWAF never bundles an AV engine or signature database. If clamd is not
// installed the feature reports itself unavailable and, by default, traffic
// is unaffected — installing CatWAF must not require installing ClamAV.

const net = require('net')
const fs = require('fs')

const logger = require('./logger')

const log = logger.child('clamav')

// Where the distro packages put clamd's socket. Checked in order when the
// operator has not named one explicitly, so the common install just works.
// /run and /var/run are root-owned: a socket there can only be planted by
// root. A world-writable directory like /tmp is deliberately NOT probed —
// any local user could plant a listener there, receive full upload contents
// over INSTREAM (exfiltration) and answer forged "stream: OK" verdicts.
const SOCKET_CANDIDATES = [
  '/run/clamav/clamd.ctl',
  '/var/run/clamav/clamd.ctl',
  '/run/clamav/clamd.sock',
  '/var/run/clamav/clamd.sock',
]

// clamd's INSTREAM chunk header is a 4-byte big-endian length. 64 KiB keeps
// us well under clamd's default StreamMaxLength per-chunk expectations.
const CHUNK_BYTES = 64 * 1024

// Availability is cached: probing a missing daemon on every request would
// add a connect-and-fail to each upload.
let availabilityCache = null
const AVAILABILITY_TTL_MS = 60_000

function connectionTarget(cfg = {}) {
  if (cfg.host) return { kind: 'tcp', host: cfg.host, port: Number(cfg.port) || 3310 }
  if (cfg.socket_path) return { kind: 'unix', path: cfg.socket_path }
  for (const path of SOCKET_CANDIDATES) {
    try { if (fs.existsSync(path)) return { kind: 'unix', path } } catch {}
  }
  return null
}

function connect(target, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = target.kind === 'unix'
      ? net.createConnection({ path: target.path })
      : net.createConnection({ host: target.host, port: target.port })

    const fail = err => { socket.destroy(); reject(err) }
    socket.setTimeout(timeoutMs, () => fail(new Error('clamd did not respond in time')))
    socket.once('error', fail)
    socket.once('connect', () => {
      socket.removeListener('error', fail)
      resolve(socket)
    })
  })
}

// Every clamd reply we care about is a single NUL-terminated line, so the
// read side is the same for PING, VERSION and INSTREAM.
function readReply(socket, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buf = ''
    // Every legitimate clamd reply is a short single line; a hostile or
    // misbehaving endpoint must not be able to balloon memory here.
    const MAX_REPLY_BYTES = 1 << 20
    const done = (err, value) => {
      clearTimeout(timer)
      socket.removeAllListeners('data')
      socket.removeAllListeners('error')
      socket.removeAllListeners('end')
      socket.destroy()
      err ? reject(err) : resolve(value)
    }
    const timer = setTimeout(() => done(new Error('clamd did not respond in time')), timeoutMs)
    socket.on('data', chunk => {
      buf += chunk.toString('utf8')
      if (buf.length > MAX_REPLY_BYTES) return done(new Error('clamd reply exceeded the size limit'))
      if (buf.includes('\0')) done(null, buf.split('\0')[0].trim())
    })
    socket.on('error', err => done(err))
    // clamd closes after answering; treat whatever arrived as the reply.
    socket.on('end', () => done(null, buf.replace(/\0/g, '').trim()))
  })
}

async function command(cmd, cfg = {}, timeoutMs = 5000) {
  const target = connectionTarget(cfg)
  if (!target) throw new Error('No clamd socket was found and none is configured.')
  const socket = await connect(target, timeoutMs)
  socket.write(`z${cmd}\0`)
  return readReply(socket, timeoutMs)
}

async function ping(cfg = {}, timeoutMs = 3000) {
  const reply = await command('PING', cfg, timeoutMs)
  return reply === 'PONG'
}

async function version(cfg = {}, timeoutMs = 3000) {
  return command('VERSION', cfg, timeoutMs)
}

// Detects whether scanning can work at all. Cached, and deliberately never
// throws — callers use this to decide whether to offer the feature, and a
// missing daemon is an expected state rather than an error.
async function available({ force = false, cfg = {} } = {}) {
  if (!force && availabilityCache && Date.now() - availabilityCache.at < AVAILABILITY_TTL_MS) {
    return availabilityCache.value
  }
  const target = connectionTarget(cfg)
  let value
  if (!target) {
    value = { available: false, reason: 'No clamd socket was found. Install ClamAV, or set the daemon address in settings.' }
  } else {
    try {
      const ok = await ping(cfg)
      value = ok
        ? { available: true, target: target.kind === 'unix' ? target.path : `${target.host}:${target.port}`, version: await version(cfg).catch(() => null) }
        : { available: false, reason: 'clamd is reachable but did not answer PING.' }
    } catch (e) {
      value = { available: false, reason: `Could not reach clamd: ${e.message}` }
    }
  }
  availabilityCache = { at: Date.now(), value }
  return value
}

function resetAvailabilityCache() { availabilityCache = null }

// Streams a buffer to clamd with INSTREAM and interprets the verdict.
//
// Returns {clean, virus, error}. A scan that could not be completed sets
// `error` and leaves `clean` null — deciding what to do about that is the
// caller's job, because it depends on the fail-open/fail-closed setting.
async function scanBuffer(buffer, cfg = {}, timeoutMs = 10_000) {
  const target = connectionTarget(cfg)
  if (!target) return { clean: null, virus: null, error: 'No clamd socket was found and none is configured.' }

  let socket
  try {
    socket = await connect(target, timeoutMs)
  } catch (e) {
    return { clean: null, virus: null, error: `Could not reach clamd: ${e.message}` }
  }

  try {
    socket.write('zINSTREAM\0')
    for (let offset = 0; offset < buffer.length; offset += CHUNK_BYTES) {
      const chunk = buffer.subarray(offset, offset + CHUNK_BYTES)
      const header = Buffer.alloc(4)
      header.writeUInt32BE(chunk.length, 0)
      socket.write(header)
      socket.write(chunk)
    }
    // A zero-length chunk terminates the stream.
    socket.write(Buffer.from([0, 0, 0, 0]))

    const reply = await readReply(socket, timeoutMs)
    return interpret(reply)
  } catch (e) {
    try { socket.destroy() } catch {}
    return { clean: null, virus: null, error: `Scan failed: ${e.message}` }
  }
}

// clamd answers "stream: OK", "stream: <signature> FOUND", or something
// ending in ERROR. Anything we do not recognise is treated as an error
// rather than as clean — an unreadable verdict is not a negative one.
function interpret(reply) {
  const text = String(reply || '').trim()
  if (!text) return { clean: null, virus: null, error: 'clamd returned an empty response.' }
  if (/\bOK$/.test(text)) return { clean: true, virus: null, error: null }
  const found = text.match(/^stream:\s*(.+?)\s+FOUND$/)
  if (found) return { clean: false, virus: found[1], error: null }
  if (/ERROR$/i.test(text)) return { clean: null, virus: null, error: text.replace(/\s*ERROR$/i, '') }
  return { clean: null, virus: null, error: `Unrecognised clamd response: ${text}` }
}

module.exports = {
  available,
  resetAvailabilityCache,
  scanBuffer,
  ping,
  version,
  interpret,
  connectionTarget,
  SOCKET_CANDIDATES,
  CHUNK_BYTES,
}
