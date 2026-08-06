// sharedState.js — the counter store, with an optional external backend
// (idea #67).
//
// The brief flags this one as having no current use case in Free, and that
// is correct: a single CatWAF node has nothing to share state with. It is
// implemented anyway, and narrowly, because the *shape* is what matters —
// every counter that would need to be consistent across nodes (rate-limit
// windows, ban expiry, challenge attempt counts) now goes through one
// interface instead of each feature keeping its own Map. Swapping the
// backend later is then a configuration change rather than an audit of every
// caller.
//
// What deliberately does NOT move: SQLite stays the source of truth for
// configuration. Only counters — values that are cheap to lose and expensive
// to disagree about — are eligible.
//
// The Redis client is ~80 lines of RESP over a socket rather than a
// dependency. CatWAF ships ten runtime packages; adding one for a feature
// with no current use case would be the wrong trade.

const net = require('net')

const settings = require('./settings')
const logger = require('./logger')

const log = logger.child('shared-state')

// ─── In-memory backend (the default, and the only one Free needs) ────────

class MemoryBackend {
  constructor() { this.map = new Map() }

  async incr(key, ttlMs) {
    const entry = this.map.get(key)
    const now = Date.now()
    if (!entry || entry.expires <= now) {
      this.map.set(key, { value: 1, expires: now + ttlMs })
      return 1
    }
    entry.value++
    return entry.value
  }

  async get(key) {
    const entry = this.map.get(key)
    if (!entry || entry.expires <= Date.now()) return null
    return entry.value
  }

  async set(key, value, ttlMs) {
    this.map.set(key, { value, expires: Date.now() + ttlMs })
    return value
  }

  async del(key) { return this.map.delete(key) ? 1 : 0 }

  async ping() { return true }

  sweep() {
    const now = Date.now()
    let removed = 0
    for (const [key, entry] of this.map) if (entry.expires <= now) { this.map.delete(key); removed++ }
    return removed
  }

  stats() { return { backend: 'memory', keys: this.map.size } }
}

// ─── Redis backend ──────────────────────────────────────────────────────

function encodeCommand(args) {
  const parts = [`*${args.length}\r\n`]
  for (const arg of args) {
    const value = String(arg)
    parts.push(`$${Buffer.byteLength(value)}\r\n${value}\r\n`)
  }
  return parts.join('')
}

// Enough of RESP2 for the commands below: integers, simple strings, bulk
// strings, errors and arrays.
function parseReply(buffer) {
  const text = buffer.toString('utf8')
  const newline = text.indexOf('\r\n')
  if (newline === -1) return { incomplete: true }
  const type = text[0]
  const head = text.slice(1, newline)

  if (type === '+') return { value: head, consumed: newline + 2 }
  if (type === '-') return { error: head, consumed: newline + 2 }
  if (type === ':') return { value: Number(head), consumed: newline + 2 }
  if (type === '$') {
    const length = Number(head)
    if (length === -1) return { value: null, consumed: newline + 2 }
    const start = newline + 2
    if (text.length < start + length + 2) return { incomplete: true }
    return { value: text.slice(start, start + length), consumed: start + length + 2 }
  }
  if (type === '*') {
    const count = Number(head)
    if (count === -1) return { value: null, consumed: newline + 2 }
    let offset = newline + 2
    const items = []
    for (let i = 0; i < count; i++) {
      const sub = parseReply(buffer.slice(offset))
      if (sub.incomplete) return { incomplete: true }
      items.push(sub.error ? new Error(sub.error) : sub.value)
      offset += sub.consumed
    }
    return { value: items, consumed: offset }
  }
  return { error: `Unexpected RESP type "${type}"` }
}

class RedisBackend {
  constructor(cfg) {
    this.cfg = cfg
    this.prefix = cfg.key_prefix || 'catwaf:'
    this.healthy = false
    this.lastError = null
  }

  key(name) { return this.prefix + name }

  command(args) {
    const cfg = this.cfg
    return new Promise((resolve, reject) => {
      let url
      try { url = new URL(cfg.url) } catch { return reject(new Error('The Redis URL is not valid.')) }

      const socket = net.createConnection({
        host: url.hostname,
        port: Number(url.port) || 6379,
      })
      let buffer = Buffer.alloc(0)
      let pending = []
      let settled = false

      const finish = (err, value) => {
        if (settled) return
        settled = true
        socket.destroy()
        if (err) { this.healthy = false; this.lastError = err.message; reject(err) }
        else { this.healthy = true; this.lastError = null; resolve(value) }
      }

      socket.setTimeout(cfg.timeout_ms)
      socket.once('timeout', () => finish(new Error('Redis timed out')))
      socket.once('error', e => finish(e))

      socket.once('connect', () => {
        pending = []
        if (cfg.password) pending.push(['AUTH', cfg.password])
        if (url.pathname && url.pathname.length > 1) pending.push(['SELECT', url.pathname.slice(1)])
        pending.push(args)
        socket.write(pending.map(encodeCommand).join(''))
      })

      socket.on('data', chunk => {
        buffer = Buffer.concat([buffer, chunk])
        const replies = []
        let offset = 0
        for (;;) {
          const reply = parseReply(buffer.slice(offset))
          if (reply.incomplete) break
          if (reply.error) return finish(new Error(reply.error))
          replies.push(reply.value)
          offset += reply.consumed
          if (replies.length === pending.length) return finish(null, replies[replies.length - 1])
        }
      })
    })
  }

  async incr(key, ttlMs) {
    const value = await this.command(['INCR', this.key(key)])
    if (value === 1) await this.command(['PEXPIRE', this.key(key), Math.max(1, Math.round(ttlMs))])
    return value
  }

  async get(key) {
    const value = await this.command(['GET', this.key(key)])
    return value === null ? null : Number(value)
  }

  async set(key, value, ttlMs) {
    await this.command(['SET', this.key(key), String(value), 'PX', String(Math.max(1, Math.round(ttlMs)))])
    return value
  }

  async del(key) { return this.command(['DEL', this.key(key)]) }

  async ping() { return (await this.command(['PING'])) === 'PONG' }

  stats() { return { backend: 'redis', healthy: this.healthy, last_error: this.lastError, prefix: this.prefix } }
}

// ─── Facade ─────────────────────────────────────────────────────────────

const memory = new MemoryBackend()
let redis = null
let activeConfig = null

function backend() {
  const cfg = settings.get('cluster')
  if (cfg.backend !== 'redis' || !cfg.url) return memory
  if (!redis || JSON.stringify(activeConfig) !== JSON.stringify(cfg)) {
    redis = new RedisBackend(cfg)
    activeConfig = cfg
  }
  return redis
}

// Every operation falls back to the in-memory store when the external one
// fails and fail_open is set — a counter store going away must degrade the
// accuracy of rate limiting, not the availability of the site.
async function withFallback(operation, args) {
  const cfg = settings.get('cluster')
  const primary = backend()
  if (primary === memory) return memory[operation](...args)
  try {
    return await primary[operation](...args)
  } catch (e) {
    if (!cfg.fail_open) throw e
    log.warn(`Shared state unavailable, using local counters (${e.message})`)
    return memory[operation](...args)
  }
}

const incr = (key, ttlMs) => withFallback('incr', [key, ttlMs])
const get = key => withFallback('get', [key])
const set = (key, value, ttlMs) => withFallback('set', [key, value, ttlMs])
const del = key => withFallback('del', [key])

async function test() {
  const cfg = settings.get('cluster')
  if (cfg.backend !== 'redis') return { ok: true, backend: 'memory', note: 'Counters are local to this process. That is the right choice for a single-node install.' }
  if (!cfg.url) return { ok: false, error: 'The Redis backend is selected but no URL is configured.' }
  const started = Date.now()
  try {
    const pong = await new RedisBackend(cfg).ping()
    return { ok: pong, backend: 'redis', latency_ms: Date.now() - started }
  } catch (e) {
    return { ok: false, backend: 'redis', error: e.message, latency_ms: Date.now() - started }
  }
}

function status() {
  const cfg = settings.get('cluster')
  return {
    ...backend().stats(),
    configured_backend: cfg.backend,
    fail_open: cfg.fail_open,
    note: cfg.backend === 'memory'
      ? 'CatWAF Free is single-node, so counters live in this process. An external counter store only starts to matter with more than one node in front of the same site.'
      : 'Rate-limit windows, ban expiry and challenge attempts are shared through Redis; SQLite remains the source of truth for configuration.',
  }
}

function sweep() { return { removed: memory.sweep(), changed: false } }

module.exports = { incr, get, set, del, test, status, sweep, MemoryBackend, RedisBackend, parseReply, encodeCommand }
