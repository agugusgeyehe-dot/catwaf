// session.js — admin session lifetime and binding (idea #25).
//
// CatWAF already has a strong auth stack for its own control panel: JWTs, a
// rotating gate path, per-request signing. What it did not have was any way
// to tune the parts that decide how long a stolen token stays useful. These
// are exactly the knobs worth having as settings rather than constants,
// because the right answer differs: binding a session to its IP is excellent
// on a fixed office connection and actively hostile on a mobile network.
//
// Defaults reproduce the previous hardcoded behaviour — a 12-hour token, no
// idle timeout, no binding — so nothing changes for an existing install
// until an admin chooses otherwise.

const crypto = require('crypto')

const db = require('./db')
const settings = require('./settings')
const { normalizeClientIp } = require('./sanitize')

const STORE_KEY = 'admin_sessions'
// Explicitly revoked token IDs. Separate from the session store on purpose:
// deleting a session record means "we are no longer tracking this", which
// touch() has always — correctly — allowed through, because a valid JWT that
// predates the store or survived a restart that cleared it is not an attack.
// "The operator pressed Sign out" is a different statement and needs its own
// record, or logging out does not actually end the session: the JWT stays
// valid for its full lifetime and anyone holding it keeps their access.
const REVOKED_KEY = 'admin_sessions_revoked'
const MAX_TRACKED = 500

function load() {
  const stored = db.getState(STORE_KEY)
  return stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {}
}

function persist(sessions) { db.setState(STORE_KEY, sessions) }

// ─── Revocation ─────────────────────────────────────────────────────────
//
// { [jti]: <epoch ms after which the token would have expired anyway> }.
// Entries are dropped once the token could no longer be used regardless, so
// this cannot grow without bound.

function loadRevoked() {
  const stored = db.getState(REVOKED_KEY)
  return stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {}
}

function pruneRevoked(revoked) {
  const now = Date.now()
  for (const [jti, expiresAt] of Object.entries(revoked)) {
    if (!Number.isFinite(expiresAt) || expiresAt <= now) delete revoked[jti]
  }
  return revoked
}

function revoke(jti) {
  if (!jti) return
  const cfg = settings.get('session')
  const revoked = pruneRevoked(loadRevoked())
  // Hold the record for the token's full possible lifetime. Erring long is
  // free; erring short would let a signed-out token come back to life.
  revoked[jti] = Date.now() + Math.max(5, cfg.absolute_max_age_min) * 60_000
  db.setState(REVOKED_KEY, revoked)
}

function isRevoked(jti) {
  if (!jti) return false
  const revoked = loadRevoked()
  const expiresAt = revoked[jti]
  return Number.isFinite(expiresAt) && expiresAt > Date.now()
}

// A binding fingerprint, not the raw values: the session table should not
// become a second place the admin's address and browser string are stored.
function fingerprint(req) {
  const cfg = settings.get('session')
  const parts = []
  if (cfg.bind_ip) parts.push(normalizeClientIp(req?.ip || ''))
  if (cfg.bind_user_agent) parts.push(String(req?.headers?.['user-agent'] || '').slice(0, 300))
  if (!parts.length) return null
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 24)
}

function prune(sessions) {
  const cfg = settings.get('session')
  const now = Date.now()
  const maxAgeMs = Math.max(5, cfg.absolute_max_age_min) * 60_000
  for (const [jti, entry] of Object.entries(sessions)) {
    if (now - new Date(entry.created_at).getTime() > maxAgeMs) delete sessions[jti]
  }
  const keys = Object.keys(sessions)
  if (keys.length > MAX_TRACKED) {
    const oldest = keys.sort((a, b) => sessions[a].created_at.localeCompare(sessions[b].created_at))
    for (const jti of oldest.slice(0, keys.length - MAX_TRACKED)) delete sessions[jti]
  }
  return sessions
}

function open({ jti, user, req }) {
  if (!jti) return null
  const cfg = settings.get('session')
  const sessions = prune(load())

  // Concurrent-session cap: the oldest session for this user is dropped so
  // the newest login always succeeds. Refusing the new login instead would
  // let an attacker who filled the cap lock the real admin out.
  if (cfg.max_concurrent > 0) {
    const mine = Object.entries(sessions)
      .filter(([, s]) => s.username === user.username)
      .sort((a, b) => a[1].created_at.localeCompare(b[1].created_at))
    for (const [oldJti] of mine.slice(0, Math.max(0, mine.length - cfg.max_concurrent + 1))) delete sessions[oldJti]
  }

  sessions[jti] = {
    username: user.username,
    role: user.role,
    created_at: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    binding: fingerprint(req),
    ip_hint: normalizeClientIp(req?.ip || '').replace(/\.\d+$/, '.x'),
  }
  persist(sessions)
  return sessions[jti]
}

// Called on every authenticated request. Returns { ok } or a reason the
// session should be rejected. Unknown sessions are allowed through: a valid
// signed JWT that predates this store (or survived a restart that cleared
// it) must not be treated as an attack.
function touch(jti, req) {
  if (!jti) return { ok: true }

  // Checked before the settings short-circuit below, because a signed-out
  // token must stop working whether or not any session-hardening option is
  // switched on. This is the only rejection here that does not depend on a
  // setting.
  if (isRevoked(jti)) {
    return { ok: false, code: 'SESSION_REVOKED', detail: 'This session was signed out. Log in again.' }
  }

  const cfg = settings.get('session')
  if (!cfg.idle_timeout_min && !cfg.bind_ip && !cfg.bind_user_agent && !cfg.rolling) return { ok: true }

  const sessions = load()
  const entry = sessions[jti]
  if (!entry) return { ok: true, unknown: true }

  if (cfg.bind_ip || cfg.bind_user_agent) {
    const current = fingerprint(req)
    if (entry.binding && current && entry.binding !== current) {
      delete sessions[jti]
      persist(sessions)
      return { ok: false, code: 'SESSION_BINDING', detail: 'This session was started from a different client. Log in again.' }
    }
    // A session opened before binding was switched on has no fingerprint;
    // adopt the current one rather than locking the admin out of the change
    // they just made.
    if (!entry.binding && current) entry.binding = current
  }

  if (cfg.idle_timeout_min > 0) {
    const idleMs = Date.now() - new Date(entry.last_seen).getTime()
    if (idleMs > cfg.idle_timeout_min * 60_000) {
      delete sessions[jti]
      persist(sessions)
      return { ok: false, code: 'SESSION_IDLE', detail: `This session was idle for more than ${cfg.idle_timeout_min} minutes. Log in again.` }
    }
  }

  // Only written when it actually moves the needle — every authenticated
  // request would otherwise be a database write.
  const sinceWrite = Date.now() - new Date(entry.last_seen).getTime()
  if (sinceWrite > 30_000) {
    entry.last_seen = new Date().toISOString()
    if (cfg.rolling) entry.created_at = new Date().toISOString()
    persist(sessions)
  }

  return { ok: true }
}

function close(jti) {
  revoke(jti)
  const sessions = load()
  if (!sessions[jti]) return { ok: true, untracked: true }
  delete sessions[jti]
  persist(sessions)
  return { ok: true }
}

function closeAllFor(username) {
  const sessions = load()
  let removed = 0
  for (const [jti, entry] of Object.entries(sessions)) {
    if (entry.username === username) { revoke(jti); delete sessions[jti]; removed++ }
  }
  persist(sessions)
  return { ok: true, removed }
}

function list() {
  const sessions = prune(load())
  persist(sessions)
  return Object.entries(sessions).map(([jti, entry]) => ({
    id: jti.slice(0, 8),
    username: entry.username,
    role: entry.role,
    created_at: entry.created_at,
    last_seen: entry.last_seen,
    ip_hint: entry.ip_hint,
    bound: !!entry.binding,
  })).sort((a, b) => b.last_seen.localeCompare(a.last_seen))
}

function status() {
  const cfg = settings.get('session')
  return {
    ...cfg,
    active_sessions: Object.keys(load()).length,
    effective: {
      token_lifetime_min: cfg.absolute_max_age_min,
      idle_timeout: cfg.idle_timeout_min > 0 ? `${cfg.idle_timeout_min} minutes` : 'off',
      bindings: [cfg.bind_ip && 'client IP', cfg.bind_user_agent && 'browser'].filter(Boolean),
    },
  }
}

module.exports = { open, touch, close, closeAllFor, list, status, fingerprint, STORE_KEY }
