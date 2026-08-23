
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')

const secrets = require('../services/secrets')
const JWT_SECRET = secrets.JWT_SECRET

const BCRYPT_COST = 12
const db = require('../services/db')

const DEFAULT_USERS = []

function loadUsers() {
  const stored = db.getState('users')
  return (stored && stored.length) ? stored : DEFAULT_USERS
}

// The account list was read once at module load and never again, so it went
// stale the moment another process touched it — and CatWAF is routinely more
// than one process. `catwaf user add` while the API was running left the API
// still answering "No account has been created yet"; `catwaf user passwd` and
// `catwaf user remove` did not affect the running API at all, which matters
// because those are the commands an operator reaches for to revoke access.
//
// Reads revalidate against SQLite at most once a second. That is one small
// indexed read per second on the authenticated path — every request already
// does a bcrypt compare or a JWT verify — and it bounds staleness to a second
// across every process instead of leaving it unbounded.
const USER_REVALIDATE_MS = 1000
let _usersReadAt = 0

function refreshUsers() {
  const now = Date.now()
  if (now - _usersReadAt < USER_REVALIDATE_MS) return
  _usersReadAt = now
  let fresh
  try { fresh = loadUsers() } catch { return }
  // A populated account store never legitimately becomes empty: removeUser()
  // refuses to delete the last admin. So an empty read on a store that had
  // accounts is a fault — a missing or unparseable `users` row, which
  // db.getState() reports as null rather than throwing — and NOT a signal to
  // believe there are no accounts. Believing it would be serious:
  // needsBootstrap() would turn true and re-open POST /api/setup/account,
  // which is unauthenticated and creates an admin. Keep what we had.
  if (_users.length && !fresh.length) return
  _users = fresh
}

function needsBootstrap() { refreshUsers(); return _users.length === 0 }
function saveUsers(users) {
  db.setState('users', users)
  _usersReadAt = Date.now()
}

let _users = loadUsers()
const USERS = new Proxy([], {
  get(_, prop) { refreshUsers(); return Reflect.get(_users, prop, _users) },
  set(_, prop, value) { return Reflect.set(_users, prop, value, _users) },
  has(_, prop) { return Reflect.has(_users, prop) },
  ownKeys() { return Reflect.ownKeys(_users) },
  deleteProperty(_, prop) { return Reflect.deleteProperty(_users, prop) },
  getOwnPropertyDescriptor(_, prop) {
    const d = Reflect.getOwnPropertyDescriptor(_users, prop)
    return d ? { ...d, configurable: true } : undefined
  },
})

const VALID_ROLES = ['admin', 'viewer']
const MIN_PASSWORD_LENGTH = 8

function addUser({ username, password, role = 'viewer' }) {
  refreshUsers()
  if (_users.find(u => u.username === username)) throw new Error(`User "${username}" already exists`)
  if (!VALID_ROLES.includes(role)) throw new Error(`Role must be one of: ${VALID_ROLES.join(', ')}`)
  if (!password || password.length < MIN_PASSWORD_LENGTH) throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
  const user = { id: 'u_' + crypto.randomBytes(6).toString('hex'), username, password_hash: bcrypt.hashSync(password, BCRYPT_COST), role, created_at: new Date().toISOString() }
  _users = [..._users, user]
  saveUsers(_users)
  return user
}
function setPassword(username, password) {
  refreshUsers()
  const u = _users.find(x => x.username === username)
  if (!u) throw new Error(`User "${username}" not found`)
  if (!password || password.length < MIN_PASSWORD_LENGTH) throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
  u.password_hash = bcrypt.hashSync(password, BCRYPT_COST)
  // Every token issued up to and including this second is dead: softAuth
  // compares with <=, and routes/auth.js refuses to mint a token whose iat
  // would land on this same second. Second granularity is all a JWT iat
  // carries, so the boundary has to be inclusive on both sides or a token
  // minted in the reset second survives the reset that was meant to kill it.
  u.tokens_valid_after = Math.floor(Date.now() / 1000)
  saveUsers(_users)
  // Belt and braces, and the part that shows up in the session list: revoke
  // the tracked sessions by jti as well, so an operator can see that the
  // reset ended them. Required lazily and tolerantly for the same reason
  // authRequired does it — the CLI paths never load the settings namespace,
  // and the tokens_valid_after stamp above is the authoritative control.
  try { require('../services/session').closeAllFor(username) } catch {}
  return u
}

function listUsers() {
  refreshUsers()
  return _users.map(u => ({ id: u.id, username: u.username, role: u.role, created_at: u.created_at || null }))
}

function findUser(username) {
  refreshUsers()
  return _users.find(u => u.username === username) || null
}

function removeUser(username) {
  refreshUsers()
  const target = _users.find(u => u.username === username)
  if (!target) throw new Error(`User "${username}" not found`)
  if (target.role === 'admin' && _users.filter(u => u.role === 'admin').length === 1) {
    throw new Error('Cannot remove the last admin account — CatWAF would become unadministrable.')
  }
  _users = _users.filter(u => u.username !== username)
  saveUsers(_users)
  return { username }
}

function setRole(username, role) {
  refreshUsers()
  if (!VALID_ROLES.includes(role)) throw new Error(`Role must be one of: ${VALID_ROLES.join(', ')}`)
  const u = _users.find(x => x.username === username)
  if (!u) throw new Error(`User "${username}" not found`)
  if (u.role === 'admin' && role !== 'admin' && _users.filter(x => x.role === 'admin').length === 1) {
    throw new Error('Cannot demote the last admin account — CatWAF would become unadministrable.')
  }
  u.role = role
  saveUsers(_users)
  return { username, role }
}

function verifyPassword(username, password) {
  refreshUsers()
  const u = _users.find(x => x.username === username)
  if (!u || !u.password_hash) return false
  return bcrypt.compareSync(String(password || ''), u.password_hash)
}

const JWT_ISSUER = 'catwaf-free'
const JWT_AUDIENCE = 'catwaf-dashboard'

function softAuth(req, res, next) {
  const h = req.headers.authorization || ''
  const bearer = h.startsWith('Bearer ') ? h.slice(7) : ''
  if (bearer) {
    try {
      const claims = jwt.verify(bearer, JWT_SECRET, {
        algorithms: ['HS256'],
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      })
      refreshUsers()
      const live = _users.find(u => u.id === claims.id)
      // Inclusive: a JWT iat is whole seconds, so a token minted in the same
      // second as the reset carries iat === tokens_valid_after. Treating that
      // as fresh left a one-second window in which an already-issued token
      // survived the password change. Legitimate logins are not caught by the
      // wider comparison because routes/auth.js pushes a new token's iat past
      // tokens_valid_after when the two would collide.
      const staleAfterReset = live && live.tokens_valid_after && claims.iat != null
        && claims.iat <= live.tokens_valid_after
      if (live && !staleAfterReset) {
        req.user = { ...claims, username: live.username, role: live.role }
      }
    } catch {}
  }
  if (!req.user) req.user = { username: 'guest', role: 'viewer' }
  next()
}

function authRequired(req, res, next) {
  if (!req.user || !req.user.jti || req.user.username === 'guest') {
    return res.status(401).json({ detail: 'Authentication required.', code: 'AUTH_REQUIRED' })
  }
  // Idle timeout and IP/browser binding (idea #25). Required lazily so the
  // middleware stays usable in the CLI paths that never load the settings
  // namespace, and so a failure here can never break authentication itself.
  try {
    const check = require('../services/session').touch(req.user.jti, req)
    if (check && check.ok === false) {
      return res.status(401).json({ detail: check.detail, code: check.code })
    }
  } catch { /* session tracking is hardening, not the auth decision */ }
  next()
}

function writeRequired(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ detail: 'Read-only role. Log in as admin to modify.' })
  next()
}

const LOGIN_ATTEMPTS = new Map()
const LOGIN_WINDOW_MS = 5 * 60 * 1000
const LOGIN_MAX_ATTEMPTS = 10

function attemptKey(req) {
  const username = typeof req.body?.username === 'string' ? req.body.username : ''
  return `${req.ip}:${username.toLowerCase().slice(0, 64)}`
}

function loginRateLimit(req, res, next) {
  const key = attemptKey(req)
  const now = Date.now()
  const entry = LOGIN_ATTEMPTS.get(key)
  if (entry && now - entry.firstAttemptAt < LOGIN_WINDOW_MS) {
    if (entry.count >= LOGIN_MAX_ATTEMPTS) {
      const retryAfterSec = Math.ceil((LOGIN_WINDOW_MS - (now - entry.firstAttemptAt)) / 1000)
      res.set('Retry-After', String(retryAfterSec))
      return res.status(429).json({ detail: 'Too many login attempts. Try again later.' })
    }
    entry.count++
  } else {
    LOGIN_ATTEMPTS.set(key, { count: 1, firstAttemptAt: now })
  }
  if (LOGIN_ATTEMPTS.size > 5000) {
    for (const [k, v] of LOGIN_ATTEMPTS) if (now - v.firstAttemptAt > LOGIN_WINDOW_MS) LOGIN_ATTEMPTS.delete(k)
  }
  next()
}
function clearLoginAttempts(req) {
  LOGIN_ATTEMPTS.delete(attemptKey(req))
}

module.exports = { JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE, USERS, softAuth, authRequired, writeRequired, loginRateLimit, clearLoginAttempts, addUser, setPassword, needsBootstrap, listUsers, findUser, removeUser, setRole, verifyPassword, VALID_ROLES, BCRYPT_COST, MIN_PASSWORD_LENGTH }
