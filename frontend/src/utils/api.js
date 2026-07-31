
const API_ORIGIN = import.meta.env.VITE_API_BASE || ''
const BASE = '/api'

const PUBLIC_PATHS = new Set(['/api/auth/login', '/api/auth/status', '/api/handshake'])

const TOKEN_KEY = 'catwaf-token'
const SESSION_KEY_KEY = 'catwaf-session-key'
const GATE_KEY = 'catwaf-gate'

function getToken() { try { return localStorage.getItem(TOKEN_KEY) || '' } catch { return '' } }
function getSessionKey() { try { return localStorage.getItem(SESSION_KEY_KEY) || '' } catch { return '' } }
function getGate() { try { return JSON.parse(localStorage.getItem(GATE_KEY) || 'null') } catch { return null } }
function setGate(g) { try { g ? localStorage.setItem(GATE_KEY, JSON.stringify(g)) : localStorage.removeItem(GATE_KEY) } catch {} }

export function setToken(t) { try { t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY) } catch {} }
export function hasToken() { return !!getToken() }

export function setSession({ token, sessionKey, api } = {}) {
  setToken(token || '')
  try { sessionKey ? localStorage.setItem(SESSION_KEY_KEY, sessionKey) : localStorage.removeItem(SESSION_KEY_KEY) } catch {}
  setGate(api || null)
}

export function clearSession() {
  setToken('')
  try { localStorage.removeItem(SESSION_KEY_KEY) } catch {}
  setGate(null)
}

function toHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
}

function randomNonceHex() {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return toHex(bytes)
}

async function sha256Hex(str) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str))
  return toHex(digest)
}

async function hmacHex(keyStr, message) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(keyStr), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message))
  return toHex(sig)
}

async function ensureGate() {
  const cached = getGate()
  if (cached?.basePath && cached.expiresAt > Date.now() + 5000) return cached
  const res = await fetch(API_ORIGIN + '/api/handshake', {
    headers: { Authorization: `Bearer ${getToken()}` },
  })
  if (!res.ok) {
    clearSession()
    window.dispatchEvent(new Event('catwaf-auth-changed'))
    throw new Error('Your session expired — please sign in again.')
  }
  const data = await res.json()
  setGate(data.api)
  return data.api
}

async function doFetch(method, logicalPath, bodyStr, retryOn410 = true) {
  const tok = getToken()
  const sessionKey = getSessionKey()
  const headers = { 'Content-Type': 'application/json' }
  if (tok) headers.Authorization = `Bearer ${tok}`

  let url = API_ORIGIN + logicalPath
  const isPublic = PUBLIC_PATHS.has(logicalPath.split('?')[0])
  if (!isPublic && tok && sessionKey) {
    const gate = await ensureGate()
    const ts = String(Date.now())
    const nonce = randomNonceHex()
    const bodyHash = await sha256Hex(bodyStr || '')
    const canonical = [method.toUpperCase(), logicalPath, ts, nonce, bodyHash].join('\n')
    headers['x-catwaf-ts'] = ts
    headers['x-catwaf-nonce'] = nonce
    headers['x-catwaf-sig'] = await hmacHex(sessionKey, canonical)
    url = API_ORIGIN + gate.basePath + logicalPath
  }

  const res = await fetch(url, { method, headers, body: bodyStr })

  if (res.status === 410 && retryOn410) {
    setGate(null)
    return doFetch(method, logicalPath, bodyStr, false)
  }
  return res
}

async function req(method, path, body) {
  const bodyStr = body !== undefined ? JSON.stringify(body) : undefined
  const res = await doFetch(method, BASE + path, bodyStr)

  if (res.status === 401) {
    clearSession(); window.dispatchEvent(new Event('catwaf-auth-changed'))
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Request failed' }))
    const detail = err.detail || 'Request failed'
    const extra = Array.isArray(err.errors) && err.errors.length ? ': ' + err.errors.join('; ') : ''
    throw new Error(detail + extra)
  }
  return res.json()
}

export const api = {
  get:    (path)        => req('GET',    path),
  post:   (path, body)  => req('POST',   path, body),
  patch:  (path, body)  => req('PATCH',  path, body),
  delete: (path)        => req('DELETE', path),
  put:    (path, body)  => req('PUT',    path, body),
}

export async function postStream(path, body, onFrame, { retryOn410 = true } = {}) {
  const tok = getToken()
  const sessionKey = getSessionKey()
  const logicalPath = BASE + path
  const bodyStr = JSON.stringify(body || {})
  const headers = { 'Content-Type': 'application/json' }
  if (tok) headers.Authorization = `Bearer ${tok}`

  let url = API_ORIGIN + logicalPath
  if (tok && sessionKey) {
    const gate = await ensureGate()
    const ts = String(Date.now())
    const nonce = randomNonceHex()
    const bodyHash = await sha256Hex(bodyStr)
    const canonical = ['POST', logicalPath, ts, nonce, bodyHash].join('\n')
    headers['x-catwaf-ts'] = ts
    headers['x-catwaf-nonce'] = nonce
    headers['x-catwaf-sig'] = await hmacHex(sessionKey, canonical)
    url = API_ORIGIN + gate.basePath + logicalPath
  }

  const res = await fetch(url, { method: 'POST', headers, body: bodyStr })

  if (res.status === 410 && retryOn410) {
    setGate(null)
    return postStream(path, body, onFrame, { retryOn410: false })
  }
  if (res.status === 401) {
    clearSession(); window.dispatchEvent(new Event('catwaf-auth-changed'))
    throw new Error('Your session expired — please sign in again.')
  }
  if (!res.ok || !res.body) {
    const err = await res.json().catch(() => ({ detail: 'Request failed' }))
    throw new Error(err.detail || 'Request failed')
  }

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    buf += decoder.decode(value, { stream: true })
    let idx
    while ((idx = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, idx); buf = buf.slice(idx + 1)
      if (!line.trim()) continue
      let frame
      try { frame = JSON.parse(line) } catch { continue }
      onFrame(frame)
    }
  }
}
