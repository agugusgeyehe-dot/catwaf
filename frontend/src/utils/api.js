
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

// "CatWAF is not answering" and "CatWAF says no" are different states and must
// never be collapsed into one. A failed `fetch` is a transport failure — the
// process is stopped, the port is wrong, the network is down, or the browser
// refused the response — and it says nothing at all about whether the session
// is valid. Treating it as a rejected session is what produced the login loop:
// sign in, a background call fails to connect, the session is discarded, back
// to the login screen, forever.
export const API_UNREACHABLE = 'API_UNREACHABLE'

function unreachable(cause) {
  const err = new Error(
    'CatWAF API is unavailable. Check that the CatWAF backend is running (`catwaf status`), then try again.',
  )
  err.code = API_UNREACHABLE
  err.status = 0
  err.cause = cause
  return err
}

// Every network call in this module goes through here, so there is exactly
// one place that decides what a transport failure means.
async function safeFetch(url, options) {
  try {
    return await fetch(url, options)
  } catch (e) {
    throw unreachable(e)
  }
}

async function ensureGate() {
  const cached = getGate()
  if (cached?.basePath && cached.expiresAt > Date.now() + 5000) return cached
  const res = await safeFetch(API_ORIGIN + '/api/handshake', {
    headers: { Authorization: `Bearer ${getToken()}` },
  })
  if (!res.ok) {
    // Only an answer from the server can end a session. 401/410 mean the
    // token really is no longer good; a 5xx means CatWAF is having a bad
    // time and the session should survive it.
    if (res.status === 401 || res.status === 403 || res.status === 410) {
      clearSession()
      window.dispatchEvent(new Event('catwaf-auth-changed'))
      throw new Error('Your session expired — please sign in again.')
    }
    const err = new Error(`CatWAF could not establish an API session (HTTP ${res.status}).`)
    err.status = res.status
    throw err
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

  const res = await safeFetch(url, { method, headers, body: bodyStr })

  if (res.status === 410 && retryOn410) {
    setGate(null)
    return doFetch(method, logicalPath, bodyStr, false)
  }
  return res
}

async function req(method, path, body) {
  const bodyStr = body !== undefined ? JSON.stringify(body) : undefined
  const res = await doFetch(method, BASE + path, bodyStr)

  // A 401 from the login endpoint means the credentials were wrong, not that
  // an existing session ended. Clearing state there would tear down the app
  // around the login form every time someone mistypes a password.
  if (res.status === 401 && !PUBLIC_PATHS.has((BASE + path).split('?')[0])) {
    clearSession(); window.dispatchEvent(new Event('catwaf-auth-changed'))
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Request failed' }))
    const detail = err.detail || 'Request failed'
    const extra = Array.isArray(err.errors) && err.errors.length ? ': ' + err.errors.join('; ') : ''
    const error = new Error(detail + extra)
    // The backend distinguishes "wrong password" from "second factor needed"
    // with a machine-readable code. Losing it here would leave the login form
    // unable to tell the two apart.
    error.code = err.code || null
    error.status = res.status
    throw error
  }
  return res.json()
}

// Some endpoints answer with HTML or CSV rather than JSON — the rendered
// challenge page, and report exports. They still travel over the signed,
// rotating admin path, so a plain <iframe src> or <a download> cannot reach
// them; the response has to be fetched here and handed on as a blob.
export async function apiRaw(method, path, body) {
  const bodyStr = body !== undefined ? JSON.stringify(body) : undefined
  const res = await doFetch(method, BASE + path, bodyStr)
  if (res.status === 401) {
    clearSession(); window.dispatchEvent(new Event('catwaf-auth-changed'))
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Request failed' }))
    throw new Error(err.detail || 'Request failed')
  }
  return res
}

export async function apiText(path) {
  return (await apiRaw('GET', path)).text()
}

// Returns an object URL the caller owns and must revoke.
export async function apiBlobUrl(path) {
  const res = await apiRaw('GET', path)
  return URL.createObjectURL(await res.blob())
}

export async function apiDownload(path, fallbackName) {
  const res = await apiRaw('GET', path)
  const disposition = res.headers.get('Content-Disposition') || ''
  const named = /filename="([^"]+)"/.exec(disposition)
  const url = URL.createObjectURL(await res.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = named ? named[1] : fallbackName
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 10000)
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

  const res = await safeFetch(url, { method: 'POST', headers, body: bodyStr })

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
