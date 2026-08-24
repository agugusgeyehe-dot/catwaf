
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
  // getRandomValues, unlike crypto.subtle, is available in every context —
  // it is not gated behind "secure context" — so this never needs a fallback.
  crypto.getRandomValues(bytes)
  return toHex(bytes)
}

// crypto.subtle only exists in a "secure context": https, or the browser's
// localhost/127.0.0.1 exemption. Reach the dashboard any other way — a LAN
// IP over plain HTTP, a domain with HTTPS not yet configured — and
// `crypto.subtle` is `undefined`. Firefox throws immediately on property
// access ("can't access property 'digest', crypto.subtle is undefined");
// Chrome is more lenient about the property existing but every call still
// rejects. Either way, signing every request would otherwise crash the app
// before the login form could even submit.
//
// The request signature is a replay/tamper guard on top of the bearer
// token, not the only thing standing between an attacker and the account —
// so a pure-JS fallback that reproduces the exact same SHA-256 and
// HMAC-SHA256 the backend verifies (backend/middleware/signing.js) keeps
// signing working end-to-end without WebCrypto, rather than silently
// dropping the header or crashing the app.
const hasSubtle = typeof crypto !== 'undefined' && !!crypto.subtle

// ---- Pure-JS SHA-256 (FIPS 180-4), used only when crypto.subtle is absent ----
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

function rotr(x, n) { return (x >>> n) | (x << (32 - n)) }

function sha256Bytes(msgBytes) {
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19

  const bitLen = msgBytes.length * 8
  const withOne = new Uint8Array(msgBytes.length + 1)
  withOne.set(msgBytes)
  withOne[msgBytes.length] = 0x80
  const padTo = Math.ceil((withOne.length + 8) / 64) * 64
  const padded = new Uint8Array(padTo)
  padded.set(withOne)
  const view = new DataView(padded.buffer)
  // bitLen fits comfortably in 32 bits for anything this client ever hashes.
  view.setUint32(padTo - 4, bitLen >>> 0)

  const w = new Uint32Array(64)
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4)
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0
    }

    let [a, b, c, d, e, f, g, h] = [h0, h1, h2, h3, h4, h5, h6, h7]
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      const ch = (e & f) ^ (~e & g)
      const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) | 0
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const t2 = (S0 + maj) | 0
      h = g; g = f; f = e; e = (d + t1) | 0
      d = c; c = b; b = a; a = (t1 + t2) | 0
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0
  }

  const out = new Uint8Array(32)
  const outView = new DataView(out.buffer)
  ;[h0, h1, h2, h3, h4, h5, h6, h7].forEach((h, i) => outView.setUint32(i * 4, h >>> 0))
  return out
}

function hmacSha256Bytes(keyBytes, msgBytes) {
  const BLOCK = 64
  let key = keyBytes
  if (key.length > BLOCK) key = sha256Bytes(key)
  const padded = new Uint8Array(BLOCK)
  padded.set(key)

  const opad = new Uint8Array(BLOCK), ipad = new Uint8Array(BLOCK)
  for (let i = 0; i < BLOCK; i++) { opad[i] = padded[i] ^ 0x5c; ipad[i] = padded[i] ^ 0x36 }

  const inner = new Uint8Array(BLOCK + msgBytes.length)
  inner.set(ipad); inner.set(msgBytes, BLOCK)
  const innerHash = sha256Bytes(inner)

  const outer = new Uint8Array(BLOCK + innerHash.length)
  outer.set(opad); outer.set(innerHash, BLOCK)
  return sha256Bytes(outer)
}

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str)
  if (hasSubtle) {
    const digest = await crypto.subtle.digest('SHA-256', bytes)
    return toHex(digest)
  }
  return toHex(sha256Bytes(bytes))
}

async function hmacHex(keyStr, message) {
  if (hasSubtle) {
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(keyStr), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    )
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message))
    return toHex(sig)
  }
  return toHex(hmacSha256Bytes(new TextEncoder().encode(keyStr), new TextEncoder().encode(message)))
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
  if (cached?.basePath && cached.expiresAt > Date.now() + 5000) {
    try { return validateGate(cached) } catch { /* fall through to a fresh handshake */ }
  }
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
  return validateGate(data.api)
}

// The gate path is prepended to every authenticated request URL together
// with the Bearer token. If a tampered localStorage value (or a compromised
// handshake response) ever made it an absolute URL, every signed call —
// credentials included — would be sent cross-origin. Only the exact shape
// the server mints is accepted.
function validateGate(gate) {
  if (!gate || !/^\/g\/[0-9a-f]{32}$/.test(gate.basePath || '') || typeof gate.expiresAt !== 'number') {
    setGate(null)
    throw new Error('The API returned an invalid session path.')
  }
  return gate
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
