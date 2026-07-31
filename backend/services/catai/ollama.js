
const logger = require('../logger')
const log = logger.child('catai')

const OLLAMA_URL = (process.env.OLLAMA_URL || 'http://127.0.0.1:11434').replace(/\/$/, '')
const MODEL = process.env.CATAI_MODEL || 'qwen3:1.7b'
const KEEP_ALIVE = process.env.CATAI_KEEP_ALIVE || '5m'
const GENERATE_TIMEOUT_MS = 90_000
const PROBE_TIMEOUT_MS = 3_000

const NUM_THREAD = Math.max(1, require('os').cpus().length - 1)

const BASE_OPTIONS = {
  num_predict: 200,
  num_ctx: 2048,
  temperature: 0.2,
  num_thread: NUM_THREAD,
}

let busy = false
function withSlot(fn) {
  if (busy) {
    const err = new Error('CatAI is already answering another question.')
    err.code = 'CATAI_BUSY'
    throw err
  }
  busy = true
  return Promise.resolve()
    .then(fn)
    .finally(() => { busy = false })
}
function isBusy() { return busy }

const BREAKER_THRESHOLD = 3
const BREAKER_COOLDOWN_MS = 60_000
let consecutiveFailures = 0
let openUntil = 0

function breakerOpen() { return Date.now() < openUntil }
function recordSuccess() { consecutiveFailures = 0; openUntil = 0 }
function recordFailure() {
  consecutiveFailures++
  if (consecutiveFailures >= BREAKER_THRESHOLD) {
    openUntil = Date.now() + BREAKER_COOLDOWN_MS
    log.warn('CatAI circuit breaker opened', { consecutiveFailures, cooldownMs: BREAKER_COOLDOWN_MS })
  }
}

async function status() {
  if (breakerOpen()) {
    return { configured: true, available: false, detail: 'Ollama is not responding right now — retrying automatically.', model: MODEL }
  }
  try {
    const res = await fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS) })
    if (!res.ok) return { configured: true, available: false, detail: `Ollama responded with HTTP ${res.status}.`, model: MODEL }
    const data = await res.json()
    const have = (data.models || []).some(m => m.name === MODEL || m.model === MODEL)
    if (!have) {
      return {
        configured: true, available: false, model: MODEL,
        detail: `Ollama is running, but the model "${MODEL}" isn't pulled yet. Run: ollama pull ${MODEL}`,
      }
    }
    return { configured: true, available: true, model: MODEL }
  } catch (e) {
    return {
      configured: true, available: false, model: MODEL,
      detail: `Could not reach Ollama at ${OLLAMA_URL} (${e.message}). Is it installed and running?`,
    }
  }
}

async function generateStream(prompt, onToken) {
  return withSlot(async () => {
    if (breakerOpen()) {
      const err = new Error('CatAI is temporarily unavailable.')
      err.code = 'CATAI_UNAVAILABLE'
      throw err
    }
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), GENERATE_TIMEOUT_MS)
    let full = ''
    try {
      const res = await fetch(`${OLLAMA_URL}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: MODEL, prompt, stream: true, think: false, keep_alive: KEEP_ALIVE, options: BASE_OPTIONS,
        }),
        signal: controller.signal,
      })
      if (!res.ok || !res.body) throw new Error(`Ollama returned HTTP ${res.status}`)

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
          let obj
          try { obj = JSON.parse(line) } catch { continue }
          if (obj.response) { full += obj.response; onToken(obj.response) }
          if (obj.done) { recordSuccess(); return full }
        }
      }
      recordSuccess()
      return full
    } catch (e) {
      recordFailure()
      if (e.name === 'AbortError') {
        const err = new Error('The assistant took too long to respond.')
        err.code = 'CATAI_TIMEOUT'
        throw err
      }
      throw e
    } finally {
      clearTimeout(timer)
    }
  })
}

async function toolCall(userMessage, tools) {
  return withSlot(async () => {
    if (breakerOpen()) return null
    try {
      const res = await fetch(`${OLLAMA_URL}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: MODEL,
          stream: false,
          keep_alive: KEEP_ALIVE,
          think: false,
          messages: [
            { role: 'system', content: 'Call a tool only if the user is clearly asking to change a firewall setting. Otherwise call no tool.' },
            { role: 'user', content: String(userMessage).slice(0, 500) },
          ],
          tools,
          options: { ...BASE_OPTIONS, num_predict: 250 },
        }),
        signal: AbortSignal.timeout(30_000),
      })
      if (!res.ok) { recordFailure(); return null }
      const data = await res.json()
      recordSuccess()
      const call = data?.message?.tool_calls?.[0]?.function
      if (!call || typeof call.name !== 'string') return null
      return { name: call.name, arguments: call.arguments || {} }
    } catch {
      recordFailure()
      return null
    }
  })
}

module.exports = { status, generateStream, toolCall, isBusy, MODEL, OLLAMA_URL }
