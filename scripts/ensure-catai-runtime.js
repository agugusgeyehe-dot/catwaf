#!/usr/bin/env node

const path = require('path')
const { spawn, spawnSync } = require('child_process')

const PROJECT_ROOT = path.join(__dirname, '..')
require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js')).load()

const CATAI_ENABLED = process.env.CATAI_ENABLED === 'true'
const OLLAMA_URL = (process.env.OLLAMA_URL || 'http://127.0.0.1:11434').replace(/\/$/, '')
const MODEL = process.env.CATAI_MODEL || 'qwen3:1.7b'
const KEEP_ALIVE = process.env.CATAI_KEEP_ALIVE || '30m'

function log(msg) { console.log(`[catai] ${msg}`) }

async function pingOllama(timeoutMs = 1500) {
  try {
    const res = await fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(timeoutMs) })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

function hasOllamaBinary() {
  const check = spawnSync('ollama', ['--version'], { stdio: 'ignore' })
  return check.status === 0
}

function startOllamaServe() {
  const child = spawn('ollama', ['serve'], { detached: true, stdio: 'ignore' })
  child.unref()
}

async function waitFor(conditionFn, { attempts = 20, delayMs = 300 } = {}) {
  for (let i = 0; i < attempts; i++) {
    const result = await conditionFn()
    if (result) return result
    await new Promise(r => setTimeout(r, delayMs))
  }
  return null
}

async function main() {
  if (!CATAI_ENABLED) {
    return
  }

  let tags = await pingOllama()

  if (!tags) {
    if (!hasOllamaBinary()) {
      log('CatAI is enabled but Ollama isn\'t installed — the assistant will report itself unavailable until it is.')
      log('Install it with: curl -fsSL https://ollama.com/install.sh | sh')
      return
    }
    log('Starting Ollama…')
    startOllamaServe()
    tags = await waitFor(() => pingOllama())
    if (!tags) {
      log('Ollama didn\'t come up in time — CatAI will retry on its own when you ask it something.')
      return
    }
  }

  const havePulled = (tags.models || []).some(m => m.name === MODEL || m.model === MODEL)
  if (!havePulled) {
    log(`Model ${MODEL} isn't downloaded yet — pulling it now (this only happens once)…`)
    const pull = spawnSync('ollama', ['pull', MODEL], { stdio: 'inherit' })
    if (pull.status !== 0) {
      log(`Could not pull ${MODEL} — CatAI will report itself unavailable. Try manually: ollama pull ${MODEL}`)
      return
    }
  }

  log(`Warming ${MODEL}…`)
  try {
    const res = await fetch(`${OLLAMA_URL}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: MODEL, prompt: 'hi', stream: false, keep_alive: KEEP_ALIVE, options: { num_predict: 1 } }),
      signal: AbortSignal.timeout(60_000),
    })
    if (res.ok) log('CatAI is ready — the cat icon in the dashboard is good to go.')
    else log(`Warm-up call returned HTTP ${res.status} — CatAI will still work, just with a cold first answer.`)
  } catch (e) {
    log(`Warm-up call failed (${e.message}) — CatAI will still work, just with a cold first answer.`)
  }
}

main().catch((e) => { log(`Unexpected error: ${e.message}`); process.exitCode = 0 })
