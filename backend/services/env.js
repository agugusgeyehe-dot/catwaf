
const fs = require('fs')
const path = require('path')

const ENV_PATH = process.env.CATWAF_ENV_FILE || path.join(__dirname, '..', '..', '.env')

function parse(text) {
  const out = {}
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    const eq = line.indexOf('=')
    if (eq === -1) continue
    const key = line.slice(0, eq).trim()
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue
    let value = line.slice(eq + 1).trim()
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1)
    }
    out[key] = value
  }
  return out
}

let loaded = false
function load() {
  if (loaded) return
  loaded = true
  let text
  try { text = fs.readFileSync(ENV_PATH, 'utf8') } catch { return }

  try {
    const mode = fs.statSync(ENV_PATH).mode & 0o077
    if (mode) {
      console.warn(`[CatWAF] ${ENV_PATH} is readable by other users on this machine (mode ${(fs.statSync(ENV_PATH).mode & 0o777).toString(8)}).`)
      console.warn('[CatWAF] Run: chmod 600 ' + ENV_PATH)
    }
  } catch {}

  for (const [k, v] of Object.entries(parse(text))) {
    if (process.env[k] === undefined) process.env[k] = v
  }
}

module.exports = { load, parse, ENV_PATH }
