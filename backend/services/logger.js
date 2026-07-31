
const fs = require('fs')
const path = require('path')

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 }
const CONFIGURED_LEVEL = LEVELS[(process.env.LOG_LEVEL || 'info').toLowerCase()] ?? LEVELS.info

const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '..', 'data', 'logs')
let logDirReady = false
function ensureLogDir() {
  if (logDirReady) return
  try { fs.mkdirSync(LOG_DIR, { recursive: true }); logDirReady = true } catch {}
}

function currentLogFile() {
  const d = new Date().toISOString().slice(0, 10)
  return path.join(LOG_DIR, `catwaf-${d}.log`)
}

function writeLine(level, mod, message, meta) {
  if (LEVELS[level] < CONFIGURED_LEVEL) return
  const line = {
    ts: new Date().toISOString(),
    level,
    module: mod || 'app',
    message,
    ...(meta && Object.keys(meta).length ? { meta } : {}),
  }
  const text = JSON.stringify(line)

  const prefix = `[${line.ts}] [${level.toUpperCase()}] [${line.module}]`
  const consoleFn = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log
  consoleFn(`${prefix} ${message}`, meta && Object.keys(meta).length ? meta : '')

  ensureLogDir()
  if (logDirReady) {
    try { fs.appendFileSync(currentLogFile(), text + '\n') } catch {}
  }
}

function child(moduleName) {
  return {
    debug: (message, meta) => writeLine('debug', moduleName, message, meta),
    info:  (message, meta) => writeLine('info',  moduleName, message, meta),
    warn:  (message, meta) => writeLine('warn',  moduleName, message, meta),
    error: (message, meta) => writeLine('error', moduleName, message, meta),
  }
}

module.exports = { child, ...child('app') }
