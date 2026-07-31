
const fs = require('fs')
const path = require('path')

const PROJECT_ROOT = path.join(__dirname, '..', '..')
const LITE = 'lite'
const FULL = 'full'
const EDITIONS = [LITE, FULL]

const FULL_ONLY = {
  api: 'the HTTP API server',
  dashboard: 'the web dashboard',
  docker: 'Docker stack management',
  catai: 'the CatAI assistant',
}

function dashboardBuilt() {
  try {
    return fs.existsSync(path.join(PROJECT_ROOT, 'frontend', 'dist', 'index.html'))
  } catch { return false }
}

function current() {
  const raw = String(process.env.CATWAF_EDITION || '').trim().toLowerCase()
  if (EDITIONS.includes(raw)) return raw
  return dashboardBuilt() ? FULL : LITE
}

function isLite() { return current() === LITE }
function isFull() { return current() === FULL }

function isExplicit() {
  return EDITIONS.includes(String(process.env.CATWAF_EDITION || '').trim().toLowerCase())
}

function isValid(value) {
  return EDITIONS.includes(String(value || '').trim().toLowerCase())
}

function unavailableMessage(capability) {
  const what = FULL_ONLY[capability] || capability
  return `This command requires CatWAF Full — ${what} is not installed in Lite.\n`
       + 'Run `catwaf setup --full` to add it. Your WAF configuration, rules, '
       + 'event history and admin accounts are preserved.'
}

function checkCapability(capability) {
  if (isFull()) return null
  if (!(capability in FULL_ONLY)) return null
  return { code: 'EDITION_LITE', message: unavailableMessage(capability) }
}

module.exports = {
  LITE, FULL, EDITIONS, FULL_ONLY,
  current, isLite, isFull, isExplicit, isValid,
  checkCapability, unavailableMessage, dashboardBuilt,
}
