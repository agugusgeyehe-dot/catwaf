
const fs = require('fs')
const path = require('path')
const db = require('./db')
const caddy = require('./caddy')
const auditSvc = require('./audit')
const { isValidCaddyPath } = require('./sanitize')

const MARKER_START = '# @@CATWAF_SENSITIVE_START@@'
const MARKER_END   = '# @@CATWAF_SENSITIVE_END@@'

const WORDLIST_DIR = path.join(__dirname, '..', '..', 'frontend', 'public', 'wordlists')

function getSensitiveState() {
  return db.getState('sensitive') || { sfl_level: 0, blocked: [] }
}
function saveSensitiveState(s) { db.setState('sensitive', s) }

function loadWordlistFile(level) {
  const listFile = path.join(WORDLIST_DIR, `sfl${level}.txt`)
  try {
    return fs.readFileSync(listFile, 'utf8')
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'))
      .map(l => l.startsWith('/') ? l : '/' + l)
      .slice(0, 500)
  } catch {
    return []
  }
}

// Higher levels include every path blocked by all lower levels:
// SFL2 ⊇ SFL1, SFL3 ⊇ SFL2, SFL4 ⊇ SFL3.
function cumulativeSflPaths(level) {
  const seen = new Set()
  for (let lvl = 1; lvl <= level; lvl++) {
    for (const p of loadWordlistFile(lvl)) seen.add(p)
  }
  return [...seen]
}

function buildSensitiveBlock(state) {
  const { sfl_level } = state
  const blocked = (state.blocked || []).filter(isValidCaddyPath)

  if (sfl_level === 0 && blocked.length === 0) return ''

  const lines = []
  lines.push(MARKER_START)
  lines.push('# CatWAF Sensitive File Protection — auto-generated, do not edit manually')
  lines.push('')

  if (sfl_level >= 1 && sfl_level <= 3) {
    const allPaths = [...new Set([...cumulativeSflPaths(sfl_level), ...blocked])]

    if (allPaths.length > 0) {
      lines.push(`  # SFL${sfl_level} — blocking ${allPaths.length} sensitive paths`)
      lines.push(`  @catwaf_sensitive {`)
      lines.push(`    path ${allPaths.join(' ')}`)
      lines.push(`  }`)
      lines.push(`  handle @catwaf_sensitive {`)
      lines.push(`    respond "You have been blocked by CatWAF" 403`)
      lines.push(`  }`)
    }
  }

  if (sfl_level === 4) {
    const serverListPath = path.join(caddy.CORAZA_LIST_DIR, 'sfl4.txt')

    try {
      if (!fs.existsSync(caddy.CORAZA_LIST_DIR)) fs.mkdirSync(caddy.CORAZA_LIST_DIR, { recursive: true })
      fs.copyFileSync(path.join(WORDLIST_DIR, 'sfl4.txt'), serverListPath)
    } catch (e) {
      console.warn(`[CatWAF] Could not write SFL4 list to ${serverListPath}: ${e.message}`)
    }

    const allSfl4 = [...new Set([...cumulativeSflPaths(4), ...blocked])]
    lines.push(`  # SFL4 — MAXIMUM — blocking ${allSfl4.length} sensitive paths (all levels)`)
    lines.push(`  @catwaf_sfl4 path ${allSfl4.join(' ')}`)
    lines.push(`  handle @catwaf_sfl4 {`)
    lines.push(`    respond "You have been blocked by CatWAF" 403`)
    lines.push(`  }`)
  }

  if (blocked.length > 0 && sfl_level === 0) {
    lines.push(`  # Manual blocks only (SFL off)`)
    lines.push(`  @catwaf_manual path ${blocked.join(' ')}`)
    lines.push(`  handle @catwaf_manual {`)
    lines.push(`    respond "You have been blocked by CatWAF" 403`)
    lines.push(`  }`)
  }

  lines.push('')
  lines.push(MARKER_END)
  return lines.join('\n')
}

function patchCaddyfile(state) {
  let content = caddy.readCaddyfile()
  const newBlock = buildSensitiveBlock(state)

  const hasMarkers = content.includes(MARKER_START)

  if (hasMarkers) {
    const startIdx = content.indexOf(MARKER_START)
    const endIdx   = content.indexOf(MARKER_END)
    if (endIdx === -1) throw new Error('Caddyfile has START marker but no END marker — fix manually')
    const before = content.slice(0, startIdx)
    const after  = content.slice(endIdx + MARKER_END.length)
    content = newBlock ? before + newBlock + after : before.trimEnd() + '\n' + after.trimStart()
  } else if (newBlock) {
    const lastBrace = content.lastIndexOf('}')
    if (lastBrace === -1) throw new Error('Caddyfile has no closing brace — cannot inject rules')
    content = content.slice(0, lastBrace) + '\n' + newBlock + '\n' + content.slice(lastBrace)
  }

  fs.writeFileSync(caddy.CADDYFILE_PATH, content, 'utf8')
}


function applyToCoraza(state, label, req) {
  let caddyResult = { reloaded: false, error: 'skipped' }
  try {
    patchCaddyfile(state)
    caddyResult = caddy.reloadCaddy()
    auditSvc.audit(req, label, `SFL${state.sfl_level}`, { reloaded: caddyResult.reloaded, blocks: state.blocked.length })
  } catch (e) {
    caddyResult = { reloaded: false, error: e.message }
    auditSvc.audit(req, label + '.error', e.message)
  }
  return caddyResult
}

module.exports = {
  MARKER_START, MARKER_END, WORDLIST_DIR,
  getSensitiveState, saveSensitiveState,
  buildSensitiveBlock, patchCaddyfile, applyToCoraza,
  cumulativeSflPaths,
}
