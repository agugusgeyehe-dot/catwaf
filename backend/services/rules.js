const fs = require('fs')
const os = require('os')
const path = require('path')

const state = require('./state')
const db = require('./db')

const RULE_ID_RE = /^\d{3,7}$/

const CATEGORY_FOR_PREFIX = {
  '911': 'Method Enforcement',
  '913': 'Scanner Detection',
  '920': 'Protocol Enforcement',
  '921': 'Protocol Attack',
  '922': 'Multipart Attack',
  '930': 'LFI',
  '931': 'RFI',
  '932': 'RCE',
  '933': 'PHP Injection',
  '934': 'Generic Attack',
  '941': 'XSS',
  '942': 'SQLi',
  '943': 'Session Fixation',
  '944': 'Java Attack',
  '949': 'Blocking Evaluation',
  '950': 'Data Leakage',
  '951': 'SQL Data Leakage',
  '952': 'Java Data Leakage',
  '953': 'PHP Data Leakage',
  '954': 'IIS Data Leakage',
  '955': 'Web Shell Detection',
  '959': 'Blocking Evaluation',
  '980': 'Anomaly Scoring',
}

function categoryForRuleId(id) {
  const prefix = String(id).slice(0, 3)
  return CATEGORY_FOR_PREFIX[prefix] || null
}

function candidateCrsDirs() {
  const dirs = []
  if (process.env.CATWAF_CRS_PATH) dirs.push(process.env.CATWAF_CRS_PATH)

  dirs.push(
    '/etc/coraza/crs',
    '/usr/share/coraza/crs',
    '/usr/local/share/coraza/crs',
    '/etc/crs4',
    '/usr/share/modsecurity-crs/rules',
    '/opt/owasp-crs/rules',
  )

  const goRoots = [
    process.env.GOMODCACHE,
    process.env.GOPATH ? path.join(process.env.GOPATH, 'pkg', 'mod') : null,
    path.join(os.homedir(), 'go', 'pkg', 'mod'),
  ].filter(Boolean)

  const goCandidates = []
  for (const root of goRoots) {
    const base = path.join(root, 'github.com', 'corazawaf')
    let entries = []
    try { entries = fs.readdirSync(base) } catch { continue }
    for (const e of entries) {
      if (!e.startsWith('coraza-coreruleset')) continue
      const nested = [path.join(base, e)]
      try {
        for (const sub of fs.readdirSync(path.join(base, e))) {
          if (/^v\d+@/.test(sub)) nested.push(path.join(base, e, sub))
        }
      } catch {}
      for (const dir of nested) {
        for (const rel of [path.join('rules', '@owasp_crs'), 'rules']) {
          const p = path.join(dir, rel)
          try {
            if (fs.statSync(p).isDirectory()) goCandidates.push({ p, version: versionKey(dir) })
          } catch {}
        }
      }
    }
  }
  goCandidates.sort((a, b) => b.version.localeCompare(a.version, undefined, { numeric: true }))
  dirs.push(...goCandidates.map(c => c.p))

  return [...new Set(dirs)]
}

function versionKey(dir) {
  const m = /@v?([0-9][^/\\]*)$/.exec(dir)
  if (!m) return '0'
  const v = m[1]
  if (/^0\.0\.0-/.test(v)) return '0'
  return v
}

function parseConfFile(body, sourceFile) {
  const rules = []
  const joined = body.replace(/\\\s*\r?\n\s*/g, ' ')
  for (const line of joined.split('\n')) {
    if (!/\bid:\d/.test(line)) continue
    if (!/^\s*(SecRule|SecAction)\b/.test(line)) continue

    const idm = /\bid:(\d{3,7})\b/.exec(line)
    if (!idm) continue

    const msg = /\bmsg:'((?:[^'\\]|\\.)*)'/.exec(line)
    const sev = /\bseverity:'?([A-Za-z]+)'?/.exec(line)
    const ver = /\bver:'([^']*)'/.exec(line)
    const phase = /\bphase:(\d)/.exec(line)
    const plTag = /paranoia-level\/(\d)/.exec(line)
    const tags = [...line.matchAll(/\btag:'([^']*)'/g)].map(m => m[1])
    const targetMatch = /^\s*SecRule\s+([^\s"]+)/.exec(line)

    rules.push({
      id: idm[1],
      msg: msg ? msg[1] : null,
      severity: sev ? sev[1].toLowerCase() : null,
      version: ver ? ver[1] : null,
      phase: phase ? Number(phase[1]) : null,
      paranoia_level: plTag ? Number(plTag[1]) : null,
      tags,
      targets: targetMatch ? targetMatch[1] : null,
      file: sourceFile,
      category: categoryForRuleId(idm[1]),
      source: 'crs',
    })
  }
  return rules
}

let INDEX = null

function buildIndex() {
  const byId = new Map()
  const sources = []

  for (const dir of candidateCrsDirs()) {
    let files = []
    try { files = fs.readdirSync(dir).filter(f => f.endsWith('.conf')) } catch { continue }
    if (!files.length) continue
    let added = 0
    for (const f of files.sort()) {
      let body
      try { body = fs.readFileSync(path.join(dir, f), 'utf8') } catch { continue }
      for (const r of parseConfFile(body, f)) {
        if (!byId.has(r.id)) { byId.set(r.id, r); added++ }
      }
    }
    if (added) sources.push({ dir, files: files.length, rules: added })
    if (byId.size) break
  }

  let harvested = 0
  try {
    const rows = db.getDb().prepare(
      'SELECT rule_ids, attack_type, severity, reason FROM request_log WHERE rule_ids IS NOT NULL LIMIT 2000'
    ).all()
    for (const row of rows) {
      let ids = []
      try { ids = JSON.parse(row.rule_ids || '[]') } catch { continue }
      for (const id of ids) {
        const key = String(id)
        if (byId.has(key)) continue
        byId.set(key, {
          id: key,
          msg: row.reason || null,
          severity: row.severity || null,
          version: null,
          phase: null,
          paranoia_level: null,
          tags: [],
          targets: null,
          file: null,
          category: categoryForRuleId(key) || row.attack_type || null,
          source: 'observed',
        })
        harvested++
      }
    }
  } catch {}

  INDEX = {
    byId,
    sources,
    harvested,
    builtAt: new Date().toISOString(),
    available: byId.size > 0,
  }
  return INDEX
}

function getIndex({ refresh = false } = {}) {
  if (!INDEX || refresh) buildIndex()
  return INDEX
}

function isValidRuleId(id) {
  return typeof id === 'string' ? RULE_ID_RE.test(id) : Number.isInteger(id) && RULE_ID_RE.test(String(id))
}

function disabledRuleIds() {
  return Array.isArray(state.WAF.disabled_rules) ? state.WAF.disabled_rules.map(String) : []
}

function isRuleDisabled(id) {
  const sid = String(id)
  if (disabledRuleIds().includes(sid)) return { disabled: true, by: 'rule' }
  const prefix = sid.slice(0, 3)
  const cat = state.RULE_CATEGORIES[prefix]
  if (cat && cat.enabled === false) return { disabled: true, by: 'category', category: cat.name }
  return { disabled: false, by: null }
}

function describe(id) {
  const sid = String(id)
  const idx = getIndex()
  const meta = idx.byId.get(sid) || null
  const status = isRuleDisabled(sid)
  return {
    id: sid,
    known: !!meta,
    description: meta?.msg || null,
    severity: meta?.severity || null,
    category: meta?.category || categoryForRuleId(sid),
    paranoia_level: meta?.paranoia_level ?? null,
    phase: meta?.phase ?? null,
    targets: meta?.targets || null,
    tags: meta?.tags || [],
    version: meta?.version || null,
    file: meta?.file || null,
    metadata_source: meta?.source || null,
    enabled: !status.disabled,
    disabled_by: status.by,
    disabled_category: status.category || null,
  }
}

function list({ category = null, enabled = null, limit = 200, offset = 0 } = {}) {
  const idx = getIndex()
  let all = [...idx.byId.keys()].sort((a, b) => Number(a) - Number(b)).map(describe)
  if (category) {
    const c = String(category).toLowerCase()
    all = all.filter(r => (r.category || '').toLowerCase().includes(c) || String(r.id).startsWith(c))
  }
  if (enabled === true) all = all.filter(r => r.enabled)
  if (enabled === false) all = all.filter(r => !r.enabled)
  return { total: all.length, rules: all.slice(offset, offset + limit), indexAvailable: idx.available }
}

function search(query, { limit = 50 } = {}) {
  const q = String(query || '').trim().toLowerCase()
  if (!q) return { total: 0, rules: [], indexAvailable: getIndex().available }
  const idx = getIndex()
  const scored = []
  for (const [id, meta] of idx.byId) {
    let score = 0
    if (id === q) score += 100
    else if (id.startsWith(q)) score += 40
    const msg = (meta.msg || '').toLowerCase()
    if (msg.includes(q)) score += 30
    const cat = (meta.category || '').toLowerCase()
    if (cat.includes(q)) score += 20
    if ((meta.tags || []).some(t => t.toLowerCase().includes(q))) score += 10
    if (score > 0) scored.push({ score, id })
  }
  scored.sort((a, b) => b.score - a.score || Number(a.id) - Number(b.id))
  return {
    total: scored.length,
    rules: scored.slice(0, limit).map(s => describe(s.id)),
    indexAvailable: idx.available,
  }
}

function validateRuleIdOrThrow(id) {
  if (!isValidRuleId(id)) {
    throw new Error(`"${id}" is not a valid CRS rule ID (expected 3-7 digits).`)
  }
  return String(id)
}

function setRuleEnabled(id, enabled) {
  const sid = validateRuleIdOrThrow(id)
  const current = disabledRuleIds()
  const isCurrentlyDisabled = current.includes(sid)

  if (enabled && !isCurrentlyDisabled) {
    const status = isRuleDisabled(sid)
    if (status.by === 'category') {
      return { changed: false, reason: `Rule ${sid} is disabled by its category "${status.category}", not individually. Enable the category instead.` }
    }
    return { changed: false, reason: `Rule ${sid} is already enabled.` }
  }
  if (!enabled && isCurrentlyDisabled) {
    return { changed: false, reason: `Rule ${sid} is already disabled.` }
  }

  const next = enabled ? current.filter(x => x !== sid) : [...current, sid].sort((a, b) => Number(a) - Number(b))
  state.WAF.disabled_rules = next
  return { changed: true, id: sid, enabled, disabled_rules: next }
}

function stats() {
  const idx = getIndex()
  const disabled = disabledRuleIds()
  const byCategory = {}
  for (const meta of idx.byId.values()) {
    const c = meta.category || 'Uncategorized'
    byCategory[c] = (byCategory[c] || 0) + 1
  }
  const disabledCategories = Object.entries(state.RULE_CATEGORIES)
    .filter(([, v]) => v.enabled === false)
    .map(([k, v]) => ({ prefix: k, name: v.name }))
  return {
    indexed: idx.byId.size,
    indexAvailable: idx.available,
    sources: idx.sources,
    observedOnly: idx.harvested,
    disabledRules: disabled,
    disabledCategories,
    byCategory,
  }
}

let _crsVersionCache
function crsVersion() {
  if (_crsVersionCache !== undefined) return _crsVersionCache
  try {
    const dirs = candidateCrsDirs()
    const versions = dirs
      .map(versionKey)
      .filter(v => v !== '0' && /^\d/.test(v))
      .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
    _crsVersionCache = versions[0] || null
  } catch { _crsVersionCache = null }
  return _crsVersionCache
}

module.exports = {
  getIndex, buildIndex, describe, list, search, stats,
  isValidRuleId, validateRuleIdOrThrow, isRuleDisabled, disabledRuleIds,
  setRuleEnabled, categoryForRuleId, parseConfFile, candidateCrsDirs,
  crsVersion,
}
