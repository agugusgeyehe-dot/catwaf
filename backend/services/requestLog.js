
const fs = require('fs')
const crypto = require('crypto')
const db = require('./db')
const caddySvc = require('./caddy')
const geoip = require('./geoip')

const now = () => new Date().toISOString()
const rid = (n = 8) => crypto.randomBytes(n).toString('hex')

const RULE_ID_CATEGORY = [
  [913000, 913999, 'Scanner Detection'],
  [930000, 930999, 'LFI'],
  [931000, 931999, 'RFI'],
  [932000, 932999, 'RCE'],
  [933000, 933999, 'PHP Injection'],
  [934000, 934999, 'Generic Attack'],
  [941000, 941999, 'XSS'],
  [942000, 942999, 'SQLi'],
  [943000, 943999, 'Session Fixation'],
  [944000, 944999, 'Java Attack'],
  [921000, 921999, 'Protocol Attack'],
  [911000, 911999, 'Method Enforcement'],
  [920000, 920999, null],
]
function categoryOfRuleId(id) {
  const n = parseInt(id, 10)
  if (!Number.isFinite(n)) return null
  for (const [lo, hi, label] of RULE_ID_CATEGORY) {
    if (n >= lo && n <= hi) return label
  }
  return null
}

function classifyRuleIds(ruleIds) {
  const counts = new Map()
  for (const id of ruleIds) {
    const label = categoryOfRuleId(id)
    if (!label) continue
    counts.set(label, (counts.get(label) || 0) + 1)
  }
  if (!counts.size) return null
  let best = null
  let bestCount = -1
  for (const [label, n] of counts) {
    if (n > bestCount) { best = label; bestCount = n }
  }
  return best
}

const SEVERITY_RANK = { emergency: 0, alert: 1, critical: 2, error: 3, warning: 4, notice: 5, info: 6, debug: 7 }

function bracketField(text, key) {
  const m = new RegExp(`\\[${key} "((?:[^"\\\\]|\\\\.)*)"\\]`).exec(text || '')
  return m ? m[1] : null
}

function headerValue(headers, name) {
  if (!headers || typeof headers !== 'object') return null
  const key = Object.keys(headers).find(k => k.toLowerCase() === name)
  if (!key) return null
  const v = headers[key]
  return Array.isArray(v) ? (v[0] ?? null) : (typeof v === 'string' ? v : null)
}

function corazaTimestampToIso(tx) {
  const nanos = tx.unix_timestamp
  if (typeof nanos === 'number' && Number.isFinite(nanos) && nanos > 0) {
    return new Date(Math.floor(nanos / 1e6)).toISOString()
  }
  const raw = tx.timestamp || tx.time_stamp
  if (typeof raw === 'string') {
    const m = /^(\d{4})\/(\d{2})\/(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/.exec(raw.trim())
    if (m) {
      const [, y, mo, d, h, mi, s] = m
      const dt = new Date(`${y}-${mo}-${d}T${h}:${mi}:${s}Z`)
      if (!Number.isNaN(dt.getTime())) return dt.toISOString()
    }
    const direct = new Date(raw)
    if (!Number.isNaN(direct.getTime())) return direct.toISOString()
  }
  return now()
}

function parseAuditEntry(raw) {
  let obj
  try { obj = JSON.parse(raw) } catch { return null }
  const tx = obj.transaction || obj.Tx || obj
  if (!tx) return null

  const messages = obj.messages || tx.messages || []
  const texts = messages.map(m => m?.error_message || m?.message || '').filter(Boolean)

  const ruleIds = [...new Set(
    texts.map(t => bracketField(t, 'id')).filter(Boolean).map(String)
  )]

  let severity = null
  let severityRank = Infinity
  for (const t of texts) {
    const s = (bracketField(t, 'severity') || '').toLowerCase()
    if (s && s in SEVERITY_RANK && SEVERITY_RANK[s] < severityRank) {
      severityRank = SEVERITY_RANK[s]
      severity = s
    }
  }

  let score = null
  for (const t of texts) {
    const m = /Total Score:\s*(\d+)/i.exec(t)
    if (m) { score = parseInt(m[1], 10); break }
  }

  const blocked = tx.is_interrupted === true
    || !!(tx.interruption || tx.Interruption)

  let reason = null
  for (const t of texts) {
    const s = (bracketField(t, 'severity') || '').toLowerCase()
    if (s && SEVERITY_RANK[s] === severityRank) {
      reason = bracketField(t, 'msg')
      if (reason) break
    }
  }
  if (!reason && texts.length) reason = bracketField(texts[0], 'msg')

  let matchedVar = null
  for (const t of texts) {
    const data = bracketField(t, 'data')
    if (!data) continue
    const m = /found within ([A-Z_]+(?::[A-Za-z0-9_.\-]{1,64})?)/.exec(data)
    if (m) { matchedVar = m[1]; break }
  }

  const rawStatus = tx.response?.status ?? tx.Response?.status ?? null
  const status = (rawStatus && rawStatus > 0) ? rawStatus : (blocked ? 403 : null)
  const ip = tx.client_ip || tx.clientIp || null
  const geo = geoip.lookup(ip)

  return {
    id: rid(6),
    ts: corazaTimestampToIso(tx),
    ip,
    method: tx.request?.method || tx.Request?.method || null,
    uri: tx.request?.uri || tx.Request?.uri || null,
    status,
    action: blocked ? 'block' : 'pass',
    attack_type: classifyRuleIds(ruleIds),
    rule_ids: JSON.stringify(ruleIds),
    score,
    user_agent: headerValue(tx.request?.headers || tx.Request?.headers, 'user-agent'),
    severity,
    reason,
    matched_var: matchedVar,
    country_code: geo?.country_code || null,
    city: geo?.city || null,
    lat: geo?.lat ?? null,
    lon: geo?.lon ?? null,
  }
}

function insertRow(row) {
  const conn = db.getDb()
  conn.prepare(`
    INSERT OR IGNORE INTO request_log (id, ts, ip, method, uri, status, action, attack_type, rule_ids, score, user_agent, severity, reason, matched_var, country_code, city, lat, lon)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(row.id, row.ts, row.ip, row.method, row.uri, row.status, row.action, row.attack_type, row.rule_ids, row.score, row.user_agent, row.severity, row.reason, row.matched_var, row.country_code, row.city, row.lat, row.lon)
}

let lastReadOffset = 0

function ingestNewEntries() {
  let stat
  try { stat = fs.statSync(caddySvc.AUDIT_LOG_PATH) } catch { return { ingested: 0, reason: 'audit log not found (Coraza not running or SecAuditEngine off)' } }

  if (stat.size < lastReadOffset) lastReadOffset = 0
  if (stat.size === lastReadOffset) return { ingested: 0 }

  const fd = fs.openSync(caddySvc.AUDIT_LOG_PATH, 'r')
  const length = stat.size - lastReadOffset
  const buf = Buffer.alloc(length)
  fs.readSync(fd, buf, 0, length, lastReadOffset)
  fs.closeSync(fd)
  lastReadOffset = stat.size

  const lines = buf.toString('utf8').split('\n').filter(Boolean)
  let ingested = 0
  for (const line of lines) {
    const row = parseAuditEntry(line)
    if (row) { insertRow(row); ingested++ }
  }
  return { ingested }
}

function getRecent(limit = 50) {
  return db.getDb().prepare('SELECT * FROM request_log ORDER BY ts DESC LIMIT ?').all(limit)
    .map(r => ({ ...r, rule_ids: JSON.parse(r.rule_ids || '[]') }))
}

function getCounts(sinceMs = 24 * 60 * 60 * 1000) {
  const since = new Date(Date.now() - sinceMs).toISOString()
  const conn = db.getDb()
  const total = conn.prepare('SELECT COUNT(*) AS n FROM request_log WHERE ts >= ?').get(since).n
  const blocked = conn.prepare("SELECT COUNT(*) AS n FROM request_log WHERE ts >= ? AND action = 'block'").get(since).n
  return { total, blocked, allowed: total - blocked }
}

function getAttackTypeCounts(sinceMs = 24 * 60 * 60 * 1000) {
  const since = new Date(Date.now() - sinceMs).toISOString()
  const rows = db.getDb().prepare(`
    SELECT attack_type, COUNT(*) AS n FROM request_log
    WHERE ts >= ? AND action = 'block' AND attack_type IS NOT NULL
    GROUP BY attack_type
  `).all(since)
  return Object.fromEntries(rows.map(r => [r.attack_type, r.n]))
}

function getById(id) {
  const row = db.getDb().prepare('SELECT * FROM request_log WHERE id = ?').get(String(id))
  return row ? { ...row, rule_ids: JSON.parse(row.rule_ids || '[]') } : null
}

function getLatest({ blockedOnly = false } = {}) {
  const sql = blockedOnly
    ? "SELECT * FROM request_log WHERE action = 'block' ORDER BY ts DESC LIMIT 1"
    : 'SELECT * FROM request_log ORDER BY ts DESC LIMIT 1'
  const row = db.getDb().prepare(sql).get()
  return row ? { ...row, rule_ids: JSON.parse(row.rule_ids || '[]') } : null
}

const WINDOW_RE = /^(\d+)\s*([smhdw])$/i
const WINDOW_MS = { s: 1000, m: 60000, h: 3600000, d: 86400000, w: 604800000 }

function parseWindow(spec, fallbackMs = 24 * 3600000) {
  if (spec == null || spec === '') return fallbackMs
  if (typeof spec === 'number' && Number.isFinite(spec)) return spec
  const m = WINDOW_RE.exec(String(spec).trim())
  if (!m) return null
  const n = Number(m[1])
  if (!Number.isFinite(n) || n <= 0 || n > 100000) return null
  return n * WINDOW_MS[m[2].toLowerCase()]
}

function query({ sinceMs = 24 * 3600000, attackType = null, severity = null, action = null, limit = 100, offset = 0 } = {}) {
  const since = new Date(Date.now() - sinceMs).toISOString()
  const where = ['ts >= ?']
  const params = [since]
  if (attackType) { where.push('attack_type = ?'); params.push(String(attackType)) }
  if (severity) { where.push('severity = ?'); params.push(String(severity).toLowerCase()) }
  if (action) { where.push('action = ?'); params.push(String(action)) }
  const sql = `SELECT * FROM request_log WHERE ${where.join(' AND ')} ORDER BY ts DESC LIMIT ? OFFSET ?`
  return db.getDb().prepare(sql).all(...params, Math.min(Number(limit) || 100, 1000), Math.max(Number(offset) || 0, 0))
    .map(r => ({ ...r, rule_ids: JSON.parse(r.rule_ids || '[]') }))
}

function summarize({ sinceMs = 24 * 3600000, attackType = null, severity = null } = {}) {
  const since = new Date(Date.now() - sinceMs).toISOString()
  const conn = db.getDb()
  const where = ['ts >= ?']
  const params = [since]
  if (attackType) { where.push('attack_type = ?'); params.push(String(attackType)) }
  if (severity) { where.push('severity = ?'); params.push(String(severity).toLowerCase()) }
  const clause = where.join(' AND ')

  const total = conn.prepare(`SELECT COUNT(*) AS n FROM request_log WHERE ${clause}`).get(...params).n
  const blocked = conn.prepare(`SELECT COUNT(*) AS n FROM request_log WHERE ${clause} AND action = 'block'`).get(...params).n
  const allowed = total - blocked

  const byAttack = conn.prepare(
    `SELECT attack_type AS k, COUNT(*) AS n FROM request_log WHERE ${clause} AND action = 'block' AND attack_type IS NOT NULL GROUP BY attack_type ORDER BY n DESC`
  ).all(...params)

  const bySeverity = conn.prepare(
    `SELECT severity AS k, COUNT(*) AS n FROM request_log WHERE ${clause} AND severity IS NOT NULL GROUP BY severity ORDER BY n DESC`
  ).all(...params)

  const scoreRow = conn.prepare(
    `SELECT AVG(score) AS avg, MAX(score) AS max, MIN(score) AS min, COUNT(score) AS n FROM request_log WHERE ${clause} AND score IS NOT NULL`
  ).get(...params)

  const topIps = conn.prepare(
    `SELECT ip AS k, COUNT(*) AS n FROM request_log WHERE ${clause} AND action = 'block' AND ip IS NOT NULL GROUP BY ip ORDER BY n DESC LIMIT 10`
  ).all(...params)

  const ruleRows = conn.prepare(
    `SELECT rule_ids FROM request_log WHERE ${clause} AND action = 'block' AND rule_ids IS NOT NULL LIMIT 5000`
  ).all(...params)
  const ruleCounts = new Map()
  for (const r of ruleRows) {
    let ids = []
    try { ids = JSON.parse(r.rule_ids || '[]') } catch { continue }
    for (const id of ids) ruleCounts.set(String(id), (ruleCounts.get(String(id)) || 0) + 1)
  }
  const topRules = [...ruleCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([id, n]) => ({ rule_id: id, count: n }))

  return {
    window_ms: sinceMs,
    since,
    until: new Date().toISOString(),
    total_requests: total,
    blocked_requests: blocked,
    allowed_requests: allowed,
    block_rate: total > 0 ? Number((blocked / total).toFixed(4)) : 0,
    top_attack_types: byAttack.map(r => ({ attack_type: r.k, count: r.n })),
    severity_distribution: bySeverity.map(r => ({ severity: r.k, count: r.n })),
    top_rules: topRules,
    top_source_ips: topIps.map(r => ({ ip: r.k, count: r.n })),
    anomaly_score: {
      average: scoreRow.avg != null ? Number(Number(scoreRow.avg).toFixed(2)) : null,
      max: scoreRow.max ?? null,
      min: scoreRow.min ?? null,
      scored_events: scoreRow.n || 0,
    },
  }
}

function getAttackMapPoints({ sinceMs = 24 * 3600000, limit = 500 } = {}) {
  const since = new Date(Date.now() - sinceMs).toISOString()
  const rows = db.getDb().prepare(`
    SELECT ip, country_code, city, lat, lon, attack_type, severity, action, ts
    FROM request_log
    WHERE ts >= ? AND action = 'block' AND lat IS NOT NULL AND lon IS NOT NULL
    ORDER BY ts DESC
    LIMIT ?
  `).all(since, Math.min(Number(limit) || 500, 2000))

  const clusters = new Map()
  for (const r of rows) {
    const key = `${r.lat.toFixed(1)},${r.lon.toFixed(1)}`
    let c = clusters.get(key)
    if (!c) {
      c = { lat: r.lat, lon: r.lon, country_code: r.country_code, city: r.city, count: 0, attack_types: {}, last_seen: r.ts, max_severity: null }
      clusters.set(key, c)
    }
    c.count++
    if (r.attack_type) c.attack_types[r.attack_type] = (c.attack_types[r.attack_type] || 0) + 1
    if (r.ts > c.last_seen) c.last_seen = r.ts
    const rank = SEVERITY_RANK[r.severity] ?? Infinity
    const curRank = c.max_severity ? SEVERITY_RANK[c.max_severity] : Infinity
    if (rank < curRank) c.max_severity = r.severity
  }
  return [...clusters.values()].sort((a, b) => b.count - a.count)
}

function hasAnyData() {
  return db.getDb().prepare('SELECT COUNT(*) AS n FROM request_log').get().n > 0
}

function purgeOldEntries(retentionDays) {
  if (!retentionDays || retentionDays <= 0) return { deleted: 0 }
  const cutoff = new Date(Date.now() - retentionDays * 86400000).toISOString()
  const info = db.getDb().prepare('DELETE FROM request_log WHERE ts < ?').run(cutoff)
  return { deleted: info.changes }
}

module.exports = {
  parseAuditEntry, ingestNewEntries, getRecent, getCounts, getAttackTypeCounts, hasAnyData,
  purgeOldEntries, getById, getLatest, query, summarize, parseWindow, getAttackMapPoints,
  classifyRuleIds, categoryOfRuleId,
  _resetOffsetForTests: () => { lastReadOffset = 0 },
}
