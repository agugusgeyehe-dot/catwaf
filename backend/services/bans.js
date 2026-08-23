// bans.js — one place that knows every address CatWAF is currently refusing,
// and why (idea #61).
//
// Before this existed the IP blocklist was the only answer, and it was
// entirely manual. Now several independent features can decide to stop an
// address — behavioural banning (#6), DNSBL hits (#11), a local threat feed
// (#13), the shared network (#12), a failed challenge (#1), relay detection
// (#5), community lists (#10). Without a shared view, "why is this visitor
// blocked and how do I let them back in" would have a different answer per
// feature, which is exactly the question false-positives.md exists to answer.
//
// The manual `ip_blacklist` in state.WAF stays what it is — a permanent,
// operator-curated list rendered into Coraza. This store holds the
// *temporary, automatic* bans, which is why it lives in SQLite with an
// expiry rather than in the generated config.

const crypto = require('crypto')
const db = require('./db')
const settings = require('./settings')
const { ipCoveredBy, normalizeClientIp, isValidIpOrCidr } = require('./sanitize')

const SOURCES = {
  manual: 'Added by an administrator',
  bad_behavior: 'Too many error responses in a short window',
  rate_limit: 'Exceeded the request rate limit',
  challenge: 'Failed the challenge gate too many times',
  dnsbl: 'Listed on a DNS blackhole list',
  community: 'Present on a subscribed community blocklist',
  threat_feed: 'Flagged by the local threat-detection daemon',
  threat_network: 'Reported by the shared threat network',
  client_probe: 'Detected as an open proxy or relay',
  asn: 'Origin network is on the ASN blocklist',
  rdns: 'Reverse DNS matches a blocked suffix',
  tools_fingerprint: 'Matched a known scanner tool fingerprint (User-Agent + header shape)',
  upload_malware: 'Uploaded a file the malware scanner rejected',
}

const now = () => new Date().toISOString()

function conn() { return db.getDb() }

function rowToBan(row) {
  if (!row) return null
  let meta = {}
  try { meta = row.meta ? JSON.parse(row.meta) : {} } catch { meta = {} }
  return {
    id: row.id,
    target: row.target,
    source: row.source,
    source_label: SOURCES[row.source] || row.source,
    reason: row.reason || SOURCES[row.source] || '',
    rule_id: row.rule_id || null,
    created_at: row.created_at,
    expires_at: row.expires_at,
    permanent: !row.expires_at,
    hits: row.hits,
    meta,
  }
}

function historyFor(target) {
  const row = conn().prepare('SELECT * FROM ban_history WHERE target = ?').get(target)
  return row ? { count: row.count, last_ban: row.last_ban, last_source: row.last_source } : { count: 0, last_ban: null, last_source: null }
}

// Repeat offenders get progressively longer bans, capped, so a persistent
// scanner is not re-banned for the same short window forever.
function escalate(target, seconds) {
  const cfg = settings.get('bad_behavior')
  if (!cfg.escalate) return seconds
  const { count } = historyFor(target)
  if (count <= 0) return seconds
  const escalated = seconds * Math.pow(2, Math.min(count, 10))
  return Math.min(escalated, cfg.max_ban_seconds)
}

function ban({ target, source = 'manual', reason = '', seconds = null, ruleId = null, meta = {}, escalateRepeat = true }) {
  const clean = normalizeClientIp(String(target || '').trim())
  if (!isValidIpOrCidr(clean)) return { ok: false, error: `"${target}" is not a valid IP address or CIDR range` }
  if (!Object.hasOwn(SOURCES, source)) return { ok: false, error: `Unknown ban source "${source}"` }

  // A range ban is served from cidrCache rather than an index lookup, so any
  // write touching one has to drop that cache — otherwise the ban is not
  // enforced until the cache happens to expire, which is up to five seconds
  // of an address CatWAF has just decided to refuse still getting through.
  const isRange = clean.includes('/')

  const existing = conn().prepare('SELECT * FROM active_bans WHERE target = ? AND source = ?').get(clean, source)
  const duration = seconds == null ? null : Math.max(1, Math.trunc(escalateRepeat ? escalate(clean, seconds) : seconds))
  const expiresAt = duration == null ? null : new Date(Date.now() + duration * 1000).toISOString()

  if (existing) {
    // Extend rather than duplicate: the same source re-reporting an address
    // should push the expiry out, not create a second row the operator then
    // has to lift twice.
    const keepLonger = !expiresAt || (existing.expires_at && new Date(existing.expires_at) > new Date(expiresAt))
    conn().prepare('UPDATE active_bans SET hits = hits + 1, reason = ?, expires_at = ?, meta = ? WHERE id = ?')
      .run(reason || existing.reason, keepLonger ? existing.expires_at : expiresAt, JSON.stringify(meta), existing.id)
    if (isRange) invalidateCache()
    return { ok: true, extended: true, ban: get(existing.id) }
  }

  const id = 'b_' + crypto.randomBytes(6).toString('hex')
  conn().prepare(`
    INSERT INTO active_bans (id, target, source, reason, rule_id, created_at, expires_at, hits, meta)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
  `).run(id, clean, source, reason || SOURCES[source], ruleId, now(), expiresAt, JSON.stringify(meta))

  conn().prepare(`
    INSERT INTO ban_history (target, count, last_ban, last_source) VALUES (?, 1, ?, ?)
    ON CONFLICT(target) DO UPDATE SET count = count + 1, last_ban = excluded.last_ban, last_source = excluded.last_source
  `).run(clean, now(), source)

  if (isRange) invalidateCache()
  return { ok: true, created: true, ban: get(id), duration_sec: duration }
}

function get(id) {
  return rowToBan(conn().prepare('SELECT * FROM active_bans WHERE id = ?').get(id))
}

function lift(id, { by = 'system' } = {}) {
  const existing = get(id)
  if (!existing) return { ok: false, error: 'No such ban' }
  conn().prepare('DELETE FROM active_bans WHERE id = ?').run(id)
  if (existing.target.includes('/')) invalidateCache()
  return { ok: true, lifted: existing, by }
}

function liftTarget(target, { source = null } = {}) {
  const clean = normalizeClientIp(String(target || '').trim())
  const rows = source
    ? conn().prepare('DELETE FROM active_bans WHERE target = ? AND source = ? RETURNING id').all(clean, source)
    : conn().prepare('DELETE FROM active_bans WHERE target = ? RETURNING id').all(clean)
  if (rows.length && clean.includes('/')) invalidateCache()
  return { ok: true, removed: rows.length }
}

// The hot path: called for every request when any automatic ban source is
// enabled. Exact matches are answered by an index; CIDR bans need a scan, so
// they are kept separate and only walked when there are any.
let cidrCache = { at: 0, rows: [] }

function cidrBans() {
  if (Date.now() - cidrCache.at < 5000) return cidrCache.rows
  cidrCache = {
    at: Date.now(),
    rows: conn().prepare("SELECT * FROM active_bans WHERE target LIKE '%/%'").all(),
  }
  return cidrCache.rows
}

function invalidateCache() { cidrCache = { at: 0, rows: [] } }

function check(ip) {
  const clean = normalizeClientIp(String(ip || '').trim())
  if (!clean) return null
  const nowIso = now()

  const exact = conn().prepare(
    'SELECT * FROM active_bans WHERE target = ? AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC LIMIT 1'
  ).get(clean, nowIso)
  if (exact) return rowToBan(exact)

  for (const row of cidrBans()) {
    if (row.expires_at && row.expires_at <= nowIso) continue
    if (ipCoveredBy(clean, row.target)) return rowToBan(row)
  }
  return null
}

function list({ source = null, limit = 200, offset = 0, includeExpired = false } = {}) {
  const clauses = []
  const params = []
  if (!includeExpired) { clauses.push('(expires_at IS NULL OR expires_at > ?)'); params.push(now()) }
  if (source) { clauses.push('source = ?'); params.push(source) }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : ''
  const rows = conn().prepare(`SELECT * FROM active_bans ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
    .all(...params, Math.min(limit, 1000), offset)
  return rows.map(rowToBan)
}

function purgeExpired() {
  const removed = conn().prepare('DELETE FROM active_bans WHERE expires_at IS NOT NULL AND expires_at <= ? RETURNING id').all(now())
  if (removed.length) invalidateCache()
  return { removed: removed.length, changed: removed.length > 0 }
}

function stats() {
  const bySource = conn().prepare(`
    SELECT source, COUNT(*) AS n FROM active_bans
    WHERE expires_at IS NULL OR expires_at > ? GROUP BY source ORDER BY n DESC
  `).all(now())
  const total = bySource.reduce((sum, r) => sum + r.n, 0)
  const permanent = conn().prepare('SELECT COUNT(*) AS n FROM active_bans WHERE expires_at IS NULL').get().n
  const soonest = conn().prepare('SELECT MIN(expires_at) AS e FROM active_bans WHERE expires_at IS NOT NULL AND expires_at > ?').get(now()).e
  return {
    total,
    permanent,
    temporary: total - permanent,
    next_expiry: soonest || null,
    by_source: bySource.map(r => ({ source: r.source, label: SOURCES[r.source] || r.source, count: r.n })),
    sources: Object.entries(SOURCES).map(([id, label]) => ({ id, label })),
  }
}

function clearAll() {
  conn().exec('DELETE FROM active_bans')
  invalidateCache()
  return { ok: true }
}

module.exports = {
  SOURCES, ban, get, lift, liftTarget, check, list, purgeExpired, stats,
  historyFor, clearAll, invalidateCache,
}
