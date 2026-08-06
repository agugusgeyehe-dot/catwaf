// intel/lists.js — the greylist tier (idea #9) and subscribed community
// blocklists (idea #10).
//
// Greylisting is the missing middle of CatWAF's allow/block pair. Today an
// allowlist entry exempts a client from *everything*, which is the wrong
// answer for a bursty-but-legitimate client such as a payment webhook or a
// monitoring probe: you want it exempt from rate limiting and the challenge
// gate, but you emphatically still want Coraza inspecting it. A greylist hit
// therefore sets skip flags for named checks and never touches WAF
// evaluation.
//
// Community lists are the other half: instead of a solo site owner having to
// know what to block, a maintained feed is merged in on a schedule, tagged
// with its source so it stays separable from anything entered by hand.

const db = require('./../db')
const settings = require('../settings')
const netGuard = require('../netGuard')
const { ipCoveredBy, isValidIpOrCidr, normalizeClientIp } = require('../sanitize')

const now = () => new Date().toISOString()

function conn() { return db.getDb() }

// ─── Greylist (#9) ──────────────────────────────────────────────────────

function matchesUserAgent(ua, patterns) {
  if (!ua) return false
  const lower = String(ua).toLowerCase()
  return patterns.some(p => lower.includes(String(p).toLowerCase()))
}

function matchesUri(uri, patterns) {
  if (!uri) return false
  return patterns.some(p => {
    const pattern = String(p)
    if (pattern.endsWith('*')) return uri.startsWith(pattern.slice(0, -1))
    return uri === pattern
  })
}

// Returns null, or { skip: Set<string>, matched: '<what>' }. `skip` is what
// the enforcement pipeline consults; WAF inspection is never in it.
function greylistMatch({ ip, asn, rdns, userAgent, uri }) {
  const cfg = settings.get('greylist')
  if (!cfg.enabled) return null

  const skip = new Set(cfg.skip_checks.filter(c => c !== 'waf'))
  const clean = normalizeClientIp(String(ip || ''))

  for (const entry of cfg.ips) {
    if (ipCoveredBy(clean, entry)) return { skip, matched: `IP ${entry}` }
  }
  if (asn && cfg.asns.includes(asn)) return { skip, matched: `ASN ${asn}` }
  if (rdns) {
    for (const suffix of cfg.rdns_suffixes) {
      const bare = suffix.replace(/^\./, '')
      if (rdns === bare || rdns.endsWith(`.${bare}`)) return { skip, matched: `reverse DNS ${suffix}` }
    }
  }
  if (matchesUserAgent(userAgent, cfg.user_agents)) return { skip, matched: 'user agent' }
  if (matchesUri(uri, cfg.uris)) return { skip, matched: 'URI' }

  return checkSubscribed('greylist', { ip: clean, asn, rdns, userAgent, uri })
    ? { skip, matched: 'community greylist' }
    : null
}

// ─── Community lists (#10) ──────────────────────────────────────────────

const PARSERS = {
  // One entry per line; `#` and `;` start a comment. Many published feeds
  // append a comment after the value, so only the first token is taken.
  ip: line => {
    const value = line.split(/[\s,;#]/)[0]
    return isValidIpOrCidr(value) ? value : null
  },
  asn: line => {
    const m = /^(?:AS)?(\d{1,10})\b/i.exec(line.trim())
    return m ? `AS${m[1]}` : null
  },
  user_agent: line => {
    const value = line.trim()
    return value.length > 0 && value.length <= 200 ? value : null
  },
  uri: line => {
    const value = line.trim().split(/\s+/)[0]
    return value.startsWith('/') && value.length <= 512 ? value : null
  },
  rdns: line => {
    const value = line.trim().toLowerCase().split(/\s+/)[0]
    return /^\.?[a-z0-9.-]+\.[a-z]{2,}$/.test(value) ? value : null
  },
}

function parseFeed(body, kind, max) {
  const parse = PARSERS[kind]
  if (!parse) return { entries: [], rejected: 0 }
  const entries = []
  let rejected = 0
  for (const raw of String(body).split('\n')) {
    if (entries.length >= max) break
    const line = raw.trim()
    if (!line || line.startsWith('#') || line.startsWith(';') || line.startsWith('//')) continue
    const value = parse(line)
    if (value) entries.push(value)
    else rejected++
  }
  return { entries: [...new Set(entries)], rejected }
}

async function refreshSource(source, { max = 50000 } = {}) {
  if (!source || !source.enabled || !source.url) return { ok: true, skipped: 'disabled' }

  // Community feeds are operator-supplied URLs, so they go through the same
  // SSRF guard every other outbound fetch in CatWAF uses — a feed URL must
  // never become a way to make CatWAF probe its own internal network.
  const { response } = await netGuard.guardedFetch(source.url, { timeoutMs: 20000 })
  if (!response.ok) throw new Error(`${source.url} returned ${response.status}`)
  const body = await response.text()

  const { entries, rejected } = parseFeed(body, source.kind, max)
  if (!entries.length) throw new Error(`${source.url} produced no usable ${source.kind} entries`)

  const before = countFor(source.id)
  const database = conn()
  database.exec('BEGIN')
  try {
    database.prepare('DELETE FROM list_entries WHERE source_id = ?').run(source.id)
    const insert = database.prepare('INSERT OR REPLACE INTO list_entries (source_id, kind, list, value, added_at) VALUES (?,?,?,?,?)')
    const ts = now()
    for (const value of entries) insert.run(source.id, source.kind, source.list, value, ts)
    database.exec('COMMIT')
  } catch (e) {
    database.exec('ROLLBACK')
    throw e
  }

  invalidateIndex()
  return { ok: true, source: source.id, entries: entries.length, rejected, added: entries.length - before, changed: entries.length !== before }
}

async function refreshAll() {
  const cfg = settings.get('community_lists')
  if (!cfg.enabled) return { ok: true, skipped: 'disabled' }
  const results = []
  let changed = false
  for (const source of cfg.sources) {
    try {
      const r = await refreshSource(source, { max: cfg.max_entries_per_source })
      results.push({ id: source.id, name: source.name, ...r })
      if (r.changed) changed = true
    } catch (e) {
      results.push({ id: source.id, name: source.name, ok: false, error: e.message })
    }
  }
  // Entries for sources that were removed from the configuration should not
  // keep being enforced.
  const known = new Set(cfg.sources.map(s => s.id))
  const orphans = conn().prepare('SELECT DISTINCT source_id FROM list_entries').all()
    .map(r => r.source_id).filter(id => !known.has(id))
  for (const id of orphans) {
    conn().prepare('DELETE FROM list_entries WHERE source_id = ?').run(id)
    changed = true
  }
  if (changed) invalidateIndex()
  return { ok: true, sources: results.length, results, orphans_removed: orphans.length, changed }
}

function countFor(sourceId) {
  return conn().prepare('SELECT COUNT(*) AS n FROM list_entries WHERE source_id = ?').get(sourceId).n
}

// ─── Lookup index ───────────────────────────────────────────────────────
//
// Rebuilt lazily. Exact IPs go in a Set (the overwhelming majority of feed
// entries), CIDRs in an array that has to be walked — keeping them apart is
// what makes a 50k-entry feed usable on the request path.

let index = null

function invalidateIndex() { index = null }

function buildIndex() {
  const built = {}
  for (const row of conn().prepare('SELECT kind, list, value FROM list_entries').all()) {
    const bucket = built[row.list] || (built[row.list] = { ip: new Set(), cidr: [], asn: new Set(), user_agent: [], uri: [], rdns: [] })
    if (row.kind === 'ip') {
      if (row.value.includes('/')) bucket.cidr.push(row.value)
      else bucket.ip.add(row.value)
    } else if (row.kind === 'asn') bucket.asn.add(row.value)
    else bucket[row.kind]?.push(row.value)
  }
  index = built
  return built
}

function checkSubscribed(list, { ip, asn, rdns, userAgent, uri }) {
  const built = index || buildIndex()
  const bucket = built[list]
  if (!bucket) return null

  if (ip) {
    if (bucket.ip.has(ip)) return { kind: 'ip', value: ip }
    for (const cidr of bucket.cidr) if (ipCoveredBy(ip, cidr)) return { kind: 'ip', value: cidr }
  }
  if (asn && bucket.asn.has(asn)) return { kind: 'asn', value: asn }
  if (rdns) {
    for (const suffix of bucket.rdns) {
      const bare = suffix.replace(/^\./, '')
      if (rdns === bare || rdns.endsWith(`.${bare}`)) return { kind: 'rdns', value: suffix }
    }
  }
  if (userAgent && matchesUserAgent(userAgent, bucket.user_agent)) return { kind: 'user_agent', value: 'matched a subscribed pattern' }
  if (uri && matchesUri(uri, bucket.uri)) return { kind: 'uri', value: uri }
  return null
}

async function evaluate({ ip, asn, rdns, userAgent, uri }) {
  const cfg = settings.get('community_lists')
  if (!cfg.enabled) return null

  const blocked = checkSubscribed('block', { ip, asn, rdns, userAgent, uri })
  if (blocked) {
    const source = sourceOwning(blocked.value)
    return {
      decision: 'block',
      source: 'community',
      reason: `Matched ${blocked.kind} "${blocked.value}" on the subscribed list${source ? ` "${source}"` : ''}.`,
    }
  }
  const allowed = checkSubscribed('allow', { ip, asn, rdns, userAgent, uri })
  if (allowed) return { decision: 'allow', source: 'community', reason: `Matched an allow entry on a subscribed list (${allowed.kind}).` }
  return null
}

function sourceOwning(value) {
  const row = conn().prepare('SELECT source_id FROM list_entries WHERE value = ? LIMIT 1').get(value)
  if (!row) return null
  const cfg = settings.get('community_lists')
  return cfg.sources.find(s => s.id === row.source_id)?.name || row.source_id
}

function summary() {
  const cfg = settings.get('community_lists')
  const counts = conn().prepare('SELECT source_id, COUNT(*) AS n, MAX(added_at) AS at FROM list_entries GROUP BY source_id').all()
  const byId = new Map(counts.map(c => [c.source_id, c]))
  return {
    enabled: cfg.enabled,
    total_entries: counts.reduce((sum, c) => sum + c.n, 0),
    sources: cfg.sources.map(s => ({
      ...s,
      entries: byId.get(s.id)?.n || 0,
      last_refresh: byId.get(s.id)?.at || null,
    })),
  }
}

function clearSource(sourceId) {
  const r = conn().prepare('DELETE FROM list_entries WHERE source_id = ? RETURNING value').all(sourceId)
  invalidateIndex()
  return { removed: r.length }
}

function clearAll() {
  conn().exec('DELETE FROM list_entries')
  invalidateIndex()
  return { ok: true }
}

module.exports = {
  greylistMatch, refreshSource, refreshAll, evaluate, checkSubscribed,
  summary, clearSource, clearAll, invalidateIndex, parseFeed, PARSERS,
}
