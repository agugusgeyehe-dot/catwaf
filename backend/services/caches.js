// caches.js — the housekeeping view over everything CatWAF caches on disk or
// in memory (idea #63).
//
// As the intel features landed, CatWAF started accumulating the same kind of
// local state BunkerWeb's cache page exists for: rDNS and ASN answers, DNSBL
// verdicts, downloaded community lists, generated Caddy assets, rotated
// backups. Each is individually harmless and collectively the reason someone
// ends up SSHing in to delete files by hand. This gives every one of them a
// name, a size, an age and a button.

const fs = require('fs')
const path = require('path')

const cache = require('./intel/cache')
const db = require('./db')
const lists = require('./intel/lists')
const enforce = require('./enforce')
const settings = require('./settings')

function dirStats(dir) {
  let bytes = 0
  let files = 0
  let newest = null
  const walk = (current, depth = 0) => {
    if (depth > 6) return
    let entries
    try { entries = fs.readdirSync(current, { withFileTypes: true }) } catch { return }
    for (const entry of entries) {
      const full = path.join(current, entry.name)
      if (entry.isDirectory()) { walk(full, depth + 1); continue }
      try {
        const st = fs.statSync(full)
        bytes += st.size
        files++
        if (!newest || st.mtimeMs > newest) newest = st.mtimeMs
      } catch { /* vanished mid-walk */ }
    }
  }
  walk(dir)
  return { bytes, files, newest: newest ? new Date(newest).toISOString() : null, exists: fs.existsSync(dir) }
}

function caddyAssetDir() { return path.join(path.dirname(db.DB_PATH), 'caddy') }
function backupDirPath() { return path.join(path.dirname(db.DB_PATH), 'backups') }

function geoipStatus() {
  const geoip = require('./geoip')
  const availability = geoip.available()
  let dbPath = null
  let age = null
  try {
    // geoip-lite ships its data alongside the package; reporting its age is
    // what makes "is my geo data stale?" answerable without a shell.
    dbPath = path.join(path.dirname(require.resolve('geoip-lite')), '..', 'data')
    const st = fs.statSync(dbPath)
    age = Math.floor((Date.now() - st.mtimeMs) / 86_400_000)
  } catch { /* not installed, or laid out differently */ }
  return { available: availability.ok, error: availability.error, path: dbPath, age_days: age }
}

// Each namespace declares how to measure itself and how to clear itself, so
// the route stays a thin dispatcher and adding a cache means adding an entry.
const NAMESPACES = {
  rdns: {
    label: 'Reverse DNS lookups',
    description: 'PTR records and forward-confirmation results, cached per address.',
    measure: () => memoryStats('rdns'),
    clear: () => ({ cleared: cache.clear('rdns') }),
  },
  asn: {
    label: 'ASN lookups',
    description: 'Origin-network answers, cached per address.',
    measure: () => memoryStats('asn'),
    clear: () => ({ cleared: cache.clear('asn') }),
  },
  dnsbl: {
    label: 'DNSBL verdicts',
    description: 'One cache per configured blackhole zone.',
    measure: () => {
      const zones = cache.stats().filter(s => s.name.startsWith('dnsbl:'))
      return {
        entries: zones.reduce((n, z) => n + z.entries, 0),
        detail: zones.length ? `${zones.length} zone cache(s)` : 'No zones queried yet',
      }
    },
    clear: () => {
      let cleared = 0
      for (const s of cache.stats()) if (s.name.startsWith('dnsbl:')) cleared += cache.clear(s.name)
      return { cleared }
    },
  },
  'threat-feed': {
    label: 'Local threat feed',
    description: 'Decisions cached from the local bouncer API.',
    measure: () => memoryStats('threat-feed'),
    clear: () => ({ cleared: cache.clear('threat-feed') }),
  },
  'threat-network': {
    label: 'Shared threat network',
    description: 'Reputation answers from the shared network.',
    measure: () => memoryStats('threat-network'),
    clear: () => ({ cleared: cache.clear('threat-network') }),
  },
  'client-probe': {
    label: 'Relay detection',
    description: 'Port-probe verdicts, cached per address.',
    measure: () => memoryStats('client-probe'),
    clear: () => ({ cleared: cache.clear('client-probe') }),
  },
  verdict: {
    label: 'Composite verdicts',
    description: 'The combined allow/block decision per address, cached briefly to keep enforcement off the critical path.',
    measure: () => memoryStats('verdict'),
    clear: () => ({ cleared: enforce.invalidate() }),
  },
  'community-lists': {
    label: 'Community blocklists',
    description: 'Entries downloaded from subscribed sources.',
    measure: () => {
      const summary = lists.summary()
      const last = summary.sources.map(s => s.last_refresh).filter(Boolean).sort().pop() || null
      return { entries: summary.total_entries, detail: `${summary.sources.length} source(s)`, last_refresh: last }
    },
    clear: () => lists.clearAll(),
    refresh: () => lists.refreshAll(),
  },
  'caddy-assets': {
    label: 'Generated Caddy assets',
    description: 'robots.txt, security.txt, error pages, certificates and CA bundles written for the generated configuration.',
    measure: () => {
      const st = dirStats(caddyAssetDir())
      return { bytes: st.bytes, entries: st.files, last_refresh: st.newest, detail: caddyAssetDir() }
    },
    // Assets are regenerated on the next apply, so clearing them is safe;
    // the current configuration keeps working until then because Caddy has
    // already loaded what it needs.
    clear: () => {
      let removed = 0
      const dir = caddyAssetDir()
      const walk = current => {
        let entries = []
        try { entries = fs.readdirSync(current, { withFileTypes: true }) } catch { return }
        for (const entry of entries) {
          const full = path.join(current, entry.name)
          if (entry.isDirectory()) { walk(full); try { fs.rmdirSync(full) } catch {} ; continue }
          try { fs.unlinkSync(full); removed++ } catch {}
        }
      }
      walk(dir)
      return { cleared: removed, note: 'Assets are rewritten on the next configuration apply.' }
    },
  },
  'caddyfile-backups': {
    label: 'Caddyfile backups',
    description: 'Timestamped copies taken before every configuration change.',
    measure: () => {
      const st = dirStats(backupDirPath())
      return { bytes: st.bytes, entries: st.files, last_refresh: st.newest, detail: backupDirPath() }
    },
    clear: () => {
      let removed = 0
      try {
        const dir = backupDirPath()
        // The most recent backup is the rollback target, so it is kept.
        const files = fs.readdirSync(dir)
          .filter(f => f.startsWith('Caddyfile.'))
          .map(f => ({ f, t: fs.statSync(path.join(dir, f)).mtimeMs }))
          .sort((a, b) => b.t - a.t)
        for (const extra of files.slice(1)) { try { fs.unlinkSync(path.join(dir, extra.f)); removed++ } catch {} }
      } catch {}
      return { cleared: removed, note: 'The most recent backup is always kept as a rollback target.' }
    },
  },
  'caddy-modules': {
    label: 'Caddy capability probe',
    description: 'The cached answer to "which optional Caddy modules are installed".',
    measure: () => {
      const info = require('./caddyModules').summary()
      return { entries: info.module_count, detail: info.version || 'Caddy binary not found' }
    },
    clear: () => { require('./caddyModules').refresh(); return { cleared: 1 } },
  },
}

function memoryStats(name) {
  const stats = cache.stats().find(s => s.name === name)
  return stats
    ? { entries: stats.entries, detail: stats.hit_rate === null ? 'No lookups yet' : `${stats.hit_rate}% hit rate`, last_refresh: stats.last_refresh }
    : { entries: 0, detail: 'No lookups yet' }
}

function overview() {
  const namespaces = Object.entries(NAMESPACES).map(([id, spec]) => {
    let measured = {}
    try { measured = spec.measure() || {} } catch (e) { measured = { error: e.message } }
    return {
      id,
      label: spec.label,
      description: spec.description,
      entries: measured.entries ?? null,
      bytes: measured.bytes ?? null,
      detail: measured.detail ?? null,
      last_refresh: measured.last_refresh ?? null,
      error: measured.error ?? null,
      can_refresh: typeof spec.refresh === 'function',
    }
  })
  return {
    namespaces,
    geoip: geoipStatus(),
    total_bytes: namespaces.reduce((n, ns) => n + (ns.bytes || 0), 0),
    total_entries: namespaces.reduce((n, ns) => n + (ns.entries || 0), 0),
  }
}

function clear(id) {
  if (id === 'all') {
    const results = {}
    for (const [name, spec] of Object.entries(NAMESPACES)) {
      try { results[name] = spec.clear() } catch (e) { results[name] = { error: e.message } }
    }
    return { ok: true, cleared: results }
  }
  const spec = NAMESPACES[id]
  if (!spec) return { ok: false, error: `Unknown cache "${id}".` }
  try { return { ok: true, id, ...spec.clear() } } catch (e) { return { ok: false, error: e.message } }
}

async function refresh(id) {
  const spec = NAMESPACES[id]
  if (!spec) return { ok: false, error: `Unknown cache "${id}".` }
  if (typeof spec.refresh !== 'function') return { ok: false, error: `"${id}" has nothing to refresh — it fills on demand.` }
  try { return { ok: true, id, ...(await spec.refresh()) } } catch (e) { return { ok: false, error: e.message } }
}

function purgeExpired() {
  let removed = 0
  for (const stat of cache.stats()) removed += cache.purgeExpired(stat.name)
  return { removed, changed: false }
}

module.exports = { overview, clear, refresh, purgeExpired, NAMESPACES, geoipStatus }
