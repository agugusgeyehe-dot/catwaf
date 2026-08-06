// intel/cache.js — a small bounded TTL cache shared by every lookup that
// costs a network round-trip (rDNS, ASN, DNSBL, the threat feed, relay
// probing).
//
// Each of those runs on the request path, so an uncached lookup would add
// DNS latency to every visit from a repeat visitor. Namespacing the caches
// also gives the housekeeping page (idea #63) something concrete to report
// and clear, rather than "some files somewhere".

const namespaces = new Map()

function ns(name, { max = 10000 } = {}) {
  if (!namespaces.has(name)) {
    namespaces.set(name, { name, max, entries: new Map(), hits: 0, misses: 0, lastRefresh: null })
  }
  return namespaces.get(name)
}

function get(name, key) {
  const space = ns(name)
  const entry = space.entries.get(key)
  if (!entry) { space.misses++; return undefined }
  if (entry.expires <= Date.now()) {
    space.entries.delete(key)
    space.misses++
    return undefined
  }
  space.hits++
  return entry.value
}

function set(name, key, value, ttlMs) {
  const space = ns(name)
  // Cheapest eviction that still bounds memory: drop the oldest insertion.
  // Map preserves insertion order, so the first key is the oldest.
  if (space.entries.size >= space.max) {
    const oldest = space.entries.keys().next().value
    if (oldest !== undefined) space.entries.delete(oldest)
  }
  space.entries.set(key, { value, expires: Date.now() + Math.max(1000, ttlMs), stored: Date.now() })
  space.lastRefresh = new Date().toISOString()
  return value
}

// Wraps an async lookup so callers never have to write the same
// check-then-store dance. A failed lookup is not cached unless the caller
// asks for it — a transient DNS failure should not stick for hours.
async function through(name, key, ttlMs, loader, { cacheErrors = false, errorTtlMs = 30000 } = {}) {
  const hit = get(name, key)
  if (hit !== undefined) return hit
  try {
    const value = await loader()
    return set(name, key, value, ttlMs)
  } catch (e) {
    if (cacheErrors) set(name, key, { error: e.message }, errorTtlMs)
    throw e
  }
}

function purgeExpired(name) {
  const space = namespaces.get(name)
  if (!space) return 0
  const now = Date.now()
  let removed = 0
  for (const [key, entry] of space.entries) {
    if (entry.expires <= now) { space.entries.delete(key); removed++ }
  }
  return removed
}

function clear(name) {
  if (!name) {
    let total = 0
    for (const space of namespaces.values()) { total += space.entries.size; space.entries.clear() }
    return total
  }
  const space = namespaces.get(name)
  if (!space) return 0
  const size = space.entries.size
  space.entries.clear()
  return size
}

function stats() {
  return [...namespaces.values()].map(space => ({
    name: space.name,
    entries: space.entries.size,
    max: space.max,
    hits: space.hits,
    misses: space.misses,
    hit_rate: space.hits + space.misses > 0 ? Math.round((space.hits / (space.hits + space.misses)) * 100) : null,
    last_refresh: space.lastRefresh,
  })).sort((a, b) => a.name.localeCompare(b.name))
}

module.exports = { get, set, through, clear, purgeExpired, stats, ns }
