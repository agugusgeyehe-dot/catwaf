// counters.js — lightweight runtime counters for events too hot (or too
// short-lived) to justify a database write per occurrence: canary hits,
// alert deliveries, edge refresh outcomes.
//
// Counters accumulate in memory and are flushed to SQLite by the scheduler
// (metrics.flush), so a scrape after a crash still reports the last flushed
// value rather than losing everything silently. Reads merge the persisted
// base with the in-memory delta.

const db = require('./db')

const KEY = 'runtime_counters'
const memory = new Map()

function incr(name, by = 1) {
  memory.set(name, (memory.get(name) || 0) + by)
}

function get(name) {
  return (memory.get(name) || 0) + (persisted()[name] || 0)
}

function all() {
  const out = { ...persisted() }
  for (const [k, v] of memory) out[k] = (out[k] || 0) + v
  return out
}

function persisted() {
  try {
    const stored = db.getState(KEY)
    return stored && typeof stored === 'object' ? stored : {}
  } catch { return {} }
}

function flush() {
  if (!memory.size) return { flushed: 0 }
  const base = persisted()
  for (const [k, v] of memory) base[k] = (base[k] || 0) + v
  db.setState(KEY, base)
  memory.clear()
  return { flushed: Object.keys(base).length }
}

module.exports = { incr, get, all, flush }
