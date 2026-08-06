// dbTuning.js — database engine reporting and connection tuning (idea #68).
//
// The brief is honest that this is not needed at Free's scale, and that
// remains true: SQLite via node:sqlite is the right answer for one site and
// one admin, and `engine` therefore offers exactly one value. What is
// implemented is the part that is real today — the SQLite pragmas that
// actually change behaviour (journal mode, synchronous level, busy timeout)
// are applied from settings instead of being hardcoded, and the pool knobs
// the brief lists are recorded and reported with an explicit note that
// node:sqlite is synchronous and single-connection, so they take effect only
// if CatWAF ever runs against a shared external database.
//
// Recording them rather than dropping them is the point: this is the marker
// the brief asks for, so if a multi-node tier ever exists the settings are
// already modelled and validated.

const db = require('./db')
const settings = require('./settings')
const logger = require('./logger')

const log = logger.child('db')

// Pragmas that map to something node:sqlite actually honours.
const APPLICABLE_PRAGMAS = ['journal_mode', 'synchronous', 'busy_timeout_ms']

// Settings that describe a pooled client/server database. node:sqlite opens
// one synchronous handle to a local file, so these have nothing to act on
// here — they are stored, surfaced and explained.
const POOL_SETTINGS = {
  pool_size: 'node:sqlite uses a single synchronous connection to a local file; there is no pool to size.',
  max_overflow: 'No pool, so no overflow.',
  recycle_sec: 'A local file handle is not recycled.',
  pre_ping: 'A local file handle cannot go stale between statements.',
  retry_attempts: 'Contention is handled by busy_timeout rather than by reconnecting.',
  retry_delay_ms: 'See retry_attempts.',
}

function currentPragmas() {
  const conn = db.getDb()
  const read = name => {
    try { return conn.prepare(`PRAGMA ${name}`).get() } catch { return null }
  }
  return {
    journal_mode: read('journal_mode')?.journal_mode ?? null,
    synchronous: read('synchronous')?.synchronous ?? null,
    busy_timeout: read('busy_timeout')?.timeout ?? null,
    page_size: read('page_size')?.page_size ?? null,
    cache_size: read('cache_size')?.cache_size ?? null,
    auto_vacuum: read('auto_vacuum')?.auto_vacuum ?? null,
  }
}

const SYNCHRONOUS_LEVELS = { OFF: 0, NORMAL: 1, FULL: 2, EXTRA: 3 }

function apply() {
  const cfg = settings.get('database')
  const conn = db.getDb()
  const applied = {}
  const failures = []

  const run = (statement, label, value) => {
    try { conn.exec(statement); applied[label] = value } catch (e) { failures.push({ setting: label, error: e.message }) }
  }

  if (/^(WAL|DELETE|TRUNCATE|PERSIST|MEMORY)$/.test(cfg.journal_mode)) {
    run(`PRAGMA journal_mode = ${cfg.journal_mode}`, 'journal_mode', cfg.journal_mode)
  }
  if (Object.hasOwn(SYNCHRONOUS_LEVELS, cfg.synchronous)) {
    run(`PRAGMA synchronous = ${SYNCHRONOUS_LEVELS[cfg.synchronous]}`, 'synchronous', cfg.synchronous)
  }
  if (Number.isInteger(cfg.busy_timeout_ms) && cfg.busy_timeout_ms >= 0) {
    run(`PRAGMA busy_timeout = ${cfg.busy_timeout_ms}`, 'busy_timeout_ms', cfg.busy_timeout_ms)
  }

  if (failures.length) log.warn('Some database pragmas could not be applied', { failures })
  return { ok: failures.length === 0, applied, failures }
}

function fileStats() {
  const fs = require('fs')
  try {
    const st = fs.statSync(db.DB_PATH)
    let walBytes = 0
    try { walBytes = fs.statSync(`${db.DB_PATH}-wal`).size } catch {}
    return { path: db.DB_PATH, bytes: st.size, wal_bytes: walBytes, modified: st.mtime.toISOString() }
  } catch (e) {
    return { path: db.DB_PATH, error: e.message }
  }
}

function tableSizes() {
  try {
    const conn = db.getDb()
    const tables = conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").all()
    return tables.map(t => {
      try { return { table: t.name, rows: conn.prepare(`SELECT COUNT(*) AS n FROM "${t.name}"`).get().n } }
      catch { return { table: t.name, rows: null } }
    }).sort((a, b) => (b.rows || 0) - (a.rows || 0))
  } catch {
    return []
  }
}

function status() {
  const cfg = settings.get('database')
  return {
    engine: cfg.engine,
    engines_available: ['sqlite'],
    driver: 'node:sqlite (DatabaseSync)',
    file: fileStats(),
    pragmas: currentPragmas(),
    tables: tableSizes(),
    applicable_settings: APPLICABLE_PRAGMAS,
    inert_settings: Object.entries(POOL_SETTINGS).map(([setting, why]) => ({ setting, value: cfg[setting], why })),
    note:
      'SQLite is the right engine for one site and one admin, so it is the only one offered. ' +
      'The pool settings above are modelled and validated but have nothing to act on with a local file — ' +
      'they would only start to matter if CatWAF ever ran against a shared external database.',
  }
}

// Reclaims space after a large retention purge. Cheap to expose, and the
// alternative is telling someone to run sqlite3 by hand.
function vacuum() {
  const before = fileStats().bytes
  try {
    db.getDb().exec('VACUUM')
    const after = fileStats().bytes
    return { ok: true, before_bytes: before, after_bytes: after, reclaimed_bytes: Math.max(0, before - after) }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

function checkpoint() {
  try {
    db.getDb().exec('PRAGMA wal_checkpoint(TRUNCATE)')
    return { ok: true, changed: false }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

module.exports = { apply, status, vacuum, checkpoint, currentPragmas, fileStats, tableSizes, POOL_SETTINGS }
