
const path = require('path')
const fs = require('fs')
const { DatabaseSync } = require('node:sqlite')

const DB_DIR = process.env.DB_DIR || path.join(__dirname, '..', '..', 'data')
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true })

let DB_PATH = process.env.DB_PATH || path.join(DB_DIR, 'catwaf.db')

function openDb(dbPath) {
  const instance = new DatabaseSync(dbPath)

  instance.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA busy_timeout = 5000;
    PRAGMA temp_store = MEMORY;
  `)

  instance.exec(`
    CREATE TABLE IF NOT EXISTS waf_state (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id    TEXT PRIMARY KEY,
      ts    TEXT,
      user  TEXT,
      role  TEXT,
      ip    TEXT,
      action TEXT,
      target TEXT,
      meta  TEXT
    );
    CREATE TABLE IF NOT EXISTS snapshots (
      id    TEXT PRIMARY KEY,
      ts    TEXT,
      username TEXT,
      label TEXT,
      state TEXT
    );
    CREATE TABLE IF NOT EXISTS false_positives (
      id   TEXT PRIMARY KEY,
      data TEXT
    );
    CREATE TABLE IF NOT EXISTS request_log (
      id          TEXT PRIMARY KEY,
      ts          TEXT NOT NULL,
      ip          TEXT,
      method      TEXT,
      uri         TEXT,
      status      INTEGER,
      action      TEXT,
      attack_type TEXT,
      rule_ids    TEXT,
      score       INTEGER,
      user_agent  TEXT,
      severity    TEXT,
      reason      TEXT,
      matched_var TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(ts DESC);
    -- Almost every analytics query is "blocked requests in a time window":
    -- the stats tiles, the attack-type breakdown, the severity split and the
    -- attack map all share that shape. On a ts-only index each of them scans
    -- the whole window and discards the passes.
    CREATE INDEX IF NOT EXISTS idx_request_log_action_ts ON request_log(action, ts DESC);
    -- Top-attacker aggregation groups by ip within blocked rows.
    CREATE INDEX IF NOT EXISTS idx_request_log_action_ip ON request_log(action, ip);
    -- Every audit read and the retention sweep order by ts.
    CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts DESC);
    CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON snapshots(ts DESC);
  `)

  migrateColumns(instance, 'request_log', {
    severity: 'TEXT',
    reason: 'TEXT',
    matched_var: 'TEXT',
    country_code: 'TEXT',
    city: 'TEXT',
    lat: 'REAL',
    lon: 'REAL',
  })

  return instance
}

const SAFE_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/
const SAFE_COLUMN_TYPE = /^(TEXT|INTEGER|REAL|BLOB|NUMERIC)$/

function migrateColumns(instance, table, columns) {
  if (!SAFE_IDENTIFIER.test(table)) throw new Error(`Unsafe table identifier: ${table}`)
  const existing = instance.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name)
  for (const [name, type] of Object.entries(columns)) {
    if (!SAFE_IDENTIFIER.test(name)) throw new Error(`Unsafe column identifier: ${name}`)
    if (!SAFE_COLUMN_TYPE.test(type)) throw new Error(`Unsafe column type: ${type}`)
    if (!existing.includes(name)) {
      instance.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`)
    }
  }
}

let db = openDb(DB_PATH)

function getState(key) {
  const row = db.prepare('SELECT value FROM waf_state WHERE key = ?').get(key)
  if (!row) return null
  try { return JSON.parse(row.value) } catch { return null }
}
function setState(key, value) {
  db.prepare('INSERT OR REPLACE INTO waf_state (key, value) VALUES (?, ?)').run(key, JSON.stringify(value))
}

function switchDb(newPath) {
  db = openDb(newPath)
  DB_PATH = newPath
  return db
}

module.exports = {
  getDb: () => db,
  getState, setState, switchDb,
  get DB_PATH() { return DB_PATH },
  DB_DIR,
}
