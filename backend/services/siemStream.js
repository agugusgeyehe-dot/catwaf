// siemStream.js — append blocked (optionally all) requests as JSON lines to
// data/siem.jsonl, with size-based rotation, and optionally POST each batch
// to an HTTP collector. Cursor is the SQLite rowid, so events are delivered
// exactly once in commit order and survive restarts.

const fs = require('fs')
const path = require('path')

const settings = require('./settings')
const db = require('./db')
const logger = require('./logger')
const netGuard = require('./netGuard')

const log = logger.child('siem')
const CURSOR_KEY = 'siem_cursor'
const MAX_FILE_BYTES = 50 * 1024 * 1024

function dataDir() {
  return process.env.DB_DIR || path.join(__dirname, '..', '..', 'data')
}
function filePath() { return path.join(dataDir(), 'siem.jsonl') }

function eventLine(row) {
  return JSON.stringify({
    ts: row.ts,
    action: row.action,
    ip: row.ip,
    method: row.method,
    uri: row.uri,
    status: row.status,
    attack_type: row.attack_type || null,
    rule_ids: row.rule_ids || null,
    score: row.score ?? null,
    severity: row.severity || null,
    user_agent: row.user_agent || null,
    country_code: row.country_code || null,
  })
}

function poll() {
  const cfg = settings.get('siem')
  if (!cfg.enabled) return { ok: true, skipped: 'disabled' }

  const conn = db.getDb()
  let cursor = Number(db.getState(CURSOR_KEY))
  if (!Number.isFinite(cursor)) {
    // First run after enabling: stream starts FROM NOW. Exporting the whole
    // retained history to a fresh collector is almost never what anyone
    // wants, and a stale cursor after VACUUM could renumber rowids — the
    // documented tradeoff of the rowid approach.
    const max = conn.prepare('SELECT COALESCE(MAX(rowid), 0) AS m FROM request_log').get().m
    db.setState(CURSOR_KEY, max)
    return { ok: true, seeded_at: max, exported: 0 }
  }
  cursor = Math.max(0, cursor)
  const where = cfg.include_allowed ? 'rowid > ?' : "rowid > ? AND action = 'block'"
  const rows = conn.prepare(
    `SELECT rowid AS rid, ts, action, ip, method, uri, status, attack_type, rule_ids, score, severity, user_agent, country_code
     FROM request_log WHERE ${where} ORDER BY rowid ASC LIMIT ?`
  ).all(cursor, Math.min(cfg.batch_max, 5000))

  if (!rows.length) return { ok: true, exported: 0 }

  const dir = dataDir()
  try { fs.mkdirSync(dir, { recursive: true }) } catch {}
  const file = filePath()

  // Size rotation: one previous generation is kept.
  try {
    const st = fs.statSync(file)
    if (st.size > MAX_FILE_BYTES) {
      try { fs.unlinkSync(file + '.1') } catch {}
      fs.renameSync(file, file + '.1')
    }
  } catch { /* first write */ }

  const payload = rows.map(eventLine).join('\n') + '\n'
  fs.appendFileSync(file, payload)

  const lastRid = rows[rows.length - 1].rid
  db.setState(CURSOR_KEY, lastRid)

  // Fire-and-forget HTTP delivery of the same batch (async, outside the
  // cursor path so a slow sink never blocks ingestion). A failed POST is
  // logged; the file already holds the events, so nothing is lost.
  if (cfg.http_url) {
    postBatch(cfg.http_url, payload).catch(e => log.warn('SIEM collector unreachable', { error: e.message }))
  }

  return { ok: true, exported: rows.length }
}

async function postBatch(url, jsonl) {
  const { response } = await netGuard.guardedFetch(url, {
    method: 'POST',
    timeoutMs: 10_000,
    headers: { 'Content-Type': 'application/x-ndjson' },
    body: jsonl,
  })
  if (!response.ok) throw new Error(`collector answered ${response.status}`)
}

module.exports = { poll, eventLine, filePath }
