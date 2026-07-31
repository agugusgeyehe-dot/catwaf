
const crypto = require('crypto')
const db = require('./db')
const state = require('./state')

const now = () => new Date().toISOString()
const rid = (n=8) => crypto.randomBytes(n).toString('hex')

const AUDIT_LIMIT = 5000
const AUDIT_PRUNE_SLACK = 500
let auditsSincePrune = 0

function audit(req, action, target, meta = {}) {
  const e = {
    id: rid(6), ts: now(),
    user: req?.user ? req.user.username : 'anonymous',
    role: req?.user ? (req.user.role ?? null) : null,
    ip: req?.ip || '',
    action, target,
    meta: JSON.stringify(meta),
  }
  const conn = db.getDb()
  conn.prepare('INSERT OR IGNORE INTO audit_log (id,ts,user,role,ip,action,target,meta) VALUES (?,?,?,?,?,?,?,?)')
    .run(e.id, e.ts, e.user, e.role, e.ip, e.action, e.target, e.meta)

  if (++auditsSincePrune >= AUDIT_PRUNE_SLACK) {
    auditsSincePrune = 0
    pruneAuditLog()
  }
}

function pruneAuditLog() {
  const conn = db.getDb()
  conn.prepare(`
    DELETE FROM audit_log
    WHERE id IN (
      SELECT id FROM audit_log ORDER BY ts DESC LIMIT -1 OFFSET ?
    )
  `).run(AUDIT_LIMIT)
}

function getAuditLogs(limit = 200) {
  const conn = db.getDb()
  return conn.prepare('SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?').all(limit)
    .map(r => ({ ...r, meta: (() => { try { return JSON.parse(r.meta) } catch { return {} } })() }))
}

function snapshot(req, label) {
  const conn = db.getDb()
  const s = {
    id: rid(6), ts: now(),
    username: req?.user ? req.user.username : 'system',
    label: label || 'manual',
    state: JSON.stringify(state.WAF),
  }
  conn.prepare('INSERT INTO snapshots (id,ts,username,label,state) VALUES (?,?,?,?,?)')
    .run(s.id, s.ts, s.username, s.label, s.state)
  conn.prepare('DELETE FROM snapshots WHERE id IN (SELECT id FROM snapshots ORDER BY ts DESC LIMIT -1 OFFSET ?)').run(50)
  return s
}

function getSnapshots() {
  return db.getDb().prepare('SELECT id,ts,username,label FROM snapshots ORDER BY ts DESC').all()
}

function getSnapshot(id) {
  const row = db.getDb().prepare('SELECT * FROM snapshots WHERE id = ?').get(id)
  if (!row) return null
  return { ...row, state: JSON.parse(row.state) }
}

function getFPs() {
  return db.getDb().prepare('SELECT data FROM false_positives ORDER BY rowid DESC').all().map(r => JSON.parse(r.data))
}
function saveFP(fp) { db.getDb().prepare('INSERT OR REPLACE INTO false_positives (id, data) VALUES (?,?)').run(fp.id, JSON.stringify(fp)) }

module.exports = {
  now, rid, audit, getAuditLogs,
  snapshot, getSnapshots, getSnapshot,
  getFPs, saveFP,
}
