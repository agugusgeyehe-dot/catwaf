// backups.js — scheduled off-box backups (idea #45).
//
// snapshots.js already covers "undo my last change": in-place, in the same
// database, on the same disk. That is the wrong tool for the failure it does
// not cover — if the disk or the whole server is lost, every snapshot goes
// with it. This copies the configuration somewhere else, on a schedule,
// with bounded retention.
//
// Reuses snapshots.js's redaction so a backup file cannot become the place
// where API tokens and password hashes leak; the redacted copy is what is
// written, and restore() is explicit that secrets have to be re-entered.

const fs = require('fs')
const path = require('path')

const db = require('./db')
const state = require('./state')
const settings = require('./settings')
const caddySvc = require('./caddy')
const snapshots = require('./snapshots')
const logger = require('./logger')
const { version: pkgVersion } = require('../../package.json')

const log = logger.child('backups')
const FILE_RE = /^catwaf-backup-(\d{8}T\d{6})\.json$/

function stamp(date = new Date()) {
  return date.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, '').replace('T', 'T')
}

function assertDestination(dir) {
  if (!dir) throw new Error('No backup destination is configured.')
  if (!path.isAbsolute(dir)) throw new Error('The backup destination must be an absolute path.')
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  fs.accessSync(dir, fs.constants.W_OK)
  return dir
}

function buildPayload({ redact = true } = {}) {
  const cfg = settings.get('backups')
  const payload = {
    catwaf_version: pkgVersion,
    created_at: new Date().toISOString(),
    redacted: redact,
    waf: state.WAF,
    rule_categories: state.RULE_CATEGORIES,
    settings: settings.getAll(),
  }
  if (cfg.include_caddyfile) {
    try { payload.caddyfile = caddySvc.readCaddyfile() } catch (e) { payload.caddyfile_error = e.message }
  }
  return redact ? snapshots.redactSecrets(payload) : payload
}

function run({ dryRun = false, destination = null } = {}) {
  const cfg = settings.get('backups')
  if (!cfg.enabled && !destination) return { ok: true, skipped: 'disabled', changed: false }

  const dir = assertDestination(destination || cfg.destination)
  const payload = buildPayload({ redact: cfg.redact_secrets })
  const name = `catwaf-backup-${stamp()}.json`
  const target = path.join(dir, name)

  if (dryRun) {
    return { ok: true, dryRun: true, would_write: target, bytes: Buffer.byteLength(JSON.stringify(payload)) }
  }

  // Write to a temp file then rename, so an interrupted backup never leaves
  // a truncated file that looks complete.
  const tmp = `${target}.partial`
  fs.writeFileSync(tmp, JSON.stringify(payload, null, 2), { mode: 0o600 })
  fs.renameSync(tmp, target)

  let dbCopy = null
  if (cfg.include_database) {
    dbCopy = path.join(dir, `catwaf-backup-${stamp()}.db`)
    try {
      // A WAL-mode database needs a checkpoint before the main file is a
      // complete copy on its own.
      db.getDb().exec('PRAGMA wal_checkpoint(TRUNCATE)')
      fs.copyFileSync(db.DB_PATH, dbCopy)
      fs.chmodSync(dbCopy, 0o600)
    } catch (e) {
      dbCopy = null
      log.error('Could not copy the database into the backup', { error: e.message })
    }
  }

  const pruned = prune(dir, cfg.retain)
  log.info('Backup written', { target, database: !!dbCopy, pruned: pruned.removed })
  return { ok: true, file: target, database: dbCopy, pruned: pruned.removed, changed: true }
}

function prune(dir, retain) {
  const keep = Math.max(1, retain)
  const removed = []
  try {
    const files = fs.readdirSync(dir)
      .filter(f => f.startsWith('catwaf-backup-'))
      .map(f => ({ f, t: fs.statSync(path.join(dir, f)).mtimeMs }))
      .sort((a, b) => b.t - a.t)

    // Retention counts JSON manifests; each manifest's sibling .db is pruned
    // with it so the two never drift.
    const manifests = files.filter(x => x.f.endsWith('.json'))
    for (const extra of manifests.slice(keep)) {
      try { fs.unlinkSync(path.join(dir, extra.f)); removed.push(extra.f) } catch {}
      const sibling = extra.f.replace(/\.json$/, '.db')
      try { fs.unlinkSync(path.join(dir, sibling)); removed.push(sibling) } catch {}
    }
  } catch (e) {
    return { removed: removed.length, error: e.message }
  }
  return { removed: removed.length, files: removed }
}

function list() {
  const cfg = settings.get('backups')
  if (!cfg.destination) return { ok: true, destination: null, backups: [] }
  try {
    const entries = fs.readdirSync(cfg.destination)
      .filter(f => FILE_RE.test(f))
      .map(f => {
        const st = fs.statSync(path.join(cfg.destination, f))
        const dbSibling = path.join(cfg.destination, f.replace(/\.json$/, '.db'))
        return {
          name: f,
          size_bytes: st.size,
          created_at: st.mtime.toISOString(),
          has_database: fs.existsSync(dbSibling),
        }
      })
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
    return { ok: true, destination: cfg.destination, backups: entries, retain: cfg.retain }
  } catch (e) {
    return { ok: false, destination: cfg.destination, error: e.message, backups: [] }
  }
}

function verifyDestination(destination) {
  try {
    const dir = assertDestination(destination)
    const probe = path.join(dir, '.catwaf-write-test')
    fs.writeFileSync(probe, 'ok')
    fs.unlinkSync(probe)
    return { ok: true, destination: dir }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

module.exports = { run, list, prune, buildPayload, verifyDestination, FILE_RE }
