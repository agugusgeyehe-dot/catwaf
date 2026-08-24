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
const { execFileSync } = require('child_process')
const path = require('path')

const db = require('./db')
const state = require('./state')
const settings = require('./settings')
const configLock = require('./configLock')
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

// A caller-supplied destination must resolve inside the configured backup
// root. Without this containment, an authenticated write-enabled request
// could point backups.run() at any writable absolute directory and have
// CatWAF stage a 0600 copy of the entire SQLite database there — plus prune()
// would delete any pre-existing "catwaf-backup-*" files in that directory.
function containedDestination(candidate, configuredRoot) {
  const requested = path.resolve(String(candidate))
  if (!configuredRoot) {
    // No configured root: fall back to CatWAF's own data directory so the
    // feature still works on a fresh install where nothing was configured.
    return { ok: true, dir: path.resolve(db.DB_DIR) }
  }
  const root = path.resolve(configuredRoot)
  const rel = path.relative(root, requested)
  if (rel === '' || (rel && !rel.startsWith('..') && !path.isAbsolute(rel))) {
    return { ok: true, dir: requested }
  }
  return {
    ok: false,
    error: `Backup destinations must live under the configured backup directory (${root}). Set a new destination in Settings → Backups first.`,
  }
}

function run({ dryRun = false, destination = null } = {}) {
  const cfg = settings.get('backups')
  if (!cfg.enabled && !destination) return { ok: true, skipped: 'disabled', changed: false }

  let dir
  if (destination) {
    const check = containedDestination(destination, cfg.destination)
    if (!check.ok) throw new Error(check.error)
    dir = assertDestination(check.dir)
  } else {
    dir = assertDestination(cfg.destination)
  }
  const payload = buildPayload({ redact: cfg.redact_secrets })
  const name = `catwaf-backup-${stamp()}.json`
  const target = path.join(dir, name)

  if (dryRun) {
    return { ok: true, dryRun: true, would_write: target + (settings.get('backups').encrypt ? '.enc' : ''), bytes: Buffer.byteLength(JSON.stringify(payload)) }
  }

  // Write plaintext to a temp file, then either rename it into place or
  // encrypt it there and destroy the plaintext — an interrupted backup
  // never leaves a truncated file that looks complete, and with encryption
  // on the plaintext only ever exists inside this directory for milliseconds.
  const tmpPlain = `${target}.partial`
  const plain = Buffer.from(JSON.stringify(payload, null, 2), 'utf8')
  let finalTarget = target
  try {
    if (cfg.encrypt) {
      encryptBufferToFile(plain, finalTarget + '.enc')
    } else {
      fs.writeFileSync(tmpPlain, plain, { mode: 0o600 })
      fs.renameSync(tmpPlain, target)
    }
  } catch (e) {
    try { fs.unlinkSync(tmpPlain) } catch {}
    try { fs.unlinkSync(finalTarget + '.enc') } catch {}
    throw e
  }
  if (cfg.encrypt) finalTarget = finalTarget + '.enc'

  let dbCopy = null
  if (cfg.include_database) {
    const stampDb = `catwaf-backup-${stamp()}`
    try {
      // A WAL-mode database needs a checkpoint before the main file is a
      // complete copy on its own.
      db.getDb().exec('PRAGMA wal_checkpoint(TRUNCATE)')
      const stage = path.join(dir, `${stampDb}.db.partial`)
      try {
        fs.copyFileSync(db.DB_PATH, stage)
        if (cfg.encrypt) {
          dbCopy = path.join(dir, `${stampDb}.db.enc`)
          // Plaintext exists only for this copy+encrypt window; any failure
          // destroys it rather than leaving a readable database behind.
          try {
            encryptBufferToFile(fs.readFileSync(stage), dbCopy)
            fs.unlinkSync(stage)
          } catch (e) {
            try { fs.unlinkSync(stage) } catch {}
            throw e
          }
        } else {
          dbCopy = path.join(dir, `${stampDb}.db`)
          fs.renameSync(stage, dbCopy)
          fs.chmodSync(dbCopy, 0o600)
        }
      } catch (e) {
        dbCopy = null
        log.error('Could not copy the database into the backup', { error: e.message })
      }
    } catch (e) {
      dbCopy = null
      log.error('Could not copy the database into the backup', { error: e.message })
    }
  }

  const pruned = prune(dir, cfg.retain)
  log.info('Backup written', { target: finalTarget, database: !!dbCopy, pruned: pruned.removed })
  return { ok: true, file: finalTarget, encrypted: cfg.encrypt, database: dbCopy, pruned: pruned.removed, changed: true }
}

function prune(dir, retain) {
  const keep = Math.max(1, retain)
  const removed = []
  try {
    const files = fs.readdirSync(dir)
      .filter(f => f.startsWith('catwaf-backup-'))
      .map(f => ({ f, t: fs.statSync(path.join(dir, f)).mtimeMs }))
      .sort((a, b) => b.t - a.t)

    // Retention counts manifests (plain or .enc); each manifest's database
    // sibling — plain or encrypted — is pruned with it so they never drift.
    const manifests = files.filter(x => /\.json(\.enc)?$/.test(x.f))
    for (const extra of manifests.slice(keep)) {
      try { fs.unlinkSync(path.join(dir, extra.f)); removed.push(extra.f) } catch {}
      const base = extra.f.replace(/\.json(\.enc)?$/, '')
      for (const sibling of [base + '.db', base + '.db.enc']) {
        try { fs.unlinkSync(path.join(dir, sibling)); removed.push(path.basename(sibling)) } catch {}
      }
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
    const ARTIFACT_RE = /^catwaf-backup-\d{8}T\d{6}\.json(\.enc)?$/
    const entries = fs.readdirSync(cfg.destination)
      .filter(f => ARTIFACT_RE.test(f) || FILE_RE.test(f))
      .map(f => {
        const st = fs.statSync(path.join(cfg.destination, f))
        const base = f.replace(/\.json(\.enc)?$/, '')
        const dbSibling = [base + '.db', base + '.db.enc'].map(s => path.join(cfg.destination, s)).find(p => fs.existsSync(p))
        return {
          name: f,
          size_bytes: st.size,
          created_at: st.mtime.toISOString(),
          has_database: !!dbSibling,
          encrypted: f.endsWith('.enc'),
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
    const cfg = settings.get('backups')
    const check = containedDestination(destination || cfg.destination, cfg.destination)
    if (!check.ok) return { ok: false, error: check.error }
    const dir = assertDestination(check.dir)
    const probe = path.join(dir, '.catwaf-write-test')
    fs.writeFileSync(probe, 'ok')
    fs.unlinkSync(probe)
    return { ok: true, destination: dir }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

// ── Restore ─────────────────────────────────────────────────────────────
//
// The write half of backups existed for a long time; this is the read half.
// Restoring is deliberately stricter than writing: a backup is an arbitrary
// file the operator points at, so everything it contains is re-validated
// before any of it touches live state.

function restoreFromFile(filePath, { restoreDatabase = false, allowRedacted = false } = {}) {
  const resolved = path.resolve(String(filePath || ''))
  if (!fs.existsSync(resolved)) return { ok: false, error: `No such file: ${resolved}` }

  let rawText
  if (isEncrypted(resolved)) {
    try {
      rawText = decryptFileToBuffer(resolved).toString('utf8')
    } catch (e) {
      return { ok: false, error: `Could not decrypt this backup: ${e.message}` }
    }
  } else {
    try { rawText = fs.readFileSync(resolved, 'utf8') } catch (e) {
      return { ok: false, error: `Cannot read ${resolved}: ${e.message}` }
    }
  }

  let manifest
  try {
    manifest = JSON.parse(rawText)
  } catch (e) {
    return { ok: false, error: `Not a readable CatWAF backup (JSON parse failed): ${e.message}` }
  }
  if (!manifest || typeof manifest !== 'object' || !manifest.waf) {
    return { ok: false, error: 'This file does not look like a CatWAF backup (missing the "waf" section).' }
  }
  if (manifest.redacted && !allowRedacted) {
    return {
      ok: false,
      error: 'This backup was written with secrets redacted. Restoring it would erase every stored secret. Re-run with --allow-redacted if that is genuinely what you want.',
      code: 'REDACTED',
    }
  }

  // Validate the WAF section exactly as a live write would.
  const sanitize = require('./sanitize')
  const check = sanitize.validateWafState(manifest.waf)
  if (!check.valid) return { ok: false, error: `Backup WAF state failed validation: ${check.errors.join('; ')}` }

  const configTx = require('./configTx')
  const hadCaddyfile = fs.existsSync(caddySvc.CADDYFILE_PATH)
  let previousCaddyfile = null
  try { previousCaddyfile = hadCaddyfile ? fs.readFileSync(caddySvc.CADDYFILE_PATH, 'utf8') : null } catch {}

  // Config restore goes through the transaction pipeline: snapshot → apply
  // → render → validate → reload, rolling back both state and file on any
  // failure — identical guarantees to every other configuration change.
  const tx = configTx.apply({
    label: 'backup.restore',
    mutate: (s) => {
      // Merge over defaults like every loader does: a minimal or older
      // backup must not amputate fields added since it was written.
      const merged = { ...state.DEFAULT_WAF, ...check.sanitized }
      for (const key of Object.keys(s.WAF)) delete s.WAF[key]
      Object.assign(s.WAF, merged)
      if (manifest.rule_categories && typeof manifest.rule_categories === 'object') {
        for (const key of Object.keys(s.RULE_CATEGORIES)) delete s.RULE_CATEGORIES[key]
        Object.assign(s.RULE_CATEGORIES, require('./sanitize').stripUnsafeKeys(manifest.rule_categories))
      }
      if (manifest.settings && typeof manifest.settings === 'object') {
        for (const [group, value] of Object.entries(manifest.settings)) {
          if (settings.isGroup(group)) settings.replace(group, value)
        }
      }
      if (typeof manifest.caddyfile === 'string' && manifest.caddyfile.trim()) {
        configLock.atomicWriteFileSync(caddySvc.CADDYFILE_PATH, manifest.caddyfile, { mode: 0o644 })
      }
      return { from: path.basename(resolved), redacted: !!manifest.redacted }
    },
    validate: (s) => {
      // A redacted caddyfile section in the source means the restored file
      // may contain «redacted» placeholders — refuse before Caddy sees it.
      if (manifest.redacted && typeof manifest.caddyfile === 'string' && manifest.caddyfile.includes('«redacted»')) {
        return { ok: false, error: 'The backed-up Caddyfile was redacted and cannot be restored.' }
      }
      return { ok: true }
    },
  })

  if (!tx.ok) {
    return { ok: false, error: tx.error || 'restore failed', phase: tx.phase, rolledBack: true }
  }

  const result = { ok: true, restored_from: resolved, waf: true, rule_categories: !!manifest.rule_categories, settings_groups: manifest.settings ? Object.keys(manifest.settings).filter(g => settings.isGroup(g)) : [], caddyfile_replaced: typeof manifest.caddyfile === 'string', reloaded: !!tx.reloaded, reload_error: tx.reloadError || null, previous_caddyfile_backup: previousCaddyfile !== null }

  // Database restore is a separate, deliberate act: the SQLite file cannot
  // be swapped under a running server. Refuse unless the caller explicitly
  // confirmed services are stopped.
  const dbCopy = resolved.replace(/\.json$/, '.db')
  if (restoreDatabase) {
    if (!fs.existsSync(dbCopy)) {
      result.database = { ok: false, error: `No database sibling found next to this backup (expected ${path.basename(dbCopy)}).` }
    } else {
      result.database = {
        ok: false,
        requires_stopped_services: true,
        file: dbCopy,
        instruction: 'Stop CatWAF (systemctl stop catwaf or catwaf stop), then run with --confirm-db-restore to copy it into place, then start again.',
      }
    }
  }
  return result
}

function confirmDatabaseRestore(filePath) {
  const resolved = path.resolve(String(filePath || ''))
  let dbCopy = resolved.replace(/\.json$/, '.db')
  let staged = null
  if (!fs.existsSync(dbCopy) || isEncrypted(dbCopy)) {
    // Encrypted database copy: decrypt next to it first.
    const enc = dbCopy + '.enc'
    if (!fs.existsSync(enc) && !fs.existsSync(dbCopy)) {
      return { ok: false, error: `No database file at ${dbCopy} (or ${path.basename(enc)})` }
    }
    try {
      staged = dbCopy + '.restore-plain'
      fs.writeFileSync(staged, decryptFileToBuffer(fs.existsSync(enc) ? enc : dbCopy), { mode: 0o600 })
    } catch (e) {
      try { fs.unlinkSync(staged) } catch {}
      return { ok: false, error: `Decrypt failed: ${e.message}` }
    }
    dbCopy = staged
  }
  const target = require('./db').DB_PATH

  // Refuse when the running server looks active: a hot WAL means SQLite has
  // open handles and copying over them corrupts both copies.
  const wal = target + '-wal'
  try {
    const st = fs.statSync(wal)
    if (Date.now() - st.mtimeMs < 15_000 && st.size > 0) {
      return { ok: false, error: 'The live database was written within the last 15 seconds — CatWAF appears to still be running. Stop it first (systemctl stop catwaf / catwaf stop), then retry.' }
    }
  } catch { /* no wal — nothing running */ }

  try {
    // Stage then rename so the target path is never a half-copied file.
    // Sidecars are removed rather than copied: the backup .db is
    // self-consistent on its own, and pairing it with OUR stale wal would
    // replay old frames over it.
    for (const suffix of ['-wal', '-shm']) {
      try { fs.unlinkSync(target + suffix) } catch {}
    }
    const tmp = target + '.restore-tmp'
    fs.copyFileSync(dbCopy, tmp)
    const fd = fs.openSync(tmp, 'r+')
    fs.fsyncSync(fd)
    fs.closeSync(fd)
    fs.renameSync(tmp, target)
    if (staged) { try { fs.unlinkSync(staged) } catch {} }
    try { fs.chmodSync(target, 0o600) } catch {}
    return { ok: true, restored: target }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}


// ── Backup encryption ───────────────────────────────────────────────────
//
// AES-256-CBC with PBKDF2 key derivation through the openssl CLI CatWAF
// already depends on. The passphrase comes from CATWAF_BACKUP_PASSPHRASE in
// .env — it is deliberately NOT stored in the database, because a backup
// that can be decrypted by the same database it protects is not encrypted
// in any meaningful sense.
const SALT_MAGIC = 'Salted__'

function passphrase() {
  const p = process.env.CATWAF_BACKUP_PASSPHRASE
  return (p && p.length >= 8) ? p : null
}

function requirePassphrase() {
  const p = passphrase()
  if (!p) {
    throw new Error('CATWAF_BACKUP_PASSPHRASE is not set (or shorter than 8 characters). Add it to .env — backups must be decryptable by something other than the database they protect.')
  }
  return p
}

function opensslEnc(args, input) {
  return execFileSync('openssl', ['enc', '-aes-256-cbc', '-pbkdf2', '-iter', '200000', ...args],
    { input, stdio: ['pipe', 'pipe', 'pipe'], timeout: 60_000, env: { ...process.env, CATWAF_BACKUP_PASSPHRASE: requirePassphrase() }, maxBuffer: 512 * 1024 * 1024 })
}

function encryptBufferToFile(plainBuf, destPath) {
  requirePassphrase()
  const out = opensslEnc(['-salt', '-pass', 'env:CATWAF_BACKUP_PASSPHRASE'], plainBuf)
  fs.writeFileSync(destPath, out, { mode: 0o600 })
}

function decryptFileToBuffer(encPath) {
  const raw = fs.readFileSync(encPath)
  if (raw.subarray(0, 8).toString('latin1') !== SALT_MAGIC) {
    throw new Error('File is not an OpenSSL-encrypted backup.')
  }
  return opensslEnc(['-d', '-pass', 'env:CATWAF_BACKUP_PASSPHRASE'], raw)
}

function isEncrypted(filePath) {
  try {
    const fd = fs.openSync(filePath, 'r')
    const head = Buffer.alloc(8)
    fs.readSync(fd, head, 0, 8, 0)
    fs.closeSync(fd)
    return head.toString('latin1') === SALT_MAGIC
  } catch { return false }
}

module.exports = { run, list, prune, buildPayload, verifyDestination, restoreFromFile, confirmDatabaseRestore, encryptBufferToFile, decryptFileToBuffer, isEncrypted, FILE_RE }
