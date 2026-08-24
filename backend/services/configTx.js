const fs = require('fs')
const path = require('path')
const { execFileSync } = require('child_process')

const state = require('./state')
const caddySvc = require('./caddy')
const configLock = require('./configLock')
const auditSvc = require('./audit')
const db = require('./db')

const MAX_BACKUPS = 20

function backupDir() {
  const dir = path.join(path.dirname(db.DB_PATH), 'backups')
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  return dir
}

function pruneBackups() {
  try {
    const dir = backupDir()
    const files = fs.readdirSync(dir)
      .filter(f => f.startsWith('Caddyfile.'))
      .map(f => ({ f, t: fs.statSync(path.join(dir, f)).mtimeMs }))
      .sort((a, b) => b.t - a.t)
    for (const extra of files.slice(MAX_BACKUPS)) {
      try { fs.unlinkSync(path.join(dir, extra.f)) } catch {}
    }
  } catch {}
}

function backupCaddyfile() {
  const src = caddySvc.CADDYFILE_PATH
  if (!fs.existsSync(src)) return null
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const dest = path.join(backupDir(), `Caddyfile.${stamp}`)
  fs.copyFileSync(src, dest)
  try { fs.chmodSync(dest, 0o600) } catch {}
  pruneBackups()
  return dest
}

function validateCaddyfile(filePath) {
  try {
    execFileSync('caddy', ['validate', '--config', filePath, '--adapter', 'caddyfile'], {
      timeout: 25000,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    return { ok: true, error: null }
  } catch (e) {
    const out = (e.stderr?.toString() || e.stdout?.toString() || e.message || '')
    if (/ENOENT/.test(out) || e.code === 'ENOENT') return { ok: true, error: null, skipped: 'caddy binary not available' }
    const line = out.split('\n').map(l => l.trim()).find(l => /^Error:|error:/i.test(l))
    return { ok: false, error: line || out.split('\n')[0] || 'validation failed' }
  }
}

function snapshotWaf() {
  return JSON.parse(JSON.stringify({
    WAF: state.WAF,
    RULE_CATEGORIES: state.RULE_CATEGORIES,
    // The extended settings groups (services/settings) render into the same
    // Caddyfile, so a rollback that restored only state.WAF would leave a
    // half-applied configuration behind.
    SETTINGS: state.settings.snapshot(),
  }))
}

// Keys that must never be copied back onto a live object: a persisted
// snapshot carrying an own "__proto__" property would survive the JSON
// round-trip above, and Object.assign's [[Set]] semantics would turn it into
// an actual prototype change on state.WAF.
const UNSAFE_RESTORE_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

function safeAssign(target, source) {
  for (const [key, value] of Object.entries(source)) {
    if (UNSAFE_RESTORE_KEYS.has(key)) continue
    target[key] = value
  }
  return target
}

function restoreWaf(snap) {
  for (const key of Object.keys(state.WAF)) delete state.WAF[key]
  safeAssign(state.WAF, snap.WAF)
  for (const key of Object.keys(state.RULE_CATEGORIES)) delete state.RULE_CATEGORIES[key]
  safeAssign(state.RULE_CATEGORIES, snap.RULE_CATEGORIES)
  if (snap.SETTINGS) state.settings.restore(snap.SETTINGS)
  db.setState('waf', state.WAF)
  db.setState('rule_categories', state.RULE_CATEGORIES)
}

function apply({ label, req = null, mutate, validate = null, reload = true }) {
  // One writer at a time, across processes: snapshot → mutate → persist →
  // render → validate → reload must never interleave with a CLI invocation
  // or a scheduled job doing the same. patchWAFCaddyfile takes the same
  // lock internally (re-entrant here), and atomicWriteFileSync guarantees a
  // reader on another process never sees a torn Caddyfile.
  return configLock.withConfigLock(() => {
  // Coraza opens SecAuditLog when the config is provisioned, so the audit
  // log has to exist before `caddy validate` runs — otherwise every WAF
  // change fails on a clean install. Idempotent.
  const auditLog = caddySvc.ensureAuditLog()
  if (!auditLog.ok) {
    return { ok: false, phase: 'audit-log', error: auditLog.error }
  }

  const before = snapshotWaf()
  const caddyfilePath = caddySvc.CADDYFILE_PATH
  const hadCaddyfile = fs.existsSync(caddyfilePath)
  const previousCaddyfile = hadCaddyfile ? fs.readFileSync(caddyfilePath, 'utf8') : null

  let backup = null
  try {
    backup = backupCaddyfile()
  } catch (e) {
    return { ok: false, phase: 'backup', error: `Could not back up the Caddyfile: ${e.message}` }
  }

  const rollback = () => {
    restoreWaf(before)
    try {
      if (previousCaddyfile !== null) configLock.atomicWriteFileSync(caddyfilePath, previousCaddyfile, { mode: 0o644 })
      else if (fs.existsSync(caddyfilePath)) fs.unlinkSync(caddyfilePath)
    } catch {}
  }

  let mutateResult
  try {
    mutateResult = mutate(state)
  } catch (e) {
    rollback()
    return { ok: false, phase: 'mutate', error: e.message, rolledBack: true, backup }
  }

  if (validate) {
    const v = validate(state)
    if (v && v.ok === false) {
      rollback()
      return { ok: false, phase: 'validate', error: v.error || 'validation failed', rolledBack: true, backup }
    }
  }

  try {
    db.setState('waf', state.WAF)
    db.setState('rule_categories', state.RULE_CATEGORIES)
  } catch (e) {
    rollback()
    return { ok: false, phase: 'persist', error: e.message, rolledBack: true, backup }
  }

  try {
    caddySvc.patchWAFCaddyfile(state.WAF)
  } catch (e) {
    rollback()
    return { ok: false, phase: 'render', error: e.message, rolledBack: true, backup }
  }

  const validation = validateCaddyfile(caddyfilePath)
  if (!validation.ok) {
    rollback()
    auditSvc.audit(req, `${label}.rollback`, '', { reason: 'invalid config', error: validation.error })
    return {
      ok: false,
      phase: 'caddy-validate',
      error: validation.error,
      rolledBack: true,
      backup,
      message: 'Configuration validation failed. CatWAF did not activate the new configuration. Previous configuration has been preserved.',
    }
  }

  let reloaded = false
  let reloadError = null
  if (reload) {
    const r = caddySvc.reloadCaddy()
    reloaded = !!r.reloaded
    reloadError = r.reloaded ? null : (r.error || 'reload failed')

    if (!reloaded && caddySvc.isCaddyRunning()) {
      rollback()
      try { caddySvc.patchWAFCaddyfile(state.WAF) } catch {}
      caddySvc.reloadCaddy()
      auditSvc.audit(req, `${label}.rollback`, '', { reason: 'reload failed', error: reloadError })
      return {
        ok: false,
        phase: 'reload',
        error: reloadError,
        rolledBack: true,
        backup,
        message: 'Caddy refused to reload the new configuration. CatWAF rolled back and restored the previous configuration.',
      }
    }
  }

  auditSvc.audit(req, label, '', {
    reloaded,
    engine: state.WAF.engine,
    paranoia_level: state.WAF.paranoia_level,
    ...(mutateResult && typeof mutateResult === 'object' ? { detail: mutateResult } : {}),
  })

    return {
      ok: true,
      reloaded,
      reloadError,
      backup,
      validationSkipped: validation.skipped || null,
      result: mutateResult,
    }
  })
}

module.exports = {
  apply,
  backupCaddyfile,
  validateCaddyfile,
  snapshotWaf,
  restoreWaf,
  backupDir,
}
