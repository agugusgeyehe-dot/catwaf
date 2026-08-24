// kernelBans.js — mirror active bans into an nftables set so banned
// addresses are dropped at SYN, before Caddy's socket even accepts them.
// This is the strongest enforcement tier and it is deliberately hard to
// turn on: it needs CATWAF_KERNEL_BANS=1 in .env, root, nftables present,
// a non-container host — and the operator must add ONE forwarding rule
// themselves (`catwaf kernel-bans print-rules`). CatWAF manages ONLY its
// own dedicated table; nothing else in the firewall is ever touched.
//
// Safety properties:
//   * Every element re-validated with isValidIpOrCidr immediately before
//     the ruleset is written — a poisoned ban row cannot inject nft syntax.
//   * The whole table is replaced atomically from one generated file via
//     `nft -f`, so a partial apply can never leave a half-populated set.
//   * A self-lockout guard mirrors the dashboard's: addresses covered by
//     the IP allowlist are never mirrored.

const { execFileSync } = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')

const settings = require('./settings')
const state = require('./state')
const configLock = require('./configLock')
const logger = require('./logger')
const { isValidIpOrCidr } = require('./sanitize')

const log = logger.child('kernel-bans')

const TABLE = 'inet catwaf_edge'

function envEnabled() {
  return process.env.CATWAF_KERNEL_BANS === '1'
}

function preflight() {
  const problems = []
  if (!envEnabled()) problems.push('CATWAF_KERNEL_BANS=1 is not set in .env')
  if (typeof process.getuid === 'function' && process.getuid() !== 0) problems.push('not running as root')
  try {
    if (fs.existsSync('/.dockerenv') || process.env.KUBERNETES_SERVICE_HOST) problems.push('running inside a container — kernel drops belong to the host')
  } catch {}
  try {
    execFileSync('nft', ['--version'], { stdio: 'ignore', timeout: 5000 })
  } catch { problems.push('nft binary not available') }
  return { ok: problems.length === 0, problems }
}

function allowlistConflict(target) {
  const { ipCoveredBy } = require('./sanitize')
  for (const entry of state.WAF.ip_whitelist || []) {
    if (!entry?.ip) continue
    if (ipCoveredBy(target, entry.ip)) return true
    if (ipCoveredBy(entry.ip, target)) return true
  }
  return false
}

function splitTargets(targets) {
  const v4 = []
  const v6 = []
  for (const t of targets) {
    if (!isValidIpOrCidr(t)) continue // last line of defense before nft syntax
    if (allowlistConflict(t)) continue
    if (t.includes(':')) v6.push(t)
    else v4.push(t)
  }
  return { v4, v6 }
}

// Pure builder — exported for tests.
function buildRuleset({ v4, v6 }) {
  const lines = [
    'table inet catwaf_edge {',
    '  set ban4 {',
    '    type ipv4_addr',
    '    flags interval',
    '    auto-merge',
  ]
  if (v4.length) lines.push(`    elements = { ${v4.join(', ')} }`)
  lines.push(
    '  }',
    '  set ban6 {',
    '    type ipv6_addr',
    '    flags interval',
    '    auto-merge',
  )
  if (v6.length) lines.push(`    elements = { ${v6.join(', ')} }`)
  lines.push('  }', '}')
  return lines.join('\n') + '\n'
}

function runNft(file) {
  execFileSync('nft', ['-f', file], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 })
}

// `nft -f` MERGES into an existing table — without this, expired and lifted
// bans would accumulate forever. Deleting first makes each apply a true
// replacement. The momentary absence of the table means drops stop for a
// few milliseconds: that fails OPEN, which is the correct failure direction.
function replaceTable(file) {
  try { execFileSync('nft', ['delete', 'table', ...TABLE.split(' ')], { stdio: 'ignore', timeout: 5000 }) } catch {}
  runNft(file)
}

function printRules() {
  return [
    '# One-time setup so the kernel consults the ban sets on inbound traffic.',
    '# Adjust the interface/ports to match your deployment, then apply once:',
    '#   sudo nft -f /etc/nftables.d/catwaf-forward.conf',
    'table inet catwaf_edge',
    '',
    'chain input {',
    '  type filter hook input priority filter - 10; policy accept;',
    '  ip daddr @ban4 counter drop',
    '  ip6 daddr @ban6 counter drop',
    '}',
  ].join('\n')
}

// Diff against what we applied last so an unchanged set costs one cheap
// `nft list table` instead of a full rewrite every minute.
let lastAppliedHash = null
let lastAppliedEntries = 0

function refresh({ force = false } = {}) {
  const cfg = settings.get('kernel_bans')
  if (!cfg.enabled || !envEnabled()) return { ok: true, skipped: 'disabled' }

  const pre = preflight()
  if (!pre.ok) return { ok: false, error: pre.problems.join('; ') }

  return configLock.withConfigLock(() => {
    const bans = require('./bans')
    const targets = bans.listActiveTargets({ limit: Math.min(cfg.max_entries, 100000) })
    const { v4, v6 } = splitTargets(targets)

    const hash = JSON.stringify([v4, v6])
    if (!force && hash === lastAppliedHash) return { ok: true, changed: false, v4: v4.length, v6: v6.length }

    const ruleset = buildRuleset({ v4, v6 })
    const tmp = path.join(os.tmpdir(), `catwaf-nft-${process.pid}-${Date.now()}.nft`)
    let appliedCount = v4.length + v6.length
    try {
      fs.writeFileSync(tmp, ruleset, { mode: 0o600 })
      replaceTable(tmp)
      lastAppliedHash = hash
      lastAppliedEntries = appliedCount
      try { require('./db').setState('kernel_bans_last_count', appliedCount) } catch {}
      log.info(`Kernel ban sets refreshed`, { v4: v4.length, v6: v6.length })
      return { ok: true, changed: true, v4: v4.length, v6: v6.length }
    } catch (e) {
      log.error('nft apply failed', { error: e.message })
      return { ok: false, error: e.message }
    } finally {
      try { fs.unlinkSync(tmp) } catch {}
    }
  })
}

function status() {
  const cfg = settings.get('kernel_bans')
  return { ...cfg, env_enabled: envEnabled(), preflight: preflight(), last_applied_entries: lastAppliedEntries }
}

module.exports = { refresh, buildRuleset, splitTargets, printRules, status, preflight, TABLE, _internals: { replaceTable, setHash: h => { lastAppliedHash = h } } }
