// intel/network.js — the opt-in shared threat network (idea #12).
//
// A single CatWAF install only ever learns from its own traffic. If enough
// installs opt in, every install's attack log becomes protection for every
// other one. That is worth having, and it is also the idea in this folder
// with the largest privacy surface — so the shape here is deliberately
// conservative:
//
//   * Off unless explicitly enabled, with sharing and consuming as two
//     separate switches (consume without sharing is a valid choice).
//   * DATA_POLICY below is the exhaustive list of what a submission
//     contains, it is what buildSubmission() actually produces, and the API
//     exposes it so the dashboard shows the real thing rather than prose
//     that could drift from the code.
//   * No endpoint is baked in. CatWAF does not ship pointing at a server;
//     an operator supplies one, which keeps "enabled" from ever meaning
//     "sending data to whoever the vendor chose".

const crypto = require('crypto')

const cache = require('./cache')
const db = require('../db')
const settings = require('../settings')
const netGuard = require('../netGuard')
const secrets = require('../secrets')
const { normalizeClientIp } = require('../sanitize')

const NS = 'threat-network'
const CURSOR_KEY = 'threat_network_cursor'

// The exhaustive contract. Anything not listed here is not sent, and
// buildSubmission() is written to make that checkable rather than trusted.
const DATA_POLICY = {
  sends: [
    { field: 'ip', detail: 'The attacking client address — the whole point of the exchange.' },
    { field: 'category', detail: 'The CRS attack category (SQLi, XSS, LFI, …). No rule text, no matched values.' },
    { field: 'ts', detail: 'When it happened, truncated to the hour.' },
    { field: 'count', detail: 'How many times, bucketed.' },
    { field: 'instance', detail: 'A rotating pseudonymous id derived from this install\'s secret. It identifies a submitter for abuse-resistance without naming the site.' },
  ],
  never_sends: [
    'Request bodies, headers, cookies or query strings',
    'The protected site\'s hostname, domain or URLs',
    'Your admin account, licence or contact details',
    'Anything about traffic that was not blocked',
  ],
}

// Derived from the install's own root secret, so a submitter can be rate
// limited or scored by a collector without the collector learning which site
// it is. Rotates monthly so a long-lived identifier cannot accumulate.
function instanceId() {
  const period = new Date().toISOString().slice(0, 7)
  return secrets.derive('threat-network', period).slice(0, 32)
}

function bucketCount(n) {
  if (n <= 1) return 1
  if (n <= 5) return 5
  if (n <= 20) return 20
  if (n <= 100) return 100
  return 500
}

function truncateToHour(iso) {
  return `${String(iso).slice(0, 13)}:00:00Z`
}

// Reads blocked requests since the last submission and reduces them to the
// five fields in DATA_POLICY. Exported so the dashboard can show exactly
// what the next submission would contain *before* sharing is switched on.
function buildSubmission({ limit = 500 } = {}) {
  const since = db.getState(CURSOR_KEY) || new Date(Date.now() - 3600_000).toISOString()
  const rows = db.getDb().prepare(`
    SELECT ip, attack_type, ts FROM request_log
    WHERE action = 'block' AND ts > ? AND ip IS NOT NULL AND ip != ''
    ORDER BY ts ASC LIMIT ?
  `).all(since, limit)

  const grouped = new Map()
  let newest = since
  for (const row of rows) {
    if (row.ts > newest) newest = row.ts
    const ip = normalizeClientIp(row.ip)
    if (!ip || !netGuard.isPubliclyRoutable(ip)) continue
    const key = `${ip}|${row.attack_type || 'unknown'}|${truncateToHour(row.ts)}`
    grouped.set(key, (grouped.get(key) || 0) + 1)
  }

  const signals = [...grouped.entries()].map(([key, count]) => {
    const [ip, category, ts] = key.split('|')
    return { ip, category, ts, count: bucketCount(count) }
  })

  return { instance: instanceId(), signals, cursor: newest, considered: rows.length }
}

async function submit({ dryRun = false } = {}) {
  const cfg = settings.get('threat_network')
  if (!cfg.enabled || !cfg.share) return { ok: true, skipped: 'sharing disabled' }
  if (!cfg.endpoint) return { ok: false, error: 'No network endpoint configured.' }

  const payload = buildSubmission()
  if (!payload.signals.length) return { ok: true, submitted: 0, changed: false }
  if (dryRun) return { ok: true, dryRun: true, submitted: payload.signals.length, payload }

  const headers = { 'Content-Type': 'application/json' }
  if (cfg.api_key) headers.Authorization = `Bearer ${cfg.api_key}`

  const url = new URL('/v1/signals', cfg.endpoint).toString()
  const { response } = await netGuard.guardedFetch(url, {
    method: 'POST', timeoutMs: 15000, headers, body: JSON.stringify(payload),
  }).catch(e => { throw new Error(`Could not reach the threat network: ${e.message}`) })

  if (!response.ok) throw new Error(`Threat network returned ${response.status}`)
  db.setState(CURSOR_KEY, payload.cursor)
  return { ok: true, submitted: payload.signals.length, changed: true }
}

async function consult(ip) {
  const cfg = settings.get('threat_network')
  if (!cfg.enabled || !cfg.consume || !cfg.endpoint) return null
  const addr = normalizeClientIp(String(ip || '').trim())
  if (!addr || !netGuard.isPubliclyRoutable(addr)) return null

  return cache.through(NS, addr, 30 * 60 * 1000, async () => {
    const url = new URL(`/v1/reputation/${encodeURIComponent(addr)}`, cfg.endpoint).toString()
    const headers = { Accept: 'application/json' }
    if (cfg.api_key) headers.Authorization = `Bearer ${cfg.api_key}`
    try {
      const { response } = await netGuard.guardedFetch(url, { timeoutMs: 2000, headers })
      if (!response.ok) return null
      const data = await response.json().catch(() => null)
      if (!data || typeof data.score !== 'number') return null
      return { score: Math.max(0, Math.min(100, data.score)), categories: Array.isArray(data.categories) ? data.categories.slice(0, 10) : [], reports: Number(data.reports) || 0 }
    } catch {
      return null
    }
  })
}

async function evaluate(ip) {
  const cfg = settings.get('threat_network')
  if (!cfg.enabled || !cfg.consume) return null
  let rep = null
  try { rep = await consult(ip) } catch { return null }
  if (!rep || rep.score < cfg.min_confidence) return null
  return {
    decision: cfg.consume_action === 'ban' ? 'ban' : cfg.consume_action === 'flag' ? 'flag' : 'challenge',
    source: 'threat_network',
    banSeconds: 3600,
    reason: `Reported by ${rep.reports || 'other'} CatWAF instance(s) with a confidence of ${rep.score}${rep.categories.length ? ` (${rep.categories.join(', ')})` : ''}.`,
  }
}

function status() {
  const cfg = settings.get('threat_network')
  const preview = buildSubmission({ limit: 25 })
  return {
    enabled: cfg.enabled,
    sharing: cfg.share,
    consuming: cfg.consume,
    endpoint_configured: !!cfg.endpoint,
    instance_id: cfg.enabled ? instanceId() : null,
    data_policy: DATA_POLICY,
    // What would leave this machine on the next submission, computed from
    // real data so the preview cannot drift from the implementation.
    next_submission_preview: { count: preview.signals.length, sample: preview.signals.slice(0, 5) },
  }
}

module.exports = { submit, consult, evaluate, status, buildSubmission, instanceId, DATA_POLICY, NS, CURSOR_KEY }
