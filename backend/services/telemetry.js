// telemetry.js — anonymous usage statistics, off unless switched on
// (idea #47).
//
// This is less a feature than a trust signal, and it is implemented in the
// order that makes the signal real: the toggle, the exact payload, and a
// preview of it exist now; the collector does not. Nothing is sent unless an
// operator both enables the toggle *and* supplies an endpoint, so "enabled"
// can never quietly mean "sending to whoever the project chose".
//
// buildPayload() is the whole contract. The dashboard renders its output
// directly rather than a prose description, so what is documented cannot
// drift from what is sent.

const db = require('./db')
const state = require('./state')
const settings = require('./settings')
const netGuard = require('./netGuard')
const secrets = require('./secrets')
const edition = require('./edition')
const { version: pkgVersion } = require('../../package.json')

const LAST_SENT_KEY = 'telemetry_last_sent'

// Volume is reported as an order of magnitude, never as a number: "this
// install serves thousands of requests a day" is useful for prioritising
// work; the exact figure is the site's business.
function bucket(n) {
  if (n <= 0) return '0'
  if (n < 100) return '<100'
  if (n < 1000) return '100-1k'
  if (n < 10000) return '1k-10k'
  if (n < 100000) return '10k-100k'
  return '100k+'
}

function enabledFeatures() {
  const out = []
  for (const group of settings.GROUP_NAMES) {
    const cfg = settings.get(group)
    if (Object.hasOwn(cfg, 'enabled') && cfg.enabled) out.push(group)
    else if (group === 'challenge' && cfg.mode !== 'off') out.push('challenge')
    else if (group === 'headers' && cfg.preset !== 'off') out.push('headers')
    else if (group === 'origin' && cfg.type !== 'reverse-proxy') out.push(`origin:${cfg.type}`)
  }
  return out
}

function buildPayload() {
  const cfg = settings.get('telemetry')
  const payload = {
    // A stable, rotating pseudonym — enough to count installs without
    // identifying one. Derived from the local secret and the calendar
    // quarter, so it cannot be correlated across a long period.
    install: secrets.derive('telemetry', new Date().toISOString().slice(0, 7)).slice(0, 24),
    sent_at: new Date().toISOString(),
  }

  if (cfg.include_version) {
    payload.version = pkgVersion
    payload.edition = edition.current()
    payload.node = process.version
    payload.platform = process.platform
  }
  if (cfg.include_feature_flags) {
    payload.features = enabledFeatures()
    payload.engine = state.WAF.engine
    payload.paranoia_level = state.WAF.paranoia_level
  }
  if (cfg.include_counts) {
    const since = new Date(Date.now() - 86_400_000).toISOString()
    const conn = db.getDb()
    payload.requests_24h = bucket(conn.prepare('SELECT COUNT(*) AS n FROM request_log WHERE ts > ?').get(since).n)
    payload.blocked_24h = bucket(conn.prepare("SELECT COUNT(*) AS n FROM request_log WHERE ts > ? AND action='block'").get(since).n)
  }
  return payload
}

async function send({ dryRun = false } = {}) {
  const cfg = settings.get('telemetry')
  if (!cfg.enabled) return { ok: true, skipped: 'disabled', changed: false }
  if (!cfg.endpoint) return { ok: false, error: 'Telemetry is enabled but no collector endpoint is configured, so nothing is being sent.' }

  const payload = buildPayload()
  if (dryRun) return { ok: true, dryRun: true, payload }

  const { response } = await netGuard.guardedFetch(cfg.endpoint, {
    method: 'POST',
    timeoutMs: 10000,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!response.ok) throw new Error(`Collector returned ${response.status}`)
  db.setState(LAST_SENT_KEY, new Date().toISOString())
  return { ok: true, sent: true, changed: false }
}

function status() {
  const cfg = settings.get('telemetry')
  return {
    enabled: cfg.enabled,
    endpoint_configured: !!cfg.endpoint,
    last_sent: db.getState(LAST_SENT_KEY) || null,
    // The real thing, computed now — not a description of it.
    payload_preview: buildPayload(),
    never_collected: [
      'Request bodies, URLs, headers or any traffic content',
      'Your domain, hostnames, IP addresses or certificates',
      'Admin usernames, emails or credentials',
      'Rule text, custom rules or exclusions you have written',
    ],
  }
}

module.exports = { send, status, buildPayload, enabledFeatures, bucket, LAST_SENT_KEY }
