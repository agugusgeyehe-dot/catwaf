// alertDispatch.js — the delivery half of the Alerts page.
//
// Until now the webhook URLs and thresholds on that page were stored and
// testable but nothing ever sent them: an operator configured Slack and
// believed they would hear about an attack. This module is the sender. It
// watches three signals — blocked-request spikes, new automatic bans, and
// engine/mode changes — and delivers through whatever channel(s) are
// configured, with a per-kind cooldown so an ongoing attack produces one
// alert, not four thousand.

const settings = require('./settings')
const state = require('./state')
const netGuard = require('./netGuard')
const logger = require('./logger')

const log = logger.child('alerts')

const STATE_KEY = 'alert_dispatch_state'
const TELEGRAM_API = 'https://api.telegram.org'

function loadState() {
  const stored = require('./db').getState(STATE_KEY)
  return stored && typeof stored === 'object' ? stored : {}
}
function saveState(s) { require('./db').setState(STATE_KEY, s) }

// ── Pure builders (exported for tests) ────────────────────────────────

function formatAlert(kind, details = {}, ctx = {}) {
  const when = new Date().toISOString()
  switch (kind) {
    case 'spike':
      return `[CatWAF] Attack spike — ${details.blocked} blocked requests in ${details.windowMin} min` +
        (details.topType ? ` (top: ${details.topType})` : '') + ` — ${when}`
    case 'new_ban':
      return `[CatWAF] New ban: ${details.target} (${details.source})${details.reason ? ` — ${details.reason}` : ''} — ${when}`
    case 'engine_change':
      return `[CatWAF] Engine changed: ${details.from} → ${details.to} — ${when}`
    case 'test':
      return `[CatWAF] Test alert — ${when}`
    default:
      return `[CatWAF] ${kind} — ${when}`
  }
}

// Which channels have something configured to send to.
function readyChannels(alerts = {}) {
  const out = []
  if (alerts.slack_webhook) out.push({ id: 'slack', url: alerts.slack_webhook, style: 'both' })
  if (alerts.discord_webhook) out.push({ id: 'discord', url: alerts.discord_webhook, style: 'both' })
  if (alerts.custom_webhook) out.push({ id: 'custom', url: alerts.custom_webhook, style: 'both' })
  if (alerts.telegram_bot_token && alerts.telegram_chat_id) {
    out.push({ id: 'telegram', token: alerts.telegram_bot_token, chatId: alerts.telegram_chat_id, style: 'telegram' })
  }
  return out
}

// ── Delivery ──────────────────────────────────────────────────────────

async function deliverOne(channel, text) {
  if (channel.style === 'telegram') {
    const url = `${TELEGRAM_API}/bot${channel.token}/sendMessage`
    const { response } = await netGuard.guardedFetch(url, {
      method: 'POST',
      timeoutMs: 8000,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: channel.chatId, text }),
    })
    return response.ok
  }
  const { response } = await netGuard.guardedFetch(channel.url, {
    method: 'POST',
    timeoutMs: 8000,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content: text, text }),
  })
  return response.ok
}

// Fan out to every ready channel; per-channel failures are recorded, not
// fatal — one broken webhook must not silence the others.
async function broadcast(text) {
  const alerts = state.WAF.alerts || {}
  const results = []
  for (const channel of readyChannels(alerts)) {
    try {
      const ok = await deliverOne(channel, text)
      results.push({ channel: channel.id, ok })
    } catch (e) {
      results.push({ channel: channel.id, ok: false, error: e.message })
    }
  }
  return results
}

// Cooldown gate, serialized across processes (API server and CLI jobs both
// evaluate): returns true if `kind` may fire right now, records it, and can
// refund the claim when delivery fails everywhere — an attack that outlives
// one broken webhook must not be silent for its whole duration.
function claimCooldown(kind, cfg) {
  const configLock = require('./configLock')
  return configLock.withConfigLock(() => {
    const s = loadState()
    const now = Date.now()
    const gap = Math.max(1, cfg.cooldown_min) * 60_000
    if (s[kind] && now - s[kind] < gap) return false
    s[kind] = now
    saveState(s)
    return true
  })
}

function refundCooldown(kind) {
  const s = loadState()
  delete s[kind]
  saveState(s)
}

async function fire(kind, details) {
  const cfg = settings.get('alert_dispatch')
  const alerts = state.WAF.alerts || {}
  if (!cfg.enabled || !readyChannels(alerts).length) return { sent: false, reason: 'disabled or no channel' }

  // The spike threshold lives with the legacy alert settings.
  const text = formatAlert(kind, details, { spikeThreshold: alerts.spike_threshold })
  if (!claimCooldown(kind, cfg)) return { sent: false, reason: 'cooldown' }
  const results = await broadcast(text)
  const delivered = results.filter(r => r.ok).length
  try { require('./counters').incr(`alerts_delivered_${kind}`, delivered) } catch {}
  // Every channel failed: refund so the next evaluation retries instead of
  // staying silent for the whole cooldown window.
  if (results.length > 0 && delivered === 0) refundCooldown(kind)
  log.info(`Alert "${kind}" delivered to ${delivered}/${results.length} channels`)
  return { sent: delivered > 0, delivered, results, text }
}

// ── Signal evaluation (called by the scheduler) ───────────────────────

async function evaluateSpike() {
  const cfg = settings.get('alert_dispatch')
  if (!cfg.enabled || !cfg.on_spike) return { ok: true, skipped: 'off' }
  const alerts = state.WAF.alerts || {}
  const threshold = Number(alerts.spike_threshold) > 0 ? Number(alerts.spike_threshold) : 100
  const windowMin = Math.max(1, cfg.spike_window_min)

  // summarize() answers exactly this shape (windowed totals + per-type
  // breakdown) with three indexed queries.
  const summary = require('./requestLog').summarize({ sinceMs: windowMin * 60_000 })
  const blocked = Number(summary.blocked_requests) || 0
  if (blocked < threshold) return { ok: true, spiked: false, blocked }

  let top = null
  for (const row of summary.top_attack_types || []) {
    if (!top || Number(row.count) > Number(top.count)) top = row
  }
  return fire('spike', { blocked, windowMin, topType: top ? top.attack_type : null })
}

// Engine/mode change detection: compare live values against what we last
// announced. First run after enable announces nothing (no false alarm on a
// fresh install).
let lastKnownEngine
function checkEngineChange() {
  const cfg = settings.get('alert_dispatch')
  if (!cfg.enabled || !cfg.on_engine_change) return { skipped: 'off' }
  const mode = require('./modes').current?.() || {}
  const current = `${state.WAF.engine}/${mode.mode || mode.key || ''}`.replace(/\/$/, '')
  if (lastKnownEngine === undefined) { lastKnownEngine = current; return { skipped: 'first-run' } }
  if (current !== lastKnownEngine) {
    const from = lastKnownEngine.split('/')[0]
    const to = current.split('/')[0]
    lastKnownEngine = current
    if (from !== to) return fire('engine_change', { from, to })
    lastKnownEngine = current
  }
  return { ok: true, unchanged: true }
}

// Called synchronously from bans.ban() via the change-listener registry.
function onBanChange(kind, detail) {
  const cfg = settings.get('alert_dispatch')
  if (!cfg.enabled || !cfg.on_new_ban) return
  if (kind !== 'add' && kind !== 'extend') return
  if (detail.source === 'manual') return // operator already knows
  fire('new_ban', { target: detail.target, source: detail.source }).catch(() => {})
}

function status() {
  const cfg = settings.get('alert_dispatch')
  return {
    ...cfg,
    ready_channels: readyChannels(state.WAF.alerts || {}).map(c => c.id),
    last_sent: loadState(),
  }
}

module.exports = { formatAlert, readyChannels, broadcast, fire, evaluateSpike, checkEngineChange, onBanChange, status, claimCooldown, refundCooldown, _internals: { loadState, saveState, STATE_KEY } }
