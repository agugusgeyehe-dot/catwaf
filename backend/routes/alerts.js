
const express = require('express')
const router = express.Router()
const state = require('../services/state')
const auditSvc = require('../services/audit')
const { writeRequired } = require('../middleware/auth')
const snapshots = require('../services/snapshots')
const netGuard = require('../services/netGuard')

// Webhook URLs and bot tokens are credentials — anyone holding them can post
// as this CatWAF instance into the operator's Slack/Discord/Telegram. They
// are stored in state.WAF.alerts, but they must not be handed to viewer-role
// sessions (or rendered back after a save): every other secret in the panel
// goes through the write-only settings pattern or redactSecrets().
function redactedAlerts() {
  return snapshots.redactSecrets(state.WAF.alerts)
}

router.get('/api/alerts', (req, res) => res.json(req.user.role === 'admin' ? state.WAF.alerts : redactedAlerts()))

// Field allowlist: this was the one write path that merged arbitrary
// request keys into persisted config. Unknown keys now bounce instead of
// living forever in waf_state and leaking back out through reads.
const ALERT_FIELDS = new Set([
  'slack_webhook', 'email_to', 'custom_webhook', 'telegram_bot_token',
  'telegram_chat_id', 'discord_webhook', 'spike_threshold',
  'alert_on_block', 'alert_on_spike', 'alert_on_engine_change',
])
const ALERT_STRING_FIELDS = new Set(['slack_webhook', 'email_to', 'custom_webhook', 'telegram_bot_token', 'telegram_chat_id', 'discord_webhook'])

router.post('/api/alerts', writeRequired, (req, res) => {
  const body = req.body || {}
  // Unknown keys are dropped, not rejected: installs predating the
  // allowlist may carry arbitrary keys in state.WAF.alerts, and echoing
  // them back into a strict 400 would permanently brick the dashboard's
  // save button with no way to remove the stale key through the API.
  // Either way an unknown key is never persisted again.
  const ignored = Object.keys(body).filter(k => !ALERT_FIELDS.has(k))
  for (const key of Object.keys(body)) {
    if (!ALERT_FIELDS.has(key)) continue
    if (ALERT_STRING_FIELDS.has(key) && typeof body[key] !== 'string') return res.status(400).json({ detail: `"${key}" must be a string` })
  }
  if (body.spike_threshold !== undefined && (!Number.isFinite(Number(body.spike_threshold)) || Number(body.spike_threshold) < 1)) {
    return res.status(400).json({ detail: 'spike_threshold must be a positive number' })
  }
  // updateWAF serializes against CLI/other processes and re-reads committed
  // state first — concurrent alert edits can no longer silently drop one
  // side's fields.
  state.updateWAF(w => {
    if (!w.alerts || typeof w.alerts !== 'object') w.alerts = {}
    for (const key of ALERT_FIELDS) {
      if (!Object.hasOwn(body, key)) continue
      const value = body[key]
      if (value === '' || value === null || value === undefined) delete w.alerts[key]
      else w.alerts[key] = value
    }
  })
  auditSvc.audit(req, 'alerts.update', '', redactedAlerts())
  res.json({ message: 'Saved', alerts: redactedAlerts(), ...(ignored.length ? { ignored } : {}) })
})

router.post('/api/alerts/test', writeRequired, async (req, res) => {
  const { channel } = req.body || {}
  const alerts = state.WAF.alerts || {}
  const text = `[CatWAF] Test Alert — channel: ${channel} — ${new Date().toISOString()}`

  // Actually deliver something where a delivery is possible. A silent fake
  // success here would leave an operator believing their alerting works on
  // the one day they check it.
  try {
    let url = null
    if (channel === 'slack' && alerts.slack_webhook) url = alerts.slack_webhook
    else if (channel === 'discord' && alerts.discord_webhook) url = alerts.discord_webhook
    else if (channel === 'custom' && alerts.custom_webhook) url = alerts.custom_webhook

    if (channel === 'email') {
      return res.status(400).json({ detail: `Email delivery is not configured on this install (${alerts.email_to || 'no recipient set'}); use a webhook channel to verify alerting.` })
    }
    if (!url) return res.status(400).json({ detail: `No webhook URL is configured for "${channel}". Save one first.` })
    if (!/^https:\/\//i.test(url)) return res.status(400).json({ detail: 'Webhook URLs must use https://' })

    const { response } = await netGuard.guardedFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: text, text }),
    })
    if (!response.ok) {
      throw new Error(`webhook answered ${response.status}`)
    }
    auditSvc.audit(req, 'alerts.test', String(channel).slice(0, 32))
    res.json({ message: `Test alert delivered to ${channel}` })
  } catch (e) {
    auditSvc.audit(req, 'alerts.test-failed', String(channel).slice(0, 32), { error: e.message })
    res.status(502).json({ detail: `Test alert could not be delivered: ${e.message}` })
  }
})

module.exports = router
