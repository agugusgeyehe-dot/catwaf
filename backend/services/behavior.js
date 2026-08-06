// behavior.js — automatic banning on repeated bad responses (idea #6).
//
// This catches the attack shape CatWAF's existing rate limiting cannot:
// credential stuffing, endpoint brute-forcing and broad scanning, where
// every individual request is *valid* — it just fails. Coraza never fires,
// and the request rate can stay well under any per-minute limit, because
// what is anomalous is the failure rate, not the volume.
//
// The counting runs over the request log rather than on the request path.
// The response status is what matters here and CatWAF only learns it after
// the fact, so a scheduled sweep is both the accurate place to do it and the
// one that costs nothing per request.

const db = require('./db')
const bans = require('./bans')
const settings = require('./settings')
const logger = require('./logger')
const { normalizeClientIp, ipCoveredBy } = require('./sanitize')

const log = logger.child('behavior')
const SEEN_KEY = 'bad_behavior_cursor'

function statusMatches(status, codes) {
  const s = String(status)
  return codes.some(code => {
    const pattern = String(code)
    if (/^\dxx$/i.test(pattern)) return s.startsWith(pattern[0])
    return pattern === s
  })
}

// Addresses the operator has explicitly allowed are never auto-banned — an
// automatic rule must not be able to override a human's decision.
function isProtected(ip) {
  const state = require('./state')
  for (const entry of state.WAF.ip_whitelist || []) {
    if (entry?.ip && ipCoveredBy(ip, entry.ip)) return true
  }
  const grey = settings.get('greylist')
  if (grey.enabled && grey.skip_checks.includes('bad_behavior')) {
    for (const cidr of grey.ips) if (ipCoveredBy(ip, cidr)) return true
  }
  return false
}

// Counts bad responses per address inside the rolling window and returns the
// offenders. Exported separately from sweep() so the dashboard can show what
// *would* be banned before the feature is switched on.
function offenders({ windowSec, codes, threshold, countWafBlocks }) {
  const since = new Date(Date.now() - windowSec * 1000).toISOString()
  const rows = db.getDb().prepare(`
    SELECT ip, status, action, COUNT(*) AS n
    FROM request_log
    WHERE ts > ? AND ip IS NOT NULL AND ip != ''
    GROUP BY ip, status, action
  `).all(since)

  const tally = new Map()
  for (const row of rows) {
    const isBad = statusMatches(row.status, codes) || (countWafBlocks && row.action === 'block')
    if (!isBad) continue
    const ip = normalizeClientIp(row.ip)
    if (!ip) continue
    const entry = tally.get(ip) || { ip, count: 0, statuses: new Map() }
    entry.count += row.n
    entry.statuses.set(row.status, (entry.statuses.get(row.status) || 0) + row.n)
    tally.set(ip, entry)
  }

  return [...tally.values()]
    .filter(e => e.count >= threshold)
    .map(e => ({
      ip: e.ip,
      count: e.count,
      breakdown: [...e.statuses.entries()].sort((a, b) => b[1] - a[1]).map(([status, n]) => `${status}×${n}`),
    }))
    .sort((a, b) => b.count - a.count)
}

function sweep({ dryRun = false } = {}) {
  const cfg = settings.get('bad_behavior')
  if (!cfg.enabled) return { ok: true, skipped: 'disabled', changed: false }

  const found = offenders({
    windowSec: cfg.window_sec,
    codes: cfg.status_codes,
    threshold: cfg.threshold,
    countWafBlocks: cfg.count_waf_blocks,
  })

  const banned = []
  const skipped = []
  for (const offender of found) {
    if (isProtected(offender.ip)) { skipped.push({ ...offender, why: 'allowlisted' }); continue }
    if (bans.check(offender.ip)) { skipped.push({ ...offender, why: 'already banned' }); continue }
    if (dryRun) { banned.push(offender); continue }

    const result = bans.ban({
      target: offender.ip,
      source: 'bad_behavior',
      seconds: cfg.ban_seconds,
      reason: `${offender.count} bad responses in ${cfg.window_sec}s (${offender.breakdown.join(', ')})`,
      meta: { count: offender.count, window_sec: cfg.window_sec, breakdown: offender.breakdown },
    })
    if (result.ok) banned.push({ ...offender, duration_sec: result.duration_sec })
  }

  if (banned.length && !dryRun) {
    log.info('Behavioural banning applied', { banned: banned.length, threshold: cfg.threshold, window_sec: cfg.window_sec })
    db.setState(SEEN_KEY, new Date().toISOString())
  }

  return { ok: true, dryRun, banned: banned.length, skipped: skipped.length, offenders: banned, changed: false }
}

function preview() {
  const cfg = settings.get('bad_behavior')
  return {
    enabled: cfg.enabled,
    window_sec: cfg.window_sec,
    threshold: cfg.threshold,
    would_ban: offenders({
      windowSec: cfg.window_sec,
      codes: cfg.status_codes,
      threshold: cfg.threshold,
      countWafBlocks: cfg.count_waf_blocks,
    }).slice(0, 50),
  }
}

module.exports = { sweep, preview, offenders, statusMatches, SEEN_KEY }
