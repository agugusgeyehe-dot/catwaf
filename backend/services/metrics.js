// metrics.js — Prometheus text-exposition rendering (idea #46).
//
// This is mostly a new *view* over numbers CatWAF already computes for the
// dashboard, not new collection. The dashboard is right for a human; a site
// owner running Grafana or an uptime check has had no machine-readable way
// in, and scraping the dashboard's own JSON API was never designed for that
// (it is behind a rotating path and a request-signing scheme).

const db = require('./db')
const settings = require('./settings')
const state = require('./state')
const bans = require('./bans')
const caddySvc = require('./caddy')
const { version: pkgVersion } = require('../../package.json')

const startedAt = Date.now()

function escapeLabel(value) {
  return String(value ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, ' ')
}

class Exposition {
  constructor(prefix) {
    this.prefix = prefix
    this.lines = []
  }

  metric(name, type, help) {
    this.current = `${this.prefix}_${name}`
    this.lines.push(`# HELP ${this.current} ${help}`)
    this.lines.push(`# TYPE ${this.current} ${type}`)
    return this
  }

  sample(value, labels = null, name = null) {
    const metric = name ? `${this.prefix}_${name}` : this.current
    const labelText = labels && Object.keys(labels).length
      ? `{${Object.entries(labels).map(([k, v]) => `${k}="${escapeLabel(v)}"`).join(',')}}`
      : ''
    const n = Number(value)
    this.lines.push(`${metric}${labelText} ${Number.isFinite(n) ? n : 0}`)
    return this
  }

  toString() { return this.lines.join('\n') + '\n' }
}

function windowCounts(sinceIso) {
  const conn = db.getDb()
  return {
    total: conn.prepare('SELECT COUNT(*) AS n FROM request_log WHERE ts > ?').get(sinceIso).n,
    blocked: conn.prepare("SELECT COUNT(*) AS n FROM request_log WHERE ts > ? AND action = 'block'").get(sinceIso).n,
    byType: conn.prepare(`
      SELECT COALESCE(attack_type, 'unknown') AS t, COUNT(*) AS n FROM request_log
      WHERE ts > ? AND action = 'block' GROUP BY t ORDER BY n DESC LIMIT 25
    `).all(sinceIso),
    bySeverity: conn.prepare(`
      SELECT COALESCE(severity, 'unknown') AS s, COUNT(*) AS n FROM request_log
      WHERE ts > ? AND action = 'block' GROUP BY s
    `).all(sinceIso),
    byCountry: conn.prepare(`
      SELECT COALESCE(country_code, 'XX') AS c, COUNT(*) AS n FROM request_log
      WHERE ts > ? AND action = 'block' GROUP BY c ORDER BY n DESC LIMIT 50
    `).all(sinceIso),
  }
}

function edgeBansCollect() {
  // Cheap count without rendering anything.
  try {
    const cfg = settings.get('edge_bans')
    const bans = require('./bans').listActiveTargets({ limit: cfg.max_rules })
      .filter(t => !require('./state').WAF.ip_whitelist?.some(e => e?.ip && (
        require('./sanitize').ipCoveredBy(t, e.ip) || require('./sanitize').ipCoveredBy(e.ip, t))))
    return bans.length
  } catch { return 0 }
}

function lastKnownKernelCount() {
  try { return Number(require('./db').getState('kernel_bans_last_count')) || 0 } catch { return 0 }
}


function render() {
  const cfg = settings.get('metrics')
  const out = new Exposition(cfg.prefix || 'catwaf')

  out.metric('build_info', 'gauge', 'CatWAF build information; the value is always 1.')
  out.sample(1, {
    version: pkgVersion,
    engine: state.WAF.engine,
    edition: require('./edition').current(),
    node: process.version,
  })

  out.metric('up', 'gauge', 'Whether the CatWAF API is serving. Always 1 when scraped.')
  out.sample(1)

  out.metric('uptime_seconds', 'gauge', 'Seconds since the CatWAF API process started.')
  out.sample(Math.round((Date.now() - startedAt) / 1000))

  // ── Enforcement tiers ──
  out.metric('edge_bans_active', 'gauge', 'Number of ban targets currently rendered at the Caddy edge.')
  let edgeCount = 0
  try { edgeCount = require('./edgeBans').enabled() ? edgeBansCollect() : 0 } catch {}
  out.sample(edgeCount)

  out.metric('kernel_bans_active', 'gauge', 'Entries mirrored into the nftables catwaf_edge sets (0 when disabled).')
  try {
    const kb = require('./kernelBans')
    const st = kb.status()
    out.sample(st.enabled && st.env_enabled ? lastKnownKernelCount() : 0)
  } catch { out.sample(0) }

  const counters = (() => { try { return require('./counters').all() } catch { return {} } })()
  out.metric('canary_hits_total', 'counter', 'Requests that touched a canary path and were banned.')
  out.sample(Number(counters.canary_hits_total) || 0)

  // ONE metric declaration with a kind label — emitting per-kind TYPE lines
  // made Prometheus reject the entire exposition.
  out.metric('alerts_delivered_total', 'counter', 'Alert deliveries attempted, by alert kind.')
  for (const kind of ['spike', 'new_ban', 'engine_change']) {
    out.sample(Number(counters[`alerts_delivered_${kind}`]) || 0, { kind })
  }

  // ── WAF configuration, as gauges so alerts can fire on a setting change ──
  out.metric('waf_engine_enabled', 'gauge', '1 when the WAF engine is blocking, 0 when it is in detection-only or off.')
  out.sample(state.WAF.engine === 'On' ? 1 : 0)

  out.metric('waf_paranoia_level', 'gauge', 'Current CRS blocking paranoia level (1-4).')
  out.sample(state.WAF.paranoia_level)

  out.metric('waf_anomaly_threshold', 'gauge', 'Inbound anomaly score threshold.')
  out.sample(state.WAF.inbound_anomaly_threshold)

  out.metric('rate_limit_enabled', 'gauge', '1 when rate limiting is enabled.')
  out.sample(state.WAF.rate_limit?.enabled ? 1 : 0)

  // ── Traffic ──
  const day = new Date(Date.now() - 86_400_000).toISOString()
  const hour = new Date(Date.now() - 3_600_000).toISOString()
  const d = windowCounts(day)
  const h = windowCounts(hour)

  out.metric('requests_total', 'gauge', 'Requests recorded in the request log, by window.')
  out.sample(h.total, { window: '1h' })
  out.sample(d.total, { window: '24h' })

  out.metric('blocked_total', 'gauge', 'Blocked requests recorded in the request log, by window.')
  out.sample(h.blocked, { window: '1h' })
  out.sample(d.blocked, { window: '24h' })

  out.metric('blocked_by_category', 'gauge', 'Blocked requests in the last 24h by CRS attack category.')
  for (const row of d.byType) out.sample(row.n, { category: row.t })

  out.metric('blocked_by_severity', 'gauge', 'Blocked requests in the last 24h by severity.')
  for (const row of d.bySeverity) out.sample(row.n, { severity: row.s })

  if (cfg.include_geo) {
    out.metric('blocked_by_country', 'gauge', 'Blocked requests in the last 24h by country code.')
    for (const row of d.byCountry) out.sample(row.n, { country: row.c })
  }

  // ── Bans (idea #61) ──
  const banStats = bans.stats()
  out.metric('active_bans', 'gauge', 'Currently active bans by the feature that produced them.')
  for (const row of banStats.by_source) out.sample(row.count, { source: row.source })
  out.sample(banStats.total, { source: 'all' })

  // ── Lists and rules ──
  out.metric('list_entries', 'gauge', 'Configured list sizes.')
  out.sample((state.WAF.ip_blacklist || []).length, { list: 'ip_blacklist' })
  out.sample((state.WAF.ip_whitelist || []).length, { list: 'ip_whitelist' })
  out.sample((state.WAF.geo_blocking || []).length, { list: 'geo_blocking' })
  out.sample((state.WAF.custom_rules || []).length, { list: 'custom_rules' })
  out.sample((state.WAF.disabled_rules || []).length, { list: 'disabled_rules' })

  // ── Config health ──
  const report = caddySvc.lastRenderReport()
  out.metric('config_skipped_directives', 'gauge', 'Settings that are switched on but could not be rendered (missing Caddy module or prerequisite).')
  out.sample((report.skipped || []).length)

  out.metric('caddy_reload_pending', 'gauge', '1 when a Caddy reload is queued but has not run yet.')
  out.sample(caddySvc.isReloadPending() ? 1 : 0)

  // ── Scheduled jobs (idea #44) ──
  const jobs = require('./jobs').list()
  out.metric('job_last_run_timestamp_seconds', 'gauge', 'Unix time of each scheduled job\'s last completion.')
  for (const job of jobs) {
    if (job.last_run?.finished_at) out.sample(Math.round(new Date(job.last_run.finished_at).getTime() / 1000), { job: job.name })
  }
  out.metric('job_last_run_success', 'gauge', '1 when a scheduled job\'s last run succeeded.')
  for (const job of jobs) {
    if (job.last_run) out.sample(job.last_run.ok ? 1 : 0, { job: job.name })
  }

  return out.toString()
}

module.exports = { render, Exposition }
