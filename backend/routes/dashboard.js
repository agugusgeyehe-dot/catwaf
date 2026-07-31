
const express = require('express')
const router = express.Router()
const state = require('../services/state')
const auditSvc = require('../services/audit')
const traffic = require('../services/traffic')
const trafficLog = require('../services/requestLog')
const rulesSvc = require('../services/rules')
const db = require('../services/db')

router.get('/api/stats', (req, res) => {
  const counts = trafficLog.getCounts()
  const attackCounts = trafficLog.getAttackTypeCounts()
  const topAttack = Object.entries(attackCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || null
  const scoreRow = db.getDb().prepare("SELECT AVG(score) AS avg FROM request_log WHERE ts >= datetime('now', '-1 day') AND score IS NOT NULL").get()

  res.json({
    total_requests: counts.total,
    blocked_requests: counts.blocked,
    passed_requests: counts.allowed,
    active_rules: Object.values(state.RULE_CATEGORIES).filter(c => c.enabled).reduce((s, c) => s + c.count, 0),
    false_positives_today: auditSvc.getFPs().filter(fp => fp.ts && fp.ts.slice(0, 10) === new Date().toISOString().slice(0, 10)).length,
    avg_anomaly_score: scoreRow.avg != null ? +scoreRow.avg.toFixed(2) : null,
    top_attack: topAttack,
    requests_per_min: counts.total ? +(counts.total / (24 * 60)).toFixed(1) : 0,
    blocked_ips: state.WAF.ip_blacklist.length,
    uptime_hours: +(process.uptime() / 3600).toFixed(1),
    engine_mode: state.WAF.engine,
    paranoia_level: state.WAF.paranoia_level,
    crs_version: rulesSvc.crsVersion(),
    coraza_version: null,
    has_real_traffic_data: trafficLog.hasAnyData(),
  })
})

router.get('/api/traffic/chart', (req, res) => {
  const rows = db.getDb().prepare(`
    SELECT strftime('%Y-%m-%dT%H:00:00Z', ts) AS hour_bucket,
           COUNT(*) AS total,
           SUM(CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS blocked
    FROM request_log
    WHERE ts >= datetime('now', '-24 hours')
    GROUP BY hour_bucket
  `).all()
  const byHour = Object.fromEntries(rows.map(r => [r.hour_bucket, r]))

  const t = Date.now(), out = []
  for (let h = 0; h < 24; h++) {
    const d = new Date(t - (23 - h) * 3600 * 1000)
    const bucketKey = `${d.toISOString().slice(0, 13)}:00:00Z`
    const row = byHour[bucketKey]
    const total = row ? row.total : 0
    const blocked = row ? row.blocked : 0
    out.push({ hour: `${String(d.getUTCHours()).padStart(2, '0')}:00`, total, blocked, passed: total - blocked })
  }
  res.json(out)
})
router.get('/api/traffic/attacks', (req, res) => {
  const counts = trafficLog.getAttackTypeCounts()
  const CATEGORIES = [
    { type: 'SQL Injection',  code: 'SQLi',           color: '#ef4444' },
    { type: 'XSS',            code: 'XSS',            color: '#f97316' },
    { type: 'LFI',            code: 'LFI',            color: '#eab308' },
    { type: 'RCE',            code: 'RCE',            color: '#a855f7' },
    { type: 'PHP Injection',  code: 'PHP Injection',  color: '#3b82f6' },
    { type: 'RFI',            code: 'RFI',            color: '#22c55e' },
    { type: 'Session Fix',    code: 'Session Fix',    color: '#ec4899' },
  ]
  res.json(CATEGORIES.map(c => ({ type: c.type, count: counts[c.code] || 0, color: c.color })))
})
router.get('/api/traffic/live',    (req, res) => res.json(traffic.recentTraffic(50)))
router.get('/api/traffic/top-ips', (req, res) => {
  const rows = db.getDb().prepare(`
    SELECT ip, country_code, city, COUNT(*) AS blocked, MAX(ts) AS last_seen FROM request_log
    WHERE action = 'block' AND ip IS NOT NULL
    GROUP BY ip ORDER BY blocked DESC LIMIT 10
  `).all()
  res.json(rows.map(r => ({ ip: r.ip, country: r.country_code, city: r.city, blocked: r.blocked, last_seen: r.last_seen })))
})

router.get('/api/attack-map', (req, res) => {
  const windowMs = trafficLog.parseWindow(req.query.window, 24 * 3600000)
  if (windowMs == null) return res.status(400).json({ detail: 'invalid window' })
  const points = trafficLog.getAttackMapPoints({ sinceMs: windowMs, limit: req.query.limit })
  res.json({
    window_ms: windowMs,
    has_data: points.length > 0,
    points,
  })
})

module.exports = router
