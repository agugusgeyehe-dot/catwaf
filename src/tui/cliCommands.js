
const os = require('os')
const path = require('path')
const ansi = require('./lib/ansi')
const Panel = require('./components/Panel')
const LogViewer = require('./components/LogViewer')
const ProgressBar = require('./components/ProgressBar')

const BACKEND_DIR = path.join(__dirname, '..', '..', 'backend')
const req = (p) => require(path.join(BACKEND_DIR, p))

function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400), h = Math.floor((seconds % 86400) / 3600), m = Math.floor((seconds % 3600) / 60)
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`
}

async function status() {
  const state = req('services/state.js')
  const caddySvc = req('services/caddy.js')
  const auditSvc = req('services/audit.js')
  const scoreSvc = req('services/securityScore.js')
  const edition = req('services/edition.js')
  const geoip = req('services/geoip.js')
  const svc = require('./service.js')
  const { version } = require(path.join(__dirname, '..', '..', 'package.json'))

  const running = caddySvc.isCaddyRunning()
  const corazaOk = caddySvc.getCaddyModules().includes('http.handlers.waf')
  const activeRules = Object.values(state.RULE_CATEGORIES).filter(c => c.enabled).reduce((n, c) => n + c.count, 0)
  const ramPct = Math.round((1 - os.freemem() / os.totalmem()) * 100)
  const scoreResult = await scoreSvc.getSecurityScore()

  const isFull = edition.isFull()
  const apiState = svc.status()
  const geo = geoip.available()

  const componentRows = isFull
    ? [
        ['API server', apiState.running ? 'RUNNING' : 'STOPPED', apiState.running ? ansi.colors.green : ansi.colors.yellow],
        ['Dashboard', edition.dashboardBuilt() ? 'BUILT' : 'NOT BUILT', edition.dashboardBuilt() ? ansi.colors.green : ansi.colors.yellow],
        ['CatAI', process.env.CATAI_ENABLED === 'true' ? 'ENABLED' : 'OFF (optional)',
          process.env.CATAI_ENABLED === 'true' ? ansi.colors.green : ansi.colors.dim],
      ]
    : [
        ['API server', 'NOT INSTALLED (Lite)', ansi.colors.dim],
        ['Dashboard', 'NOT INSTALLED (Lite)', ansi.colors.dim],
        ['CatAI', 'NOT INSTALLED (Lite)', ansi.colors.dim],
      ]

  console.log(ansi.color('\n🐱 CatWAF — WAF Health Summary\n', ansi.colors.bold))
  console.log(Panel('Status', [
    ['Version', version],
    ['Edition', (isFull ? 'Full' : 'Lite') + (edition.isExplicit() ? '' : ' (inferred)'),
      isFull ? ansi.colors.cyan : ansi.colors.dim],
    ['Protection', state.WAF.engine === 'On' ? 'ACTIVE' : state.WAF.engine.toUpperCase(), state.WAF.engine === 'On' ? ansi.colors.green : ansi.colors.yellow],
    ['Caddy', running ? 'RUNNING' : 'NOT RUNNING', running ? ansi.colors.green : ansi.colors.red],
    ['Coraza', !corazaOk ? 'MODULE NOT FOUND' : running ? 'ACTIVE' : 'AVAILABLE (Caddy stopped)',
      corazaOk && running ? ansi.colors.green : corazaOk ? ansi.colors.yellow : ansi.colors.red],
    ...componentRows,
    ['GeoIP', geo.ok ? 'AVAILABLE' : 'UNAVAILABLE (no location data)', geo.ok ? ansi.colors.green : ansi.colors.yellow],
    ['Rules loaded', activeRules],
    ['Load average', os.loadavg().map(n => n.toFixed(2)).join(', ')],
    ['RAM', ramPct + '%'],
    ['Uptime', formatUptime(os.uptime())],
  ], { width: 56 }).join('\n'))

  console.log(ansi.color('\n  Security score', ansi.colors.bold))
  console.log(`  ${ProgressBar(scoreResult.score, { width: 30 })}`)
  console.log(`  Grade ${scoreResult.grade} — ${scoreResult.passing} passing, ${scoreResult.warnings} warnings, ${scoreResult.critical_failures} critical`)
  for (const rec of scoreResult.recommendations.slice(0, 5)) {
    console.log(`  ${ansi.color('•', ansi.colors.yellow)} [${rec.severity}] ${rec.label}: ${rec.recommendation}`)
  }

  console.log(ansi.color('\n  Recent activity', ansi.colors.bold))
  const entries = auditSvc.getAuditLogs(10).map(l => ({
    ts: l.ts, severity: 'info', ip: l.ip,
    summary: `${ansi.color(l.user || 'guest', ansi.colors.cyan)} → ${l.action}${l.target ? ' (' + l.target + ')' : ''}`,
  }))
  console.log(LogViewer(entries, { limit: 10 }).join('\n'))
  console.log()
}

module.exports = { status }
