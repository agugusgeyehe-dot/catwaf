
const state = require('../state')
const requestLog = require('../requestLog')
const securityScore = require('../securityScore')

function countryNameFor(cc) {
  try { return new Intl.DisplayNames(['en'], { type: 'region' }).of(cc) || cc } catch { return cc }
}

const QUERIES = {
  protection_status: {
    match: /\b(protect|safe|secur|status|engine|working|active|enabl|running|paranoia|firewall|how am i doing|everything ok|all good|set ?up)/i,
    async run() {
      const w = state.WAF
      const geo = (w.geo_blocking || []).length
      const rl = (w.rate_limit || {}).enabled
      return [
        `Protection engine: ${w.engine}${w.engine === 'On' ? ' (attacks are actively blocked)' : w.engine === 'DetectionOnly' ? ' (attacks are only logged, NOT blocked)' : ' (protection is off entirely)'}`,
        `Paranoia level: ${w.paranoia_level} of 4`,
        `Rate limiting: ${rl ? `on (${(w.rate_limit || {}).requests_per_min}/min per IP)` : 'off'}`,
        `Countries blocked: ${geo || 'none'}${geo ? ` (${(w.geo_blocking || []).map(countryNameFor).join(', ')})` : ''}`,
        `IPs blocked: ${(w.ip_blacklist || []).length}`,
        `IPs allowlisted: ${(w.ip_whitelist || []).length}`,
      ].join('\n')
    },
  },

  security_score: {
    match: /\b(score|grade|rating|improve|recommend|harden|better|weak|stronger)/i,
    async run() {
      const s = await securityScore.getSecurityScore()
      const top = s.recommendations.filter(r => r.severity === 'high').slice(0, 3)
      return [
        `Security score: ${s.score}/100 (grade ${s.grade})`,
        `Checks passing: ${s.passing} of ${s.total_checks}, warnings: ${s.warnings}`,
        top.length
          ? `Top things to fix:\n${top.map(r => `  - ${r.label}: ${r.recommendation}`).join('\n')}`
          : 'No high-severity recommendations outstanding.',
      ].join('\n')
    },
  },

  traffic_stats: {
    match: /\b(attack|block|traffic|today|request|hit|how many|activity|recent|happening|log|visitor|threat)/i,
    async run() {
      if (!requestLog.hasAnyData()) {
        return 'Request log: no traffic has been recorded yet (the audit log is empty — this usually means Coraza has not logged anything since setup, not that the site is idle).'
      }
      const day = requestLog.getCounts(24 * 60 * 60 * 1000)
      const hour = requestLog.getCounts(60 * 60 * 1000)
      const types = requestLog.getAttackTypeCounts(24 * 60 * 60 * 1000)
      const typeList = Object.entries(types).sort((a, b) => b[1] - a[1]).slice(0, 5)
      return [
        `Last 24 hours: ${day.total} requests seen, ${day.blocked} blocked, ${day.allowed} allowed`,
        `Last hour: ${hour.total} requests seen, ${hour.blocked} blocked`,
        typeList.length
          ? `Attack types blocked in 24h:\n${typeList.map(([t, n]) => `  - ${t}: ${n}`).join('\n')}`
          : 'No attacks classified in the last 24 hours.',
      ].join('\n')
    },
  },

  block_lists: {
    match: /\b(blocklist|blacklist|allowlist|whitelist|ban|list|which ip|what ip|countr|blocking|blocked)/i,
    async run() {
      const w = state.WAF
      const bl = (w.ip_blacklist || []).slice(0, 10)
      const wl = (w.ip_whitelist || []).slice(0, 10)
      const geo = w.geo_blocking || []
      const ua = w.blocked_user_agents || []
      return [
        `Blocked IPs (${(w.ip_blacklist || []).length}): ${bl.length ? bl.map(e => e.ip || e).join(', ') : 'none'}`,
        `Allowlisted IPs (${(w.ip_whitelist || []).length}): ${wl.length ? wl.map(e => e.ip || e).join(', ') : 'none'}`,
        `Blocked countries (${geo.length}): ${geo.length ? geo.map(cc => `${countryNameFor(cc)} (${cc})`).join(', ') : 'none'}`,
        `Blocked user agents (${ua.length}): ${ua.length ? ua.slice(0, 10).join(', ') : 'none'}`,
      ].join('\n')
    },
  },
}

async function resolve(userMessage, { onStage = () => {} } = {}) {
  const msg = String(userMessage || '')
  const blocks = []
  const ran = []
  for (const [name, q] of Object.entries(QUERIES)) {
    if (!q.match.test(msg)) continue
    try {
      const text = await q.run()
      if (text) { blocks.push(text); ran.push(name) }
    } catch {}
  }
  if (!blocks.length) return null
  onStage('lookup', ran)
  return { text: blocks.join('\n\n'), ran }
}

module.exports = { resolve, QUERIES }
