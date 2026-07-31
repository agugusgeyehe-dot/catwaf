
const state = require('../state')
const securityScoreSvc = require('../securityScore')
const requestLog = require('../requestLog')

async function buildConfigContext() {
  const score = await securityScoreSvc.getSecurityScore().catch(() => null)
  const lines = [
    `Protection engine: ${state.WAF.engine}`,
    `Paranoia level: ${state.WAF.paranoia_level} of 4`,
    `Rate limiting: ${state.WAF.rate_limit?.enabled ? 'on' : 'off'}`,
    `Blocked IP addresses: ${state.WAF.ip_blacklist.length}`,
    `Allowlisted IP addresses: ${state.WAF.ip_whitelist.length}`,
    `Blocked countries: ${state.WAF.geo_blocking.length ? state.WAF.geo_blocking.join(', ') : 'none'}`,
  ]
  if (score) lines.push(`Security score: ${score.score}% (grade ${score.grade})`)
  return lines.join('\n')
}

const LOG_INTENT_RE = /\b(blocked|log|request|why (was|did|is)|attack|rule\s*\d|anomal)/i
function shouldIncludeLogs(userMessage) {
  return LOG_INTENT_RE.test(String(userMessage || ''))
}

const CONTROL_AND_BIDI_RE = new RegExp(
  '[\\u0000-\\u001F\\u007F' +
  '\\u200B-\\u200F' +
  '\\u202A-\\u202E' +
  '\\u2066-\\u2069' +
  '\\uFEFF]',
  'g',
)

function sanitizeField(v, maxLen) {
  let s = String(v == null ? '' : v).normalize('NFKC')
  s = s.replace(CONTROL_AND_BIDI_RE, '')
  s = s.replace(/[<>]/g, '')
  s = s.replace(/`/g, "'")
  return s.length > maxLen ? s.slice(0, maxLen) + '…' : s
}

function buildLogContext({ limit = 10 } = {}) {
  const rows = requestLog.getRecent(limit)
  if (!rows.length) return 'No recent request log entries.'
  const header = 'TIME                 IP               METHOD  URI                                           ACTION   RULES'
  const lines = rows.map(r => {
    const time = sanitizeField(r.ts, 20).padEnd(20)
    const ip = sanitizeField(r.ip || '-', 15).padEnd(15)
    const method = sanitizeField(r.method || '-', 6).padEnd(6)
    const uri = sanitizeField(r.uri || '-', 45).padEnd(45)
    const action = sanitizeField(r.action || '-', 8).padEnd(8)
    const rules = sanitizeField((r.rule_ids || []).slice(0, 3).join(','), 20)
    return `${time} ${ip} ${method}  ${uri} ${action} ${rules}`
  })
  return [header, ...lines].join('\n')
}

module.exports = { buildConfigContext, buildLogContext, shouldIncludeLogs }
