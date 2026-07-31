
const fs = require('fs')
const state = require('./state')
const caddy = require('./caddy')
const debuggerSvc = require('./debugger')
const auditSvc = require('./audit')

function lintConfig() {
  const errors = []
  const warnings = []

  const ruleIds = state.WAF.custom_rules.map(r => r.id)
  const dupeIds = ruleIds.filter((id, i) => ruleIds.indexOf(id) !== i)
  if (dupeIds.length) errors.push({ level:'error', code:'DUPLICATE_RULE_ID', message:`Duplicate custom rule ID(s): ${[...new Set(dupeIds)].join(', ')}` })

  const wl = new Set(state.WAF.ip_whitelist.map(e=>e.ip))
  const conflicts = state.WAF.ip_blacklist.filter(e => wl.has(e.ip)).map(e=>e.ip)
  if (conflicts.length) warnings.push({ level:'warning', code:'IP_CONFLICT', message:`IP(s) in both whitelist and blacklist: ${conflicts.join(', ')} — whitelist wins, blacklist entry is dead` })

  if (state.WAF.executing_paranoia_level < state.WAF.paranoia_level) {
    errors.push({ level:'error', code:'PL_MISMATCH', message:`Detection PL${state.WAF.executing_paranoia_level} is lower than Blocking PL${state.WAF.paranoia_level} — invalid, detection must be >= blocking` })
  }

  if (state.WAF.inbound_anomaly_threshold < 3) warnings.push({ level:'warning', code:'LOW_THRESHOLD', message:`Inbound anomaly threshold (${state.WAF.inbound_anomaly_threshold}) is very low — high false-positive risk` })
  if (state.WAF.inbound_anomaly_threshold > 20) warnings.push({ level:'warning', code:'HIGH_THRESHOLD', message:`Inbound anomaly threshold (${state.WAF.inbound_anomaly_threshold}) is very high — many real attacks may pass` })

  if (state.WAF.engine === 'Off' && (state.WAF.custom_rules.length > 0 || state.WAF.ip_blacklist.length > 0)) {
    warnings.push({ level:'warning', code:'ENGINE_OFF', message:'state.WAF engine is Off but you have custom rules / blacklisted IPs configured — they are not being enforced' })
  }

  state.WAF.custom_rules.forEach(r => {
    if (!r.variable || !r.operator || !r.value) {
      errors.push({ level:'error', code:'INCOMPLETE_RULE', message:`Custom rule "${r.name||r.id}" is missing variable/operator/value` })
    }
    if (!['deny','log','redirect','pass','allow'].includes(r.action)) {
      warnings.push({ level:'warning', code:'UNKNOWN_ACTION', message:`Custom rule "${r.name||r.id}" has unusual action "${r.action}"` })
    }
  })

  const knownIds = new Set(debuggerSvc.TRACE_RULES.map(r=>r.id))
  state.WAF.rule_exclusions.forEach(e => {
    if (!knownIds.has(e.rule_id) && !/^9\d{5}$/.test(e.rule_id)) {
      warnings.push({ level:'warning', code:'UNKNOWN_EXCLUSION_TARGET', message:`Exclusion targets rule ${e.rule_id}, which isn't a recognized CRS/custom rule ID — check for typos` })
    }
  })

  let caddyfileErrors = []
  try {
    const content = fs.readFileSync(caddy.CADDYFILE_PATH, 'utf8')
    if (!content.includes('coraza_waf')) caddyfileErrors.push({ level:'error', code:'NO_CORAZA_BLOCK', message:'Caddyfile does not contain a coraza_waf block — state.WAF is not actually wired in' })
    if (!content.includes('order coraza_waf first')) caddyfileErrors.push({ level:'warning', code:'ORDER_MISSING', message:'Caddyfile is missing "order coraza_waf first" — Coraza may not run before other handlers' })
    const openBraces = (content.match(/{/g)||[]).length
    const closeBraces = (content.match(/}/g)||[]).length
    if (openBraces !== closeBraces) caddyfileErrors.push({ level:'error', code:'BRACE_MISMATCH', message:`Caddyfile has unbalanced braces (${openBraces} open, ${closeBraces} close) — this will fail to parse` })
  } catch (e) {
    caddyfileErrors.push({ level:'error', code:'CADDYFILE_UNREADABLE', message:`Cannot read Caddyfile: ${e.message}` })
  }

  const allIssues = [...errors, ...caddyfileErrors, ...warnings]
  return {
    valid: errors.filter(e=>e.level==='error').length === 0 && caddyfileErrors.filter(e=>e.level==='error').length === 0,
    error_count: allIssues.filter(i=>i.level==='error').length,
    warning_count: allIssues.filter(i=>i.level==='warning').length,
    issues: allIssues,
    linted_at: auditSvc.now(),
  }
}

module.exports = { lintConfig }
