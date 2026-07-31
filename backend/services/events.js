const state = require('./state')
const rulesSvc = require('./rules')
const requestLog = require('./requestLog')
const simulateSvc = require('./simulate')

const EVENT_ID_RE = /^[a-f0-9]{4,32}$/i

const SENSITIVE_QUERY_KEYS = /^(pass|passwd|password|pwd|token|secret|api[_-]?key|apikey|auth|authorization|session|sid|jwt|access[_-]?token|refresh[_-]?token|credential|signature|sig)$/i

function isValidEventId(id) {
  return typeof id === 'string' && EVENT_ID_RE.test(id)
}

function sanitizeUri(uri) {
  if (typeof uri !== 'string') return { uri: null, redacted: [] }
  const redacted = []
  const qIdx = uri.indexOf('?')
  if (qIdx === -1) return { uri, redacted }

  const pathPart = uri.slice(0, qIdx)
  const queryPart = uri.slice(qIdx + 1)

  const rebuilt = queryPart.split('&').map(pair => {
    const eq = pair.indexOf('=')
    const key = eq === -1 ? pair : pair.slice(0, eq)
    let decoded = key
    try { decoded = decodeURIComponent(key) } catch {}
    if (SENSITIVE_QUERY_KEYS.test(decoded)) {
      redacted.push(decoded)
      return `${key}=[REDACTED]`
    }
    return pair
  }).join('&')

  return { uri: `${pathPart}?${rebuilt}`, redacted }
}

const SEV_RANK = { emergency: 0, alert: 1, critical: 2, error: 3, warning: 4, notice: 5, info: 6, debug: 7 }

function friendlyVar(v) {
  if (!v) return null
  const [collection, name] = String(v).split(':')
  const label = {
    ARGS: 'query string or body parameter',
    ARGS_NAMES: 'query/body parameter name',
    ARGS_GET: 'query string parameter',
    ARGS_POST: 'body parameter',
    REQUEST_URI: 'URL path',
    REQUEST_FILENAME: 'URL path',
    REQUEST_BODY: 'request body',
    REQUEST_HEADERS: 'request header',
    REQUEST_COOKIES: 'request cookie',
    REQUEST_METHOD: 'HTTP method',
    REQUEST_LINE: 'request line',
    XML: 'XML body',
  }[collection] || collection
  return name ? `${label} "${name}"` : label
}

function pickPrimaryRule(ruleDetails, event) {
  const known = ruleDetails.filter(r => r.known)
  if (!known.length) return ruleDetails[0] || null
  const matchingCategory = known.filter(r => event.attack_type && r.category === event.attack_type)
  const pool = matchingCategory.length ? matchingCategory : known
  return [...pool].sort((a, b) => {
    const sa = SEV_RANK[a.severity] ?? 99
    const sb = SEV_RANK[b.severity] ?? 99
    if (sa !== sb) return sa - sb
    return Number(a.id) - Number(b.id)
  })[0]
}

function matchedComponent(rule) {
  if (!rule || !rule.targets) return null
  const t = rule.targets
  if (/REQUEST_COOKIES/.test(t)) return 'request cookies'
  if (/REQUEST_HEADERS:User-Agent/i.test(t)) return 'User-Agent header'
  if (/REQUEST_HEADERS/.test(t)) return 'request headers'
  if (/REQUEST_URI|REQUEST_FILENAME/.test(t)) return 'URL path'
  if (/ARGS_NAMES/.test(t)) return 'query/body parameter names'
  if (/ARGS/.test(t)) return 'query string or body parameters'
  if (/REQUEST_BODY/.test(t)) return 'request body'
  if (/XML/.test(t)) return 'XML body'
  if (/REQUEST_METHOD/.test(t)) return 'HTTP method'
  return t.split('|')[0] || null
}

function remediationFor({ event, ruleDetails }) {
  const tips = []
  const attack = event.attack_type

  if (event.action !== 'block') {
    tips.push('This request was recorded but not blocked. If it should have been blocked, raise the paranoia level or lower the inbound anomaly threshold.')
    return tips
  }

  if (attack === 'Scanner Detection') {
    tips.push('A known scanner/tool User-Agent was detected. If this was your own security testing, allowlist the source IP temporarily rather than disabling the rule.')
  }

  const plRules = ruleDetails.filter(r => typeof r.paranoia_level === 'number')
  const highestPl = plRules.length ? Math.max(...plRules.map(r => r.paranoia_level)) : null
  if (highestPl && highestPl >= state.WAF.paranoia_level && highestPl > 1) {
    tips.push(`The strictest matching rule belongs to paranoia level ${highestPl}. If this was a false positive, dropping to PL${highestPl - 1} would stop it matching — at the cost of weaker coverage.`)
  }

  if (event.score != null && event.score >= state.WAF.inbound_anomaly_threshold) {
    tips.push(`Anomaly score ${event.score} met or exceeded the inbound threshold of ${state.WAF.inbound_anomaly_threshold}. Raising the threshold makes blocking less sensitive across the board — prefer a targeted exclusion instead.`)
  }

  const primary = pickPrimaryRule(ruleDetails, event)
  if (primary) {
    tips.push(`If this is a confirmed false positive for your application, disable only the decisive rule: catwaf rules disable ${primary.id}`)
  }

  tips.push('Before changing anything, confirm the request really was legitimate — a block is the WAF working as intended unless proven otherwise.')
  return tips
}

function explain(eventIdOrOptions) {
  const opts = typeof eventIdOrOptions === 'string' ? { id: eventIdOrOptions } : (eventIdOrOptions || {})
  let event = null

  if (opts.last) {
    event = requestLog.getLatest({ blockedOnly: opts.blockedOnly !== false })
    if (!event) event = requestLog.getLatest({ blockedOnly: false })
    if (!event) return { ok: false, error: 'No events have been recorded yet. Send traffic through the WAF first.' }
  } else {
    if (!isValidEventId(opts.id)) {
      return { ok: false, error: 'Event ID must be a hexadecimal identifier. Use `catwaf explain --last` for the most recent event.' }
    }
    event = requestLog.getById(opts.id)
    if (!event) return { ok: false, error: `No event found with ID "${opts.id}".` }
  }

  const ruleDetails = (event.rule_ids || []).map(id => rulesSvc.describe(id))
  const { uri, redacted } = sanitizeUri(event.uri)

  const primary = pickPrimaryRule(ruleDetails, event)

  const whyParts = []
  if (event.action === 'block') {
    whyParts.push(`Coraza interrupted this request, so it never reached your application. CatWAF returned ${event.status || 403}.`)
    const decisive = primary?.description || event.reason
    if (decisive) whyParts.push(`The decisive rule (${primary ? primary.id : 'unknown'}) reported: "${decisive}".`)
    if (event.score != null) {
      whyParts.push(`The request accumulated an anomaly score of ${event.score} against an inbound threshold of ${state.WAF.inbound_anomaly_threshold}; CRS blocks once the score reaches the threshold.`)
    }
    if (ruleDetails.length > 1) {
      whyParts.push(`${ruleDetails.length} rules matched in total — CRS is score-based, so several rules commonly contribute to one decision.`)
    }
  } else {
    whyParts.push('This request was logged as relevant by Coraza but was not interrupted, so it reached your application.')
  }

  return {
    ok: true,
    event: {
      id: event.id,
      timestamp: event.ts,
      action: event.action,
      status: event.status,
      method: event.method,
      uri,
      redacted_query_keys: redacted,
      client_ip: event.ip,
      user_agent: event.user_agent,
      attack_type: event.attack_type,
      severity: event.severity,
      anomaly_score: event.score,
      reason: event.reason,
    },
    waf: {
      paranoia_level: state.WAF.paranoia_level,
      detection_paranoia_level: state.WAF.executing_paranoia_level,
      inbound_anomaly_threshold: state.WAF.inbound_anomaly_threshold,
      engine: state.WAF.engine,
    },
    matched_rules: ruleDetails,
    matched_component: friendlyVar(event.matched_var) || matchedComponent(primary),
    matched_variable: event.matched_var || null,
    primary_rule: primary ? primary.id : null,
    why: whyParts.join(' '),
    remediation: remediationFor({ event, ruleDetails }),
    notes: [
      'Request bodies, cookies, and Authorization headers are never stored by CatWAF and cannot be shown here.',
      redacted.length ? `Sensitive-looking query parameters were redacted: ${redacted.join(', ')}.` : null,
    ].filter(Boolean),
  }
}

function buildReplayRequest(event) {
  const { uri } = sanitizeUri(event.uri)
  const headers = {}
  if (event.user_agent) headers['user-agent'] = String(event.user_agent).slice(0, 512)
  return {
    ok: true,
    method: (event.method || 'GET').toUpperCase(),
    target: uri || '/',
    host: null,
    headers,
    body: '',
  }
}

async function replay(opts = {}) {
  const id = typeof opts === 'string' ? opts : opts.id
  if (opts.target && opts.target !== 'sandbox') {
    return { ok: false, error: 'Replay only runs against CatWAF\'s local simulation sandbox. Replaying against a live upstream is not supported.' }
  }
  if (!isValidEventId(id)) {
    return { ok: false, error: 'Event ID must be a hexadecimal identifier.' }
  }

  const event = requestLog.getById(id)
  if (!event) return { ok: false, error: `No event found with ID "${id}".` }

  const request = buildReplayRequest(event)
  const { headers } = simulateSvc.redactHeaders(request.headers)
  const result = await simulateSvc.runSandbox({ ...request, headers })

  if (!result.ok) return result

  const originalRules = (event.rule_ids || []).map(String).sort()
  const currentRules = (result.rule_ids || []).map(String).sort()
  const stillDetected = result.blocked
  const wasBlocked = event.action === 'block'

  const noLongerMatching = originalRules.filter(r => !currentRules.includes(r))
  const newlyMatching = currentRules.filter(r => !originalRules.includes(r))

  let verdict
  if (wasBlocked && stillDetected) verdict = 'still-blocked'
  else if (wasBlocked && !stillDetected) verdict = 'regression'
  else if (!wasBlocked && stillDetected) verdict = 'now-blocked'
  else verdict = 'still-allowed'

  const verdictText = {
    'still-blocked': 'This attack is still blocked by your current configuration.',
    'regression': 'WARNING: this attack was blocked when it happened, but your current configuration would ALLOW it.',
    'now-blocked': 'This request was allowed when it happened, but your current configuration would block it.',
    'still-allowed': 'This request was not blocked then, and would still not be blocked now.',
  }[verdict]

  return {
    ok: true,
    replay: true,
    simulation: true,
    target: 'local sandbox (a throwaway Caddy + Coraza instance against a local sink)',
    event_id: event.id,
    original: {
      timestamp: event.ts,
      action: event.action,
      status: event.status,
      attack_type: event.attack_type,
      severity: event.severity,
      anomaly_score: event.score,
      rule_ids: originalRules,
    },
    current: {
      blocked: result.blocked,
      status: result.status,
      attack_type: result.attack_type,
      severity: result.severity,
      anomaly_score: result.anomaly_score,
      rule_ids: currentRules,
      paranoia_level: result.paranoia_level,
    },
    changes: {
      rules_no_longer_matching: noLongerMatching.map(id => rulesSvc.describe(id)),
      rules_newly_matching: newlyMatching.map(id => rulesSvc.describe(id)),
      detection_changed: wasBlocked !== stillDetected,
    },
    verdict,
    verdict_text: verdictText,
    request_replayed: {
      method: request.method,
      target: request.target,
      headers,
    },
    note: 'Replay never contacts your real upstream. The request is reconstructed from sanitized stored fields only — bodies and cookies were never stored and are not replayed.',
  }
}

module.exports = { explain, replay, sanitizeUri, isValidEventId, buildReplayRequest, matchedComponent, friendlyVar, pickPrimaryRule }
