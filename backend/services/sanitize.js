
function escapeForDirective(str) {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/`/g, "'")
    .replace(/"/g, "'")
    .replace(/[\r\n]/g, ' ')
}

function isValidCaddyPath(p) {
  return typeof p === 'string' &&
    p.length > 0 && p.length <= 256 &&
    p.startsWith('/') &&
    !/[\s`{}"'\\]/.test(p)
}

const IPV4_OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
const IPV4_RE = new RegExp(`^${IPV4_OCTET}(\\.${IPV4_OCTET}){3}$`)
const IPV4_CIDR_RE = new RegExp(`^${IPV4_OCTET}(\\.${IPV4_OCTET}){3}/(\\d|[12]\\d|3[0-2])$`)
const IPV6_RE = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*$/
const IPV6_CIDR_RE = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*\/\d{1,3}$/

function isValidIpOrCidr(ip) {
  if (typeof ip !== 'string' || ip.length === 0 || ip.length > 64) return false
  return IPV4_RE.test(ip) || IPV4_CIDR_RE.test(ip) || IPV6_RE.test(ip) || IPV6_CIDR_RE.test(ip)
}


function normalizeClientIp(ip) {
  if (typeof ip !== 'string') return ''
  const m = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip.trim())
  return m ? m[1] : ip.trim()
}

function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, o) => ((acc << 8) >>> 0) + Number(o), 0) >>> 0
}

function ipv6ToBigInt(ip) {
  if (typeof ip !== 'string' || !ip.includes(':')) return null
  let head = ip, tail = ''
  const hasShorthand = ip.includes('::')
  if (hasShorthand) {
    const parts = ip.split('::')
    if (parts.length > 2) return null
    head = parts[0]; tail = parts[1]
  }
  const h = head ? head.split(':').filter(Boolean) : []
  const t = tail ? tail.split(':').filter(Boolean) : []
  const groups = hasShorthand
    ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t]
    : h
  if (groups.length !== 8) return null
  let n = 0n
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null
    n = (n << 16n) + BigInt(parseInt(g, 16))
  }
  return n
}

function ipCoveredBy(clientIp, target) {
  const ip = normalizeClientIp(clientIp)
  if (!ip || typeof target !== 'string' || !target) return false

  const t = target.trim()
  const slash = t.indexOf('/')
  const base = slash === -1 ? t : t.slice(0, slash)
  const bits = slash === -1 ? null : Number(t.slice(slash + 1))

  if (slash === -1) return ip.toLowerCase() === base.toLowerCase()
  if (!Number.isInteger(bits) || bits < 0) return false

  if (IPV4_RE.test(ip) && IPV4_RE.test(base)) {
    if (bits > 32) return false
    if (bits === 0) return true
    const mask = (~0 << (32 - bits)) >>> 0
    return ((ipv4ToInt(ip) & mask) >>> 0) === ((ipv4ToInt(base) & mask) >>> 0)
  }

  const ipN = ipv6ToBigInt(ip), baseN = ipv6ToBigInt(base)
  if (ipN !== null && baseN !== null) {
    if (bits > 128) return false
    if (bits === 0) return true
    const mask = ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits)
    return (ipN & mask) === (baseN & mask)
  }

  return false
}

function isValidCountryCode(cc) {
  return typeof cc === 'string' && /^[A-Z]{2}$/.test(cc)
}

const ALLOWED_VARIABLES = new Set([
  'ARGS', 'ARGS_NAMES', 'REQUEST_URI', 'REQUEST_HEADERS', 'REQUEST_BODY',
  'REQUEST_COOKIES', 'REQUEST_METHOD', 'QUERY_STRING', 'REMOTE_ADDR',
  'REQUEST_HEADERS:User-Agent', 'REQUEST_HEADERS:Referer', 'REQUEST_HEADERS:Cookie',
  'ARGS|REQUEST_BODY', 'REQUEST_URI|ARGS',
])
const ALLOWED_OPERATORS = new Set([
  'contains', 'streq', 'beginsWith', 'endsWith', 'rx', 'pm', 'eq', 'ge', 'le', 'gt', 'lt',
])
const ALLOWED_ACTIONS = new Set(['deny', 'pass', 'allow', 'drop', 'log', 'block'])
const ALLOWED_PHASES = new Set([1, 2, 3, 4, 5])

function isValidCustomRule(r) {
  if (!r || typeof r !== 'object') return 'Rule must be an object'
  if (!ALLOWED_VARIABLES.has(r.variable || 'ARGS')) return `Unsupported variable: ${r.variable}`
  if (!ALLOWED_OPERATORS.has(r.operator || 'contains')) return `Unsupported operator: ${r.operator}`
  if (!ALLOWED_ACTIONS.has(r.action || 'deny')) return `Unsupported action: ${r.action}`
  if (!ALLOWED_PHASES.has(Number(r.phase || 2))) return `Phase must be 1-5`
  if (typeof r.value !== 'string' || r.value.length === 0 || r.value.length > 512) return 'value must be a non-empty string (max 512 chars)'
  if (typeof r.name !== 'string' || r.name.length === 0 || r.name.length > 128) return 'name must be a non-empty string (max 128 chars)'
  if (r.id !== undefined && !/^\d{1,10}$/.test(String(r.id))) return 'id must be numeric'
  return null
}

function isValidExclusion(e) {
  if (!e || typeof e !== 'object') return 'Exclusion must be an object'
  if (!/^\d{1,10}(-\d{1,10})?$/.test(String(e.rule_id || ''))) return 'rule_id must be numeric (or a numeric range)'
  if (typeof e.target !== 'string' || e.target.length === 0 || e.target.length > 128) return 'target must be a non-empty string'
  if (typeof e.value !== 'string' || e.value.length > 256) return 'value must be a string (max 256 chars)'
  return null
}

const VALID_HTTP_METHODS = new Set(['GET','POST','PUT','DELETE','HEAD','OPTIONS','PATCH','TRACE','CONNECT'])
function isValidMethodList(methods) {
  return Array.isArray(methods) && methods.length > 0 &&
    methods.every(m => typeof m === 'string' && VALID_HTTP_METHODS.has(m.toUpperCase()))
}

function isValidUserAgentList(list) {
  return Array.isArray(list) && list.length <= 200 &&
    list.every(u => typeof u === 'string' && u.length > 0 && u.length <= 128)
}

function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

const VALID_ENGINE_MODES = new Set(['On', 'DetectionOnly', 'Off'])

function validateWafState(incoming) {
  if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) {
    return { valid: false, errors: ['Imported config must be a JSON object'] }
  }
  const errors = []
  const clean = {}

  for (const [key, value] of Object.entries(incoming)) {
    switch (key) {
      case 'custom_rules': {
        if (!Array.isArray(value)) { errors.push('custom_rules must be an array'); break }
        const bad = []
        value.forEach((r, i) => { const err = isValidCustomRule(r); if (err) bad.push(`#${i}: ${err}`) })
        if (bad.length) errors.push(`custom_rules: ${bad.join('; ')}`)
        else clean.custom_rules = value
        break
      }
      case 'rule_exclusions': {
        if (!Array.isArray(value)) { errors.push('rule_exclusions must be an array'); break }
        const bad = []
        value.forEach((e, i) => { const err = isValidExclusion(e); if (err) bad.push(`#${i}: ${err}`) })
        if (bad.length) errors.push(`rule_exclusions: ${bad.join('; ')}`)
        else clean.rule_exclusions = value
        break
      }
      case 'ip_blacklist':
      case 'ip_whitelist': {
        if (!Array.isArray(value)) { errors.push(`${key} must be an array`); break }
        const bad = value.filter(e => !e || !isValidIpOrCidr(e.ip))
        if (bad.length) errors.push(`${key}: ${bad.length} entr${bad.length === 1 ? 'y has' : 'ies have'} an invalid ip`)
        else clean[key] = value
        break
      }
      case 'geo_blocking': {
        if (!Array.isArray(value) || !value.every(isValidCountryCode)) errors.push('geo_blocking must be an array of 2-letter country codes')
        else clean.geo_blocking = value
        break
      }
      case 'blocked_user_agents': {
        if (!isValidUserAgentList(value)) errors.push('blocked_user_agents must be an array of strings (max 200 entries, 128 chars each)')
        else clean.blocked_user_agents = value
        break
      }
      case 'allowed_methods': {
        if (!isValidMethodList(value)) errors.push('allowed_methods must be a non-empty array of valid HTTP methods')
        else clean.allowed_methods = value
        break
      }
      case 'engine': {
        if (!VALID_ENGINE_MODES.has(value)) errors.push(`engine must be one of ${[...VALID_ENGINE_MODES].join(', ')}`)
        else clean.engine = value
        break
      }
      case 'paranoia_level':
      case 'executing_paranoia_level': {
        if (![1, 2, 3, 4].includes(value)) errors.push(`${key} must be 1-4`)
        else clean[key] = value
        break
      }
      case 'inbound_anomaly_threshold':
      case 'outbound_anomaly_threshold':
      case 'sampling_percentage':
      case 'max_request_body_size':
      case 'max_file_upload_size':
      case 'rate_limit':
      case 'retention_days': {
        if (typeof value === 'object' ? value === null : typeof value !== 'number' && typeof value !== 'boolean') {
          errors.push(`${key} has an unexpected type`)
        } else clean[key] = value
        break
      }
      case 'allowed_content_types':
      case 'header_rules':
      case 'audit_log_parts': {
        if (!Array.isArray(value)) errors.push(`${key} must be an array`)
        else clean[key] = value
        break
      }
      case 'php_exclusions':
      case 'alerts': {
        if (!value || typeof value !== 'object' || Array.isArray(value)) errors.push(`${key} must be an object`)
        else clean[key] = value
        break
      }
      case 'request_body_inspection':
      case 'response_body_inspection':
      case 'audit_log':
      case 'enforce_bodyproc_urlencoded':
      case 'early_blocking': {
        if (typeof value !== 'boolean') errors.push(`${key} must be a boolean`)
        else clean[key] = value
        break
      }
      default:
        errors.push(`Unknown field: ${key}`)
    }
  }

  return errors.length ? { valid: false, errors } : { valid: true, sanitized: clean }
}

module.exports = {
  escapeForDirective, escapeRegex,
  isValidCaddyPath, isValidIpOrCidr, isValidCountryCode,
  ipCoveredBy, normalizeClientIp,
  isValidCustomRule, isValidExclusion,
  isValidMethodList, isValidUserAgentList,
  validateWafState,
  ALLOWED_VARIABLES, ALLOWED_OPERATORS, ALLOWED_ACTIONS, ALLOWED_PHASES,
}
