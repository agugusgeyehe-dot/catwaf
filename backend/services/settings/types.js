// settings/types.js — field validators for the extended settings schema.
//
// Every value that reaches this module is eventually interpolated into a
// generated Caddyfile, so validation here is the injection boundary, not a
// convenience. The rule is the same one services/sanitize.js applies to WAF
// rules: reject anything that could terminate a directive, a block or a
// quoted string, rather than trying to escape it afterwards.

const { isValidIpOrCidr, isValidCountryCode } = require('../sanitize')

// Characters that end a token, a block, a quoted string or a heredoc in the
// Caddyfile grammar. Nothing carrying one of these is ever a valid setting
// value, so they are refused outright instead of escaped.
const UNSAFE = /[`"'{}\\\r\n\t\0]/

function isSafeToken(value, maxLen = 256) {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLen && !UNSAFE.test(value)
}

const HTTP_METHODS = new Set([
  'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT',
  'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'REPORT',
])

const HEADER_NAME_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/
const MIME_RE = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*\/[A-Za-z0-9*][A-Za-z0-9!#$&^_.+-]*$/
const HOSTNAME_RE = /^(?=.{1,253}$)(\*\.)?([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/
const DNS_SUFFIX_RE = /^\.?([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z]{2,63}$/
const EXT_RE = /^\.[A-Za-z0-9]{1,12}$/

// A URI pattern usable as a Caddy path matcher: leading slash, optional
// trailing/star wildcards. Deliberately narrower than a full URL.
function isUriPattern(value) {
  return isSafeToken(value, 512) && value.startsWith('/') && !/\s/.test(value)
}

function isPemBlock(value, kinds) {
  if (typeof value !== 'string') return false
  if (value.length > 512 * 1024) return false
  const re = new RegExp(`-----BEGIN (?:${kinds.join('|')})-----[\\s\\S]+-----END (?:${kinds.join('|')})-----`)
  return re.test(value)
}

function isHttpUrl(value, { allowHttp = true } = {}) {
  if (!isSafeToken(value, 2048)) return false
  let u
  try { u = new URL(value) } catch { return false }
  if (u.protocol === 'https:') return true
  return allowHttp && u.protocol === 'http:'
}

// host:port, ip:port or [ipv6]:port — the same shape proxy/generator.js
// accepts for an upstream, plus optional scheme prefixes Caddy understands.
const UPSTREAM_RE = /^(?:(?:https?|h2c|unix):\/\/)?(?:[A-Za-z0-9][A-Za-z0-9_.-]*|\[[0-9A-Fa-f:]+\]|\/[A-Za-z0-9._/-]+)(?::\d{1,5})?$/

const ITEM_VALIDATORS = {
  cidr: v => isValidIpOrCidr(v) ? null : `"${v}" is not a valid IP address or CIDR range`,
  country: v => isValidCountryCode(String(v || '').toUpperCase()) ? null : `"${v}" is not a 2-letter country code`,
  method: v => HTTP_METHODS.has(String(v || '').toUpperCase()) ? null : `"${v}" is not a supported HTTP method`,
  uri: v => isUriPattern(v) ? null : `"${v}" is not a valid URI pattern (must start with /)`,
  host: v => (isSafeToken(v, 253) && HOSTNAME_RE.test(v)) ? null : `"${v}" is not a valid hostname`,
  dnssuffix: v => (isSafeToken(v, 253) && DNS_SUFFIX_RE.test(v)) ? null : `"${v}" is not a valid DNS suffix`,
  asn: v => /^(AS)?\d{1,10}$/i.test(String(v || '')) ? null : `"${v}" is not a valid AS number`,
  header: v => HEADER_NAME_RE.test(String(v || '')) ? null : `"${v}" is not a valid HTTP header name`,
  mime: v => (isSafeToken(v, 128) && MIME_RE.test(v)) ? null : `"${v}" is not a valid MIME type`,
  ext: v => EXT_RE.test(String(v || '')) ? null : `"${v}" is not a valid file extension (e.g. .css)`,
  url: v => isHttpUrl(v) ? null : `"${v}" is not a valid http(s) URL`,
  upstream: v => (isSafeToken(v, 256) && UPSTREAM_RE.test(v)) ? null : `"${v}" is not a valid upstream (host:port)`,
  token: v => isSafeToken(v) ? null : `"${v}" contains characters that are not allowed in a configuration value`,
  ua: v => (typeof v === 'string' && v.length > 0 && v.length <= 128 && !/[\r\n]/.test(v)) ? null : `"${v}" is not a valid user-agent pattern`,
}

function normalizeItem(kind, value) {
  const s = String(value).trim()
  if (kind === 'country') return s.toUpperCase()
  if (kind === 'method') return s.toUpperCase()
  if (kind === 'asn') return 'AS' + s.replace(/^AS/i, '')
  if (kind === 'dnssuffix') return s.toLowerCase()
  if (kind === 'host') return s.toLowerCase()
  return s
}

// Validates one field against its spec. Returns { error } or { value }.
function validateField(spec, raw, path) {
  const where = path ? `${path}` : 'value'

  switch (spec.type) {
    case 'bool':
      if (typeof raw !== 'boolean') return { error: `${where} must be true or false` }
      return { value: raw }

    case 'int': {
      const n = typeof raw === 'number' ? raw : Number(raw)
      if (!Number.isFinite(n) || !Number.isInteger(n)) return { error: `${where} must be a whole number` }
      if (spec.min !== undefined && n < spec.min) return { error: `${where} must be at least ${spec.min}` }
      if (spec.max !== undefined && n > spec.max) return { error: `${where} must be at most ${spec.max}` }
      return { value: n }
    }

    case 'enum':
      if (!spec.values.includes(raw)) return { error: `${where} must be one of: ${spec.values.join(', ')}` }
      return { value: raw }

    case 'str': {
      if (typeof raw !== 'string') return { error: `${where} must be a string` }
      const s = spec.trim === false ? raw : raw.trim()
      if (s === '') return spec.required ? { error: `${where} is required` } : { value: '' }
      if (s.length > (spec.maxLen || 256)) return { error: `${where} must be at most ${spec.maxLen || 256} characters` }
      if (spec.item) {
        const err = ITEM_VALIDATORS[spec.item](s)
        if (err) return { error: `${where}: ${err}` }
        return { value: normalizeItem(spec.item, s) }
      }
      if (!isSafeToken(s, spec.maxLen || 256)) {
        return { error: `${where} contains characters that are not allowed in a configuration value` }
      }
      if (spec.pattern && !spec.pattern.test(s)) return { error: spec.patternMessage || `${where} is not in the expected format` }
      return { value: s }
    }

    // Free-form multi-line text (PEM blobs, HTML snippets, raw config).
    // Never rendered as a bare token — always emitted inside a delimited
    // region or written to its own file — so newlines are allowed here.
    case 'text': {
      if (typeof raw !== 'string') return { error: `${where} must be a string` }
      if (raw.length > (spec.maxLen || 8192)) return { error: `${where} must be at most ${spec.maxLen || 8192} characters` }
      if (raw !== '' && spec.pem && !isPemBlock(raw, spec.pem)) {
        return { error: `${where} must be a PEM block (${spec.pem.join(' or ')})` }
      }
      if (raw !== '' && spec.pattern && !spec.pattern.test(raw)) {
        return { error: spec.patternMessage || `${where} is not in the expected format` }
      }
      return { value: raw }
    }

    case 'list': {
      if (!Array.isArray(raw)) return { error: `${where} must be an array` }
      if (raw.length > (spec.max || 200)) return { error: `${where} may hold at most ${spec.max || 200} entries` }
      const out = []
      for (const [i, item] of raw.entries()) {
        if (typeof item !== 'string') return { error: `${where}[${i}] must be a string` }
        const s = item.trim()
        if (!s) continue
        const err = ITEM_VALIDATORS[spec.item](s)
        if (err) return { error: `${where}[${i}]: ${err}` }
        out.push(normalizeItem(spec.item, s))
      }
      return { value: spec.unique === false ? out : [...new Set(out)] }
    }

    case 'records': {
      if (!Array.isArray(raw)) return { error: `${where} must be an array` }
      if (raw.length > (spec.max || 100)) return { error: `${where} may hold at most ${spec.max || 100} entries` }
      const out = []
      for (const [i, item] of raw.entries()) {
        if (!item || typeof item !== 'object' || Array.isArray(item)) return { error: `${where}[${i}] must be an object` }
        const rec = {}
        for (const [name, sub] of Object.entries(spec.fields)) {
          const has = Object.hasOwn(item, name)
          const value = has ? item[name] : sub.default
          const r = validateField(sub, value, `${where}[${i}].${name}`)
          if (r.error) return { error: r.error }
          rec[name] = r.value
        }
        const unknown = Object.keys(item).filter(k => !Object.hasOwn(spec.fields, k))
        if (unknown.length) return { error: `${where}[${i}]: unknown field(s) ${unknown.join(', ')}` }
        out.push(rec)
      }
      return { value: out }
    }

    case 'map': {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { error: `${where} must be an object` }
      const keys = Object.keys(raw)
      if (keys.length > (spec.max || 100)) return { error: `${where} may hold at most ${spec.max || 100} entries` }
      const out = {}
      for (const key of keys) {
        const keyErr = ITEM_VALIDATORS[spec.key](key)
        if (keyErr) return { error: `${where}: ${keyErr}` }
        const r = validateField(spec.value, raw[key], `${where}.${key}`)
        if (r.error) return { error: r.error }
        out[normalizeItem(spec.key, key)] = r.value
      }
      return { value: out }
    }

    default:
      return { error: `${where} has an unsupported field type "${spec.type}"` }
  }
}

module.exports = {
  validateField, isSafeToken, isUriPattern, isPemBlock, isHttpUrl,
  ITEM_VALIDATORS, HTTP_METHODS, HEADER_NAME_RE, MIME_RE, HOSTNAME_RE, UPSTREAM_RE,
}
