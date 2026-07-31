
const { isValidIpOrCidr } = require('../sanitize')

function fold(s) {
  return String(s)
    .normalize('NFD').replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/[^a-z\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function buildCountryMap() {
  const map = new Map()
  let dn
  try { dn = new Intl.DisplayNames(['en'], { type: 'region' }) } catch { return map }
  for (let a = 65; a <= 90; a++) {
    for (let b = 65; b <= 90; b++) {
      const cc = String.fromCharCode(a, b)
      let name
      try { name = dn.of(cc) } catch { continue }
      if (!name || name === cc) continue
      const folded = fold(name)
      if (folded) map.set(folded, cc)
    }
  }
  const aliases = {
    usa: 'US', us: 'US', america: 'US', 'the us': 'US', 'united states': 'US',
    uk: 'GB', britain: 'GB', 'great britain': 'GB', england: 'GB', scotland: 'GB', wales: 'GB',
    uae: 'AE', emirates: 'AE',
    'south korea': 'KR', 'north korea': 'KP', 'korea': 'KR',
    holland: 'NL', 'the netherlands': 'NL',
    russia: 'RU', 'russian federation': 'RU',
    vietnam: 'VN', czechia: 'CZ', 'czech republic': 'CZ',
    turkiye: 'TR', turkey: 'TR', 'ivory coast': 'CI',
    burma: 'MM', swaziland: 'SZ', macedonia: 'MK', 'cape verde': 'CV',
  }
  for (const [k, v] of Object.entries(aliases)) map.set(fold(k), v)
  return map
}
const COUNTRIES = buildCountryMap()

const AMBIGUOUS = new Set(['turkey', 'chad', 'jordan', 'georgia', 'mali', 'niger', 'chile', 'guinea', 'togo'])
const GEO_CUE = /\b(countr\w*|nation\w*|region|geo|traffic|visitors?|users?|from|based in|located)\b/i

const COUNTRY_NAMES = [...COUNTRIES.keys()].sort((a, b) => b.length - a.length)

function findCountry(text) {
  const lower = ' ' + fold(text) + ' '
  for (const name of COUNTRY_NAMES) {
    if (!lower.includes(' ' + name + ' ')) continue
    if (AMBIGUOUS.has(name) && !GEO_CUE.test(text)) continue
    return { cc: COUNTRIES.get(name), name }
  }
  return null
}

const ALLOW_RE  = /\b(unblock|un-block|allow|whitelist|white-list|allow-?list|permit|exempt|let\s+(?:them|him|her|it)?\s*(?:through|in)|stop\s+blocking)\b/i
const BLOCK_RE  = /\b(block|ban|blacklist|black-list|deny|drop|stop|refuse|reject|kick)\b/i
const ENABLE_RE = /\b(enable|turn\s+on|switch\s+on|activate|start)\b/i

const IP_RE = /\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b|\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:\/\d{1,3})?\b/

const WORD_NUM = { one: 1, two: 2, three: 3, four: 4 }

function findIp(text) {
  const m = IP_RE.exec(text)
  if (!m) return null
  const candidate = m[0]
  return isValidIpOrCidr(candidate) ? candidate : null
}

const EXPLANATORY_RE = /^\s*(what|what's|whats|whats|how|why|when|which|who|explain|describe|tell me|show me|does|do|is|are|can i|should i)\b/i

const CHANGE_VERB_RE = /\b(set|make|change|raise|lower|increase|decrease|bump|turn|enable|disable|activate|block|allow|unblock|ban|add|remove|delete|apply|configure|put)\b/i

function findParanoiaLevel(text) {
  const digit = /\b(?:level|pl|paranoia)\s*[:=]?\s*([1-4])\b/i.exec(text) || /\b([1-4])\b/.exec(text)
  if (digit) return Number(digit[1])
  const word = /\b(one|two|three|four)\b/i.exec(text)
  if (word) return WORD_NUM[word[1].toLowerCase()]
  return null
}

function findTtlMinutes(text) {
  const m = /\b(\d{1,4})\s*(minutes?|mins?|hours?|hrs?|days?)\b/i.exec(text)
  if (!m) return null
  const n = Number(m[1]); const unit = m[2].toLowerCase()
  if (unit.startsWith('h')) return n * 60
  if (unit.startsWith('d')) return n * 1440
  return n
}

function extractAction(message) {
  if (typeof message !== 'string' || !message.trim()) return null
  const text = message.trim().slice(0, 500)

  if (EXPLANATORY_RE.test(text) && !CHANGE_VERB_RE.test(text)) return null

  const wantsAllow = ALLOW_RE.test(text)
  const wantsBlock = !wantsAllow && BLOCK_RE.test(text)
  const wantsEnable = ENABLE_RE.test(text)
  const ip = findIp(text)

  if (/\bparanoia\b/i.test(text) || /\bpl\s*[1-4]\b/i.test(text)) {
    const level = findParanoiaLevel(text)
    if (level) return { actionId: 'paranoia.set', params: { level }, complete: true }
    return { actionId: 'paranoia.set', params: {}, complete: false, missing: 'level' }
  }

  if (wantsAllow) {
    const unblockCountry = findCountry(text)
    if (!ip && unblockCountry) {
      return { actionId: 'geo.unblock', params: unblockCountry, complete: true }
    }
    if (!ip) {
      return { actionId: 'ip.allow', params: {}, complete: false, missing: 'ip' }
    }
    const isUnblock = /\b(unblock|un-block|stop\s+blocking)\b/i.test(text)
    return isUnblock
      ? { actionId: 'ip.unblock', params: { ip }, complete: true }
      : { actionId: 'ip.allow', params: { ip, ttl_minutes: findTtlMinutes(text) || 60 }, complete: true }
  }

  if (wantsEnable && /\brate[\s-]?limit\w*\b/i.test(text)) {
    return { actionId: 'rate_limit.enable', params: {}, complete: true }
  }
  if (wantsEnable && /\b(engine|protection|firewall|waf|blocking)\b/i.test(text)) {
    return { actionId: 'engine.enable', params: {}, complete: true }
  }

  if (wantsBlock) {
    if (ip) return { actionId: 'ip.block', params: { ip }, complete: true }

    const country = findCountry(text)
    if (country) return { actionId: 'geo.block', params: { cc: country.cc, name: country.name }, complete: true }

    const ua = /\b(?:user[\s-]?agent|ua)\b[^a-z0-9]*["'`]?([a-z0-9._\/-]{2,64})["'`]?/i.exec(text)
    if (ua) return { actionId: 'ua.block', params: { agent: ua[1] }, complete: true }

    if (/\bcountr\w*|nation\w*|region\b/i.test(text)) {
      return { actionId: 'geo.block', params: {}, complete: false, missing: 'country' }
    }
    if (/\bip\b|\baddress\b/i.test(text)) {
      return { actionId: 'ip.block', params: {}, complete: false, missing: 'ip' }
    }
  }

  return null
}

module.exports = { extractAction, findCountry, findIp, findParanoiaLevel, findTtlMinutes, COUNTRIES }
