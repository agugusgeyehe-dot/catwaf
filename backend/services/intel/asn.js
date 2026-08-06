// intel/asn.js — origin-network (AS number) lookup and allow/block matching
// (idea #7).
//
// Country blocking is a whole nation and IP blocking is one address; ASN
// sits usefully between them — "block this hosting provider's entire
// announced range" without hand-maintaining CIDRs that change monthly.
//
// Resolution strategy, in order:
//   1. A locally configured CIDR→ASN map (CATWAF_ASN_MAP), for offline and
//      air-gapped installs.
//   2. Team Cymru's DNS-based origin lookup — a plain TXT query, so it needs
//      no new dependency and no API key, and its answers are cacheable.
// Anything unresolved stays `null`, and a null ASN never matches a block
// rule: an unavailable lookup must not turn into a blocked visitor.

const fs = require('fs')
const dns = require('dns')

const cache = require('./cache')
const settings = require('../settings')
const geoip = require('../geoip')
const { ipCoveredBy, normalizeClientIp } = require('../sanitize')

const NS = 'asn'
const CACHE_TTL_MS = 6 * 60 * 60 * 1000

let localMap = null

function loadLocalMap() {
  if (localMap !== null) return localMap
  localMap = []
  const file = process.env.CATWAF_ASN_MAP
  if (!file) return localMap
  try {
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith('#')) continue
      const [cidr, asn, ...rest] = trimmed.split(/[\s,]+/)
      if (!cidr || !asn) continue
      localMap.push({ cidr, asn: normalizeAsn(asn), name: rest.join(' ') || null })
    }
  } catch { /* an unreadable map is the same as no map */ }
  return localMap
}

function normalizeAsn(value) {
  const s = String(value || '').trim().replace(/^AS/i, '')
  return /^\d{1,10}$/.test(s) ? `AS${s}` : null
}

function reverseV4(ip) {
  return ip.split('.').reverse().join('.')
}

function resolveTxt(name, timeoutMs) {
  return new Promise((resolve, reject) => {
    const resolver = new dns.Resolver({ timeout: timeoutMs, tries: 1 })
    const timer = setTimeout(() => { try { resolver.cancel() } catch {} ; reject(new Error('lookup timed out')) }, timeoutMs + 200)
    resolver.resolveTxt(name, (err, records) => {
      clearTimeout(timer)
      if (err) reject(err)
      else resolve(records.map(r => r.join('')))
    })
  })
}

// "13335 | 104.16.0.0/13 | US | arin | 2010-07-09"
function parseCymruOrigin(records) {
  for (const record of records) {
    const parts = record.split('|').map(s => s.trim())
    const asn = normalizeAsn((parts[0] || '').split(/\s+/)[0])
    if (asn) return { asn, prefix: parts[1] || null, country: parts[2] || null }
  }
  return null
}

async function lookupName(asn, timeoutMs) {
  try {
    const records = await resolveTxt(`${asn.replace(/^AS/, 'AS')}.asn.cymru.com`, timeoutMs)
    const parts = (records[0] || '').split('|').map(s => s.trim())
    return parts[4] || null
  } catch { return null }
}

// Returns { asn, name, prefix, source } or null. Never throws.
async function lookup(ip, { timeoutMs = 2000, withName = false } = {}) {
  const addr = normalizeClientIp(String(ip || '').trim())
  if (!addr || geoip.isPrivateIp(addr)) return null

  for (const entry of loadLocalMap()) {
    if (ipCoveredBy(addr, entry.cidr)) return { asn: entry.asn, name: entry.name, prefix: entry.cidr, source: 'local-map' }
  }

  // IPv6 origin lookup uses a different zone and nibble format; only IPv4 is
  // resolved over DNS here, and an IPv6 visitor simply has no ASN rather
  // than a wrong one.
  if (addr.includes(':')) return null

  try {
    return await cache.through(NS, addr, CACHE_TTL_MS, async () => {
      const records = await resolveTxt(`${reverseV4(addr)}.origin.asn.cymru.com`, timeoutMs)
      const parsed = parseCymruOrigin(records)
      if (!parsed) return null
      const name = withName ? await lookupName(parsed.asn, timeoutMs) : null
      return { ...parsed, name, source: 'dns' }
    })
  } catch {
    return null
  }
}

// The allow/block decision for one address. `null` means "no opinion" so the
// caller can carry on with its other checks.
async function evaluate(ip) {
  const cfg = settings.get('asn_lists')
  if (!cfg.enabled) return null
  if (!cfg.allow.length && !cfg.block.length && cfg.mode !== 'allowlist') return null

  const info = await lookup(ip)
  const asn = info ? info.asn : null

  if (asn && cfg.allow.includes(asn)) {
    return { decision: 'allow', asn, name: info.name, reason: `Origin network ${asn} is explicitly allowed.` }
  }

  if (cfg.mode === 'allowlist') {
    if (!asn) {
      // Refusing every unresolvable address would block most IPv6 traffic and
      // anything Cymru does not answer for. Say so instead of doing it.
      return { decision: 'flag', asn: null, reason: 'ASN allowlist mode is on but this address\'s origin network could not be resolved, so it was not blocked.' }
    }
    if (!cfg.allow.includes(asn)) {
      return { decision: 'block', asn, name: info.name, reason: `Origin network ${asn} is not on the ASN allowlist.` }
    }
    return null
  }

  if (asn && cfg.block.includes(asn)) {
    return { decision: 'block', asn, name: info.name, reason: `Origin network ${asn}${info.name ? ` (${info.name})` : ''} is blocked.` }
  }
  return null
}

function available() {
  return {
    local_map: !!process.env.CATWAF_ASN_MAP,
    local_entries: loadLocalMap().length,
    dns_lookup: true,
    note: 'ASN is resolved over DNS (Team Cymru) and cached; set CATWAF_ASN_MAP to a "CIDR ASN name" file to resolve entirely offline.',
  }
}

module.exports = { lookup, evaluate, normalizeAsn, available, NS, _parseCymruOrigin: parseCymruOrigin }
