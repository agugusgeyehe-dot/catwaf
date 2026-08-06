// intel/dnsbl.js — DNS blackhole list lookups (idea #11).
//
// A DNSBL answer is a reversed-octet A query against a published zone: if
// 1.2.3.4 is listed on bl.example.org, 4.3.2.1.bl.example.org resolves.
// It is threat intelligence CatWAF does not have to source or maintain, and
// it is complementary to the manual blocklist rather than a replacement.
//
// Results are cached per address *and per zone* — an address is often listed
// on one zone and not another, and a shared cache key would make the first
// answer stand for all of them.

const dns = require('dns')

const cache = require('./cache')
const settings = require('../settings')
const netGuard = require('../netGuard')
const { normalizeClientIp } = require('../sanitize')

const NS = 'dnsbl'
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/

function reverseOctets(ip) {
  return ip.split('.').reverse().join('.')
}

function resolve4(name, timeoutMs) {
  const resolver = new dns.Resolver({ timeout: timeoutMs, tries: 1 })
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { try { resolver.cancel() } catch {} ; reject(new Error('timeout')) }, timeoutMs + 200)
    resolver.resolve4(name, (err, addrs) => {
      clearTimeout(timer)
      if (err) reject(err)
      else resolve(addrs)
    })
  })
}

// Optional TXT explanation. Only fetched once a zone has already said "yes",
// so a clean address costs exactly one query per zone.
async function reason(query, timeoutMs) {
  const resolver = new dns.Resolver({ timeout: timeoutMs, tries: 1 })
  return new Promise(resolve => {
    const timer = setTimeout(() => { try { resolver.cancel() } catch {} ; resolve(null) }, timeoutMs + 200)
    resolver.resolveTxt(query, (err, records) => {
      clearTimeout(timer)
      resolve(err || !records?.length ? null : records[0].join('').slice(0, 200))
    })
  })
}

async function checkZone(ip, zone, { timeoutMs = 1200, cacheMinutes = 120 } = {}) {
  const query = `${reverseOctets(ip)}.${String(zone).replace(/^\.|\.$/g, '')}`
  return cache.through(`${NS}:${zone}`, ip, cacheMinutes * 60 * 1000, async () => {
    try {
      const addrs = await resolve4(query, timeoutMs)
      if (!addrs.length) return { listed: false }
      return { listed: true, codes: addrs, reason: await reason(query, timeoutMs) }
    } catch (e) {
      // NXDOMAIN is the normal "not listed" answer, not an error.
      if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return { listed: false }
      return { listed: false, error: e.code || e.message }
    }
  })
}

async function lookup(ip, opts = {}) {
  const cfg = { ...settings.get('dnsbl'), ...opts }
  const addr = normalizeClientIp(String(ip || '').trim())
  if (!IPV4_RE.test(addr)) return { listed: false, skipped: 'DNSBL zones answer for IPv4 addresses only' }
  if (cfg.global_only && !netGuard.isPubliclyRoutable(addr)) return { listed: false, skipped: 'private address' }
  if (!cfg.zones.length) return { listed: false, skipped: 'no zones configured' }

  const hits = []
  const errors = []
  const results = await Promise.all(cfg.zones.map(async zone => {
    try {
      const r = await checkZone(addr, zone, { timeoutMs: cfg.timeout_ms, cacheMinutes: cfg.cache_minutes })
      return { zone, ...r }
    } catch (e) {
      return { zone, listed: false, error: e.message }
    }
  }))
  for (const r of results) {
    if (r.listed) hits.push(r)
    else if (r.error) errors.push({ zone: r.zone, error: r.error })
  }

  return { listed: hits.length > 0, hits, errors, checked: cfg.zones.length }
}

async function evaluate(ip) {
  const cfg = settings.get('dnsbl')
  if (!cfg.enabled || !cfg.zones.length) return null
  const result = await lookup(ip)
  if (!result.listed) return null
  const zones = result.hits.map(h => h.zone).join(', ')
  const detail = result.hits.find(h => h.reason)?.reason
  return {
    decision: cfg.action === 'ban' ? 'ban' : cfg.action === 'challenge' ? 'challenge' : 'flag',
    banSeconds: cfg.ban_seconds,
    source: 'dnsbl',
    reason: `Listed on ${zones}${detail ? ` — ${detail}` : ''}.`,
    zones: result.hits.map(h => h.zone),
  }
}

module.exports = { lookup, evaluate, checkZone, reverseOctets, NS }
