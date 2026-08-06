// intel/rdns.js — reverse-DNS verification (idea #8).
//
// This is the standard way to tell a real Googlebot from anything that
// merely sends Googlebot's user-agent string, which UA matching alone cannot
// do. The important part is `forward_confirm`: a PTR record is controlled by
// whoever owns the address, so "PTR ends in .googlebot.com" is only
// meaningful once that name has been resolved *back* to the same address.

const dns = require('dns')

const cache = require('./cache')
const settings = require('../settings')
const netGuard = require('../netGuard')
const { normalizeClientIp } = require('../sanitize')

const NS = 'rdns'

function withResolver(timeoutMs, fn) {
  const resolver = new dns.Resolver({ timeout: timeoutMs, tries: 1 })
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { try { resolver.cancel() } catch {} ; reject(new Error('lookup timed out')) }, timeoutMs + 200)
    fn(resolver, (err, value) => {
      clearTimeout(timer)
      if (err) reject(err)
      else resolve(value)
    })
  })
}

function matchesSuffix(name, suffix) {
  if (!name || !suffix) return false
  const host = String(name).toLowerCase().replace(/\.$/, '')
  const want = String(suffix).toLowerCase().replace(/\.$/, '')
  const bare = want.startsWith('.') ? want.slice(1) : want
  return host === bare || host.endsWith(`.${bare}`)
}

// Returns { name, names, confirmed, error } — never throws.
async function lookup(ip, opts = {}) {
  const cfg = { ...settings.get('rdns_lists'), ...opts }
  const addr = normalizeClientIp(String(ip || '').trim())
  if (!addr) return { name: null, names: [], confirmed: false, error: 'no address' }
  if (cfg.global_only && !netGuard.isPubliclyRoutable(addr)) {
    return { name: null, names: [], confirmed: false, skipped: 'private address' }
  }

  const ttl = Math.max(1, cfg.cache_minutes) * 60 * 1000
  try {
    return await cache.through(NS, addr, ttl, async () => {
      let names = []
      try {
        names = await withResolver(cfg.timeout_ms, (r, cb) => r.reverse(addr, cb))
      } catch (e) {
        return { name: null, names: [], confirmed: false, error: e.code || e.message }
      }
      names = names.map(n => String(n).toLowerCase().replace(/\.$/, '')).filter(Boolean)
      if (!names.length) return { name: null, names: [], confirmed: false }

      if (!cfg.forward_confirm) return { name: names[0], names, confirmed: false }

      for (const name of names) {
        try {
          const v4 = await withResolver(cfg.timeout_ms, (r, cb) => r.resolve4(name, cb)).catch(() => [])
          const v6 = await withResolver(cfg.timeout_ms, (r, cb) => r.resolve6(name, cb)).catch(() => [])
          if ([...v4, ...v6].map(normalizeClientIp).includes(addr)) {
            return { name, names, confirmed: true }
          }
        } catch { /* try the next name */ }
      }
      return { name: names[0], names, confirmed: false, error: 'forward confirmation failed' }
    })
  } catch (e) {
    return { name: null, names: [], confirmed: false, error: e.message }
  }
}

async function evaluate(ip) {
  const cfg = settings.get('rdns_lists')
  if (!cfg.enabled) return null
  if (!cfg.allow_suffixes.length && !cfg.block_suffixes.length) return null

  const result = await lookup(ip)
  if (!result.name) return null

  // A name that failed forward confirmation is treated as *not* belonging to
  // the network it claims — the whole point of the check.
  const trusted = cfg.forward_confirm ? result.confirmed : true

  for (const suffix of cfg.block_suffixes) {
    if (matchesSuffix(result.name, suffix)) {
      return { decision: 'block', rdns: result.name, reason: `Reverse DNS ${result.name} matches the blocked suffix ${suffix}.` }
    }
  }

  for (const suffix of cfg.allow_suffixes) {
    if (!matchesSuffix(result.name, suffix)) continue
    if (!trusted) {
      return {
        decision: 'flag',
        rdns: result.name,
        reason: `${result.name} claims to be ${suffix} but its name does not resolve back to this address — treated as unverified, not as an allowed crawler.`,
      }
    }
    return { decision: 'allow', rdns: result.name, reason: `Verified crawler: ${result.name} resolves back to this address.` }
  }

  return null
}

module.exports = { lookup, evaluate, matchesSuffix, NS }
