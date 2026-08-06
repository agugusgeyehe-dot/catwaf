// caddyModules.js — what the installed Caddy binary can actually do.
//
// Most of what CatWAF renders is stock Caddy. A handful of settings need a
// module that only exists in a custom build (response caching, HTML
// injection, DNS-01 providers, per-IP connection limiting). Rendering those
// directives against a binary that lacks the module does not fail politely
// — `caddy validate` rejects the whole file, so a single unavailable feature
// would take the entire configuration down.
//
// So renderers ask here first, skip the directive when the module is
// missing, and record the omission. The API surfaces those records, which is
// how the dashboard can say "this needs a Caddy build with X" instead of the
// setting silently doing nothing.

const { execFileSync } = require('child_process')

const CACHE_TTL_MS = 60_000

let cached = null
let cachedAt = 0

function readModules() {
  try {
    return execFileSync('caddy', ['list-modules'], { timeout: 8000, stdio: ['ignore', 'pipe', 'pipe'] })
      .toString()
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.includes(' ') && !l.startsWith('Standard') && !l.startsWith('Non-standard'))
  } catch {
    return null
  }
}

function readVersion() {
  try {
    const out = execFileSync('caddy', ['version'], { timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] }).toString()
    const m = /v?(\d+)\.(\d+)\.(\d+)/.exec(out)
    if (!m) return null
    return { raw: out.trim().split('\n')[0], major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) }
  } catch {
    return null
  }
}

function load(force = false) {
  const now = Date.now()
  if (!force && cached && now - cachedAt < CACHE_TTL_MS) return cached
  const modules = readModules()
  cached = {
    available: modules !== null,
    modules: modules || [],
    version: readVersion(),
  }
  cachedAt = now
  return cached
}

function hasModule(id) {
  const info = load()
  // With no binary to ask (CI, a container that only runs the API), assume
  // the module is absent: skipping an optional directive is recoverable,
  // emitting one Caddy cannot load is not.
  if (!info.available) return false
  return info.modules.includes(id)
}

// Caddy renamed `basicauth` to `basic_auth` in 2.8; the old spelling is
// still accepted but deprecated, and the new one does not exist before it.
function basicAuthDirective() {
  const v = load().version
  if (!v) return 'basic_auth'
  return (v.major > 2 || (v.major === 2 && v.minor >= 8)) ? 'basic_auth' : 'basicauth'
}

// Features that need something beyond a stock build, with the message the
// dashboard shows when one is missing.
const OPTIONAL = {
  cache: {
    module: 'http.handlers.cache',
    label: 'Upstream response caching',
    hint: 'Needs a Caddy build including the HTTP cache handler (for example github.com/caddyserver/cache-handler).',
  },
  replace_response: {
    module: 'http.handlers.replace_response',
    label: 'HTML injection',
    hint: 'Needs a Caddy build including github.com/caddyserver/replace-response.',
  },
  rate_limit: {
    module: 'http.handlers.rate_limit',
    label: 'Per-client connection limiting',
    hint: 'Needs a Caddy build including github.com/mholt/caddy-ratelimit. Connection timeouts and HTTP/2 stream limits are applied without it.',
  },
  coraza: {
    module: 'http.handlers.waf',
    label: 'Coraza WAF',
    hint: 'CatWAF\'s own installer builds Caddy with github.com/corazawaf/coraza-caddy.',
  },
}

function dnsProviderModule(provider) {
  return `dns.providers.${provider}`
}

function checkFeature(name) {
  const spec = OPTIONAL[name]
  if (!spec) return { ok: true }
  if (hasModule(spec.module)) return { ok: true, module: spec.module }
  return { ok: false, feature: name, label: spec.label, module: spec.module, hint: spec.hint }
}

function checkDnsProvider(provider) {
  if (!provider || provider === 'none') return { ok: false, feature: 'dns-01', label: 'ACME DNS-01 challenge', hint: 'Choose a DNS provider first.' }
  const module = dnsProviderModule(provider)
  if (hasModule(module)) return { ok: true, module }
  return {
    ok: false, feature: 'dns-01', label: `ACME DNS-01 (${provider})`, module,
    hint: `Needs a Caddy build including the ${provider} DNS provider module (xcaddy build --with github.com/caddy-dns/${provider}).`,
  }
}

function summary() {
  const info = load()
  const features = {}
  for (const name of Object.keys(OPTIONAL)) features[name] = checkFeature(name)
  return {
    binary_available: info.available,
    version: info.version ? info.version.raw : null,
    module_count: info.modules.length,
    basic_auth_directive: basicAuthDirective(),
    features,
  }
}

module.exports = {
  load, hasModule, checkFeature, checkDnsProvider, dnsProviderModule,
  basicAuthDirective, summary, OPTIONAL,
  refresh: () => load(true),
}
