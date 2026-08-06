// sites.js — the registry of hostnames CatWAF considers "ours" (idea #65).
//
// CatWAF Free is deliberately single-site (see the editions knowledge doc:
// one site, one admin, no fleet management). That is an edition boundary,
// not an oversight — but several features now need to answer "which hosts
// are legitimate?" (reject-unknown-Host, the catch-all block, security.txt's
// canonical URL, redirect rules). Answering that from a registry rather than
// from a scattered set of env reads is what keeps the boundary a conscious
// decision: `capacity()` is the one place the limit lives, and the features
// that grew around it (templates, discovery, the proxy generator) stay
// single-site-safe because they all ask here.

const settings = require('./settings')
const edition = require('./edition')

function normalizeHost(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '')
}

function fromEnvironment() {
  const out = []
  const domain = normalizeHost(process.env.DOMAIN)
  if (domain) {
    out.push(domain)
    if (!domain.startsWith('www.')) out.push(`www.${domain}`)
  }
  for (const extra of String(process.env.CATWAF_EXTRA_HOSTS || '').split(',')) {
    const host = normalizeHost(extra)
    if (host) out.push(host)
  }
  return out
}

// Everything CatWAF is willing to serve, in precedence order: explicitly
// configured hosts first, then the site registry, then the environment.
function knownHosts() {
  const access = settings.get('access')
  const site = settings.get('sites')
  const hosts = [
    ...access.known_hosts,
    site.primary_host,
    ...site.aliases,
    ...fromEnvironment(),
  ].map(normalizeHost).filter(Boolean)
  return [...new Set(hosts)]
}

function primaryHost() {
  const site = settings.get('sites')
  if (site.primary_host) return normalizeHost(site.primary_host)
  return knownHosts()[0] || null
}

// The edition limit, in one place. Free returns 1; the schema caps the
// setting at 1 too, so raising it is a deliberate two-file change rather
// than something that can drift in accidentally.
function capacity() {
  const configured = settings.get('sites').max_sites
  return { max: edition.isFull() ? configured : 1, edition: edition.current() }
}

function canAddSite(currentCount) {
  const { max } = capacity()
  if (currentCount < max) return { ok: true }
  return {
    ok: false,
    code: 'SITE_LIMIT',
    message: `CatWAF Free protects one site. Fleet management across multiple independent sites is not part of this edition — see the editions documentation. Aliases of the same site can be added under Protected sites.`,
  }
}

function describe() {
  const hosts = knownHosts()
  return {
    primary: primaryHost(),
    hosts,
    aliases: settings.get('sites').aliases,
    capacity: capacity(),
    source: settings.get('sites').primary_host
      ? 'configured'
      : (process.env.DOMAIN ? 'environment' : 'unset'),
  }
}

module.exports = { knownHosts, primaryHost, capacity, canAddSite, describe, normalizeHost }
