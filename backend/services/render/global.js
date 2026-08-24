// render/global.js — the directives CatWAF manages inside Caddy's global
// options block, plus the catch-all site block that answers idea #55.
//
// Global options are the only place several of these can live: listener
// wrappers (PROXY protocol), trusted proxies, protocol selection and server
// timeouts are all per-server settings, not per-site ones. Keeping them in
// their own marked region means CatWAF can rewrite them wholesale without
// touching whatever else the operator put in the global block.

const cloudflareSvc = require('../cloudflare')
const sites = require('../sites')
const { q, dur, block, indent } = require('./util')

const PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.1/32', '::1/128', 'fc00::/7']

function trustedRanges(realIp) {
  if (realIp.preset === 'private') return PRIVATE_RANGES
  if (realIp.preset === 'cloudflare') {
    const ranges = typeof cloudflareSvc.edgeRanges === 'function' ? cloudflareSvc.edgeRanges() : []
    return ranges.length ? ranges : realIp.trusted_proxies
  }
  return realIp.trusted_proxies
}

function build(overrides = {}) {
  const settings = overrides.settings || require('../settings')
  const get = g => settings.get(g)
  const out = { lines: [], skipped: [], notes: [] }

  const access = get('access')
  const realIp = get('real_ip')
  const conns = get('connections')
  const proxy = get('proxy')
  const tls = get('tls')
  const raw = get('raw_config')

  // ── ACME account + provider (#23) ──
  if (tls.acme_email) out.lines.push(`email ${q(tls.acme_email)}`)
  if (tls.cert_source === 'acme' && tls.acme_provider === 'custom' && tls.acme_ca_url) {
    out.lines.push(`acme_ca ${q(tls.acme_ca_url)}`)
  }

  // ── #59 disable plaintext HTTP ──
  if (access.disable_plain_http) {
    out.lines.push('auto_https disable_redirects')
    out.notes.push('Caddy no longer opens a plaintext listener to redirect — port 80 simply does not answer.')
  }

  // ── servers { } ──
  const server = []

  // #31 protocol selection
  const protocols = ['h1']
  if (proxy.http2) protocols.push('h2')
  if (proxy.http3) protocols.push('h3')
  if (protocols.length !== 2 || !proxy.http2) server.push(`protocols ${protocols.join(' ')}`)
  if (proxy.http3) out.notes.push('HTTP/3 also needs UDP open on the same port as HTTPS.')

  // ── Anti-DDoS (#75): emergency mode is enforced at classification time
  // (enforce.js / challenge). Slowloris-resistant connection timeouts live
  // in the `connections` group above (#18) — deliberately the single source
  // of truth rather than a second knob set fighting over servers.timeouts.

  // #55 SNI half — refuse a TLS handshake whose SNI is not a known host.
  if (access.reject_unknown_host) {
    const hosts = sites.knownHosts()
    if (hosts.length) server.push('strict_sni_host')
    else out.skipped.push({ feature: 'reject_unknown_host', reason: 'No known hostnames are configured yet, so CatWAF cannot tell a legitimate Host from an unknown one. Set a primary hostname under Protected sites.' })
  }

  // #16 real client IP
  if (realIp.enabled) {
    const ranges = trustedRanges(realIp)
    if (!ranges.length) {
      out.skipped.push({ feature: 'real_ip', reason: 'Trusting an upstream proxy needs at least one trusted CIDR — without it, any client could forge its own address.' })
    } else {
      server.push(`trusted_proxies static ${ranges.map(q).join(' ')}`)
      server.push(`client_ip_headers ${q(realIp.header)}`)
      if (realIp.recursive) server.push('trusted_proxies_strict')
      out.notes.push(`Client IP is read from ${realIp.header} for requests arriving from ${ranges.length} trusted range(s).`)
    }
  }

  // #17 PROXY protocol
  if (realIp.proxy_protocol) {
    const allow = realIp.proxy_protocol_allow.length ? realIp.proxy_protocol_allow : trustedRanges(realIp)
    if (!allow.length) {
      out.skipped.push({ feature: 'proxy_protocol', reason: 'Accepting the PROXY protocol from anywhere would let any client claim any source address — configure the load balancer\'s CIDR first.' })
    } else {
      server.push(...block('listener_wrappers', [
        ...block('proxy_protocol', ['timeout 2s', `allow ${allow.map(q).join(' ')}`]),
        'tls',
      ]))
      out.notes.push('The PROXY protocol header is read from the load balancer before TLS.')
    }
  }

  // #48 protocol limits
  if (access.max_header_size_kb > 0) server.push(`max_header_size ${access.max_header_size_kb}KB`)
  if (access.file_cache_size > 0) {
    out.skipped.push({
      feature: 'file_cache',
      reason: 'Caddy serves files without a tunable open-descriptor cache, so this value is recorded but has no directive to render. It is surfaced here rather than silently dropped.',
    })
  }

  // #18 connection limits — the timeout half is native; the per-IP
  // concurrency half needs a module and is reported when it is missing.
  if (conns.enabled) {
    const timeouts = []
    if (conns.idle_timeout_sec > 0) timeouts.push(`idle ${dur(conns.idle_timeout_sec)}`)
    if (conns.read_timeout_sec > 0) timeouts.push(`read_body ${dur(conns.read_timeout_sec)}`, `read_header ${dur(Math.min(conns.read_timeout_sec, 60))}`)
    if (conns.write_timeout_sec > 0) timeouts.push(`write ${dur(conns.write_timeout_sec)}`)
    if (timeouts.length) server.push(...block('timeouts', timeouts))
    out.notes.push(`Idle connections are closed after ${dur(conns.idle_timeout_sec)}.`)

    const caddyModules = require('../caddyModules')
    const feature = caddyModules.checkFeature('rate_limit')
    if (!feature.ok) {
      out.skipped.push({ feature: 'connection_limits', reason: feature.hint, module: feature.module })
    }
  }

  if (get('metrics').enabled) server.push('metrics')

  if (server.length) out.lines.push(...block('servers', server))

  // ── #62 raw global injection ──
  if (raw.enabled && raw.global_http.trim()) {
    out.lines.push('# ── unmanaged: raw global directives ──')
    out.lines.push(...raw.global_http.split('\n'))
  }

  return out
}

// ─── #55 catch-all site block ──────────────────────────────────────────
//
// Emitted as its own top-level block so an unknown Host is answered by
// CatWAF rather than falling through to whichever site block happens to be
// first. Known hosts still get their normal HTTP→HTTPS redirect, which is
// why this cannot simply be `:80 { abort }`.
function buildCatchAll(overrides = {}) {
  const settings = overrides.settings || require('../settings')
  const access = settings.get('access')
  const raw = settings.get('raw_config')
  if (!access.reject_unknown_host) return { lines: [], skipped: [], notes: [] }

  const hosts = sites.knownHosts()
  if (!hosts.length) {
    return {
      lines: [],
      skipped: [{ feature: 'reject_unknown_host', reason: 'No known hostnames configured — set a primary hostname under Protected sites before turning this on.' }],
      notes: [],
    }
  }

  const body = []
  body.push(`@catwaf_known host ${hosts.map(q).join(' ')}`)
  body.push(`redir @catwaf_known https://{host}{uri} 308`)
  body.push(access.unknown_host_action === 'status' ? `respond ${access.blocked_status_code}` : 'abort')
  if (raw.enabled && raw.catch_all.trim()) {
    body.push('# ── unmanaged: raw catch-all directives ──')
    body.push(...raw.catch_all.split('\n'))
  }

  return {
    lines: [
      '# Any request whose Host is not one of the hostnames below is refused here',
      '# rather than reaching a site block by accident (origin-exposure.md).',
      ':80 {',
      ...indent(body, 1),
      '}',
    ],
    skipped: [],
    notes: [`Unknown Host headers are ${access.unknown_host_action === 'status' ? `answered with ${access.blocked_status_code}` : 'dropped'}; ${hosts.length} hostname(s) are recognised.`],
  }
}

module.exports = { build, buildCatchAll, trustedRanges, PRIVATE_RANGES }
