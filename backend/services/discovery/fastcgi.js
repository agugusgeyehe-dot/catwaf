// discovery/fastcgi.js — correlate a web-server container with the
// separate PHP-FPM container it proxies to.
//
// The common production PHP layout splits the web server and the PHP
// runtime across two containers on a shared Docker network:
//
//     freshmart_nginx (nginx:alpine, :80 published)
//         │  fastcgi_pass freshmart_php:9000;
//         ▼
//     freshmart_php   (php:8.3-fpm, :9000, not published)
//
// Looking at either container alone gets this wrong: the nginx container
// has no PHP anywhere on it (so it looks static), and the PHP container
// speaks FastCGI rather than HTTP (so it looks like a non-web service).
// Only the pair, considered together, is a PHP web application.
//
// ── Correlation evidence, strongest first ─────────────────────────────
//   'config'            the web server's own config has a fastcgi_pass /
//                       fcgi:// pointing at a host that resolves to a
//                       PHP-FPM container on a shared Docker network.
//                       Unambiguous — this is the actual wiring.
//   'network-inference' the config could not be read (no shell, minimal
//                       image, exec denied), but exactly ONE PHP-FPM
//                       container shares a network with this web server.
//                       Credible, and scored lower to reflect that.
//   'local'             fastcgi_pass targets a unix socket or loopback —
//                       PHP-FPM runs inside this same container. Not a
//                       cross-container link, but still proof of PHP.
//
// Deliberately NOT inferred: a web server with no readable FastCGI config
// and no PHP-FPM container on its network stays static. Ambiguity (two or
// more candidate backends and no config to disambiguate) also yields no
// link, rather than a guess.

const webservers = require('./webservers')

const FASTCGI_PASS_RE = /fastcgi_pass\s+([^;\s]+)\s*;/g
const UPSTREAM_BLOCK_RE = /upstream\s+([A-Za-z0-9_.-]+)\s*\{([^}]*)\}/g
const UPSTREAM_SERVER_RE = /server\s+([^;\s]+)\s*;/g
const APACHE_FCGI_RE = /fcgi:\/\/([^/\s"']+)/g

// One exec that covers nginx (preferring `nginx -T`, which resolves
// includes) and the usual Apache config locations. Read-only.
// NOTE the trailing `; true`. Each command here targets paths that may not
// exist, and `sh -c` exits with the status of the LAST one — so without it
// a perfectly readable nginx config was reported as unreadable purely
// because the final Apache `cat` found nothing. That silently downgraded
// config-confirmed correlation to topology inference.
const CONFIG_DUMP_CMD = [
  'nginx -T 2>/dev/null',
  'cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null',
  'cat /etc/apache2/sites-enabled/*.conf /etc/apache2/conf-enabled/*.conf 2>/dev/null',
  'cat /usr/local/apache2/conf/httpd.conf /usr/local/apache2/conf/extra/*.conf 2>/dev/null',
  'cat /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf 2>/dev/null',
  'true',
].join('; ')

const LOCAL_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '0.0.0.0'])

function splitHostPort(raw) {
  const value = String(raw || '').trim()
  if (!value) return null
  if (/^unix:/i.test(value)) return { host: null, port: null, local: true, raw: value }

  // strip an optional scheme (fcgi://, http://)
  const bare = value.replace(/^[a-z]+:\/\//i, '')

  // bracketed IPv6, e.g. [::1]:9000
  const v6 = /^\[([^\]]+)\](?::(\d+))?$/.exec(bare)
  if (v6) {
    return { host: v6[1], port: v6[2] ? Number(v6[2]) : null, local: LOCAL_HOSTS.has(v6[1]), raw: value }
  }

  const idx = bare.lastIndexOf(':')
  if (idx === -1) return { host: bare, port: null, local: LOCAL_HOSTS.has(bare), raw: value }

  const host = bare.slice(0, idx)
  const port = Number(bare.slice(idx + 1))
  return { host, port: Number.isFinite(port) ? port : null, local: LOCAL_HOSTS.has(host), raw: value }
}

function parseUpstreams(configText) {
  const upstreams = new Map()
  UPSTREAM_BLOCK_RE.lastIndex = 0
  let m
  while ((m = UPSTREAM_BLOCK_RE.exec(configText)) !== null) {
    const [, name, body] = m
    UPSTREAM_SERVER_RE.lastIndex = 0
    let s
    const servers = []
    while ((s = UPSTREAM_SERVER_RE.exec(body)) !== null) servers.push(s[1])
    if (servers.length) upstreams.set(name, servers)
  }
  return upstreams
}

// Returns the distinct FastCGI targets referenced by a web server config.
function parseFastcgiTargets(configText) {
  const text = String(configText || '')
  if (!text) return []

  const upstreams = parseUpstreams(text)
  const raws = []

  FASTCGI_PASS_RE.lastIndex = 0
  let m
  while ((m = FASTCGI_PASS_RE.exec(text)) !== null) raws.push(m[1])

  APACHE_FCGI_RE.lastIndex = 0
  while ((m = APACHE_FCGI_RE.exec(text)) !== null) raws.push(m[1])

  const targets = []
  const seen = new Set()
  for (const raw of raws) {
    // a bare name may be an upstream block rather than a host
    const expanded = upstreams.has(raw) ? upstreams.get(raw) : [raw]
    for (const value of expanded) {
      const parsed = splitHostPort(value)
      if (!parsed) continue
      const key = `${parsed.host}:${parsed.port}:${parsed.local}`
      if (seen.has(key)) continue
      seen.add(key)
      targets.push(parsed)
    }
  }
  return targets
}

// discovery/index.js already reads and parses each web server's config in
// the observe pass, so reuse it rather than exec'ing into the container a
// second time. The direct read remains for callers (and tests) that have no
// pre-read config.
function readFastcgiConfig(dockerClient, container) {
  if (container?.serverConfig && container.serverConfig.text !== undefined) {
    return container.serverConfig.text
  }
  if (!container.id || !container.running) return null
  const command = webservers.configCommandFor(container?.server?.server || null)
  const result = dockerClient.execCapture(container.id, command, { timeout: 6000 })
  if (!result.ok || !String(result.stdout || '').trim()) return null
  return result.stdout
}

// A PHP-FPM backend: speaks FastCGI, not HTTP. Requires positive evidence
// of php-fpm specifically — a plain `php` CLI process or a PHP image alone
// is not enough, since those are usually self-contained web apps.
function isFpmBackend(container, processes) {
  const procText = (processes || []).join('\n')
  const evidence = []

  if (/php-fpm/i.test(procText)) evidence.push('php-fpm process running')
  if (/fpm/i.test(container.image) && /php/i.test(container.image)) evidence.push(`image "${container.image}" is a PHP-FPM image`)

  if (!evidence.length) return { isFpm: false, evidence: [] }

  const listensOnFpmPort = container.ports.some(p => p.containerPort === 9000 || p.containerPort === 9001)
  if (listensOnFpmPort) evidence.push('listening on the FastCGI port')

  return { isFpm: true, evidence }
}

function sharedNetworks(a, b) {
  const aNames = new Set((a.networks || []).map(n => n.name))
  return (b.networks || []).map(n => n.name).filter(n => aNames.has(n))
}

function sharesNetwork(a, b) {
  return sharedNetworks(a, b).length > 0
}

// Does `host` (as written in a config file) name this container? Docker's
// embedded DNS resolves container names, compose service names and network
// aliases, so all three are valid ways to write the upstream.
function matchesHost(container, host) {
  if (!host) return false
  const needle = host.toLowerCase()
  const names = new Set()
  if (container.name) names.add(String(container.name).toLowerCase())
  if (container.composeService) names.add(String(container.composeService).toLowerCase())
  for (const n of container.networks || []) {
    for (const alias of n.aliases || []) names.add(String(alias).toLowerCase())
  }
  return names.has(needle)
}

// The PHP version of a backend container. Prefer the PHP_VERSION env var —
// the official php images set it, and it survives being rebuilt under a
// custom image name (e.g. `fake-web-php`), which the image tag does not.
function backendPhpVersion(backend) {
  // Anchored and digits-only: this value reaches generated configuration.
  const fromEnv = backend?.env?.PHP_VERSION
  if (fromEnv) {
    const m = /^(\d+\.\d+)/.exec(String(fromEnv))
    if (m) return m[1]
  }
  const m = /php:?(\d+\.\d+)/i.exec(String(backend?.image || ''))
  return m ? m[1] : null
}

// Correlates web-server records with PHP-FPM backend records in place.
// `records` are the partially-built container records from
// discovery/index.js pass 1 (normalized + processes + web + server).
function correlate(records, dockerClient) {
  const backends = []
  for (const rec of records) {
    const verdict = isFpmBackend(rec, rec.processes)
    if (verdict.isFpm) {
      rec.fpm = { isBackend: true, evidence: verdict.evidence, servesFor: [] }
      backends.push(rec)
    }
  }

  // Any registered web server that can front FastCGI — not a hardcoded
  // nginx/apache pair, so a server added to the registry is correlated too.
  const webServers = records.filter(r => {
    const profile = r.server?.server ? webservers.byId(r.server.server) : null
    return !!profile && profile.frontsFastcgi !== false
  })

  for (const web of webServers) {
    const configText = readFastcgiConfig(dockerClient, web)
    const targets = configText ? parseFastcgiTargets(configText) : []

    let link = null

    for (const target of targets) {
      if (target.local) {
        link = { basis: 'local', target: target.raw, backend: null }
        continue // a remote target, if any, is a stronger signal — keep looking
      }
      const backend = backends.find(b => matchesHost(b, target.host) && sharesNetwork(web, b))
        || records.find(r => matchesHost(r, target.host) && sharesNetwork(web, r))
      if (backend) {
        link = {
          basis: 'config',
          target: `${target.host}:${target.port || 9000}`,
          backend,
          detail: `${web.server.server} config sends FastCGI to ${target.host}:${target.port || 9000}`,
        }
        break
      }
    }

    // Config unreadable (minimal image, exec denied, ...) — fall back to
    // network topology, but only when it is unambiguous.
    if (!link && !configText) {
      const candidates = backends.filter(b => b !== web && sharesNetwork(web, b))
      if (candidates.length === 1) {
        const backend = candidates[0]
        const port = backend.ports.find(p => p.containerPort === 9000 || p.containerPort === 9001)?.containerPort || 9000
        const shared = sharedNetworks(web, backend)
        link = {
          basis: 'network-inference',
          target: `${backend.composeService || backend.name}:${port}`,
          backend,
          detail: `the only PHP-FPM container on shared network "${shared[0] || 'unknown'}"`,
        }
      }
    }

    if (!link) continue

    web.fastcgi = {
      basis: link.basis,
      target: link.target,
      detail: link.detail || null,
      backendName: link.backend ? (link.backend.composeService || link.backend.name) : null,
      backendContainerName: link.backend ? link.backend.name : null,
      phpVersion: link.backend ? backendPhpVersion(link.backend) : null,
    }

    if (link.backend) {
      link.backend.fpm = link.backend.fpm || { isBackend: true, evidence: [], servesFor: [] }
      link.backend.fpm.servesFor.push(web.composeService || web.name)
    }
  }

  correlateHttpProxies(records)
  return records
}

// A web server can also reverse-proxy plain HTTP to an application
// container — Apache `ProxyPass / http://app:3000/`, nginx
// `proxy_pass http://app:3000`. PHP is not involved, so this is what makes
// "Apache in front of Node/Python" classify as that runtime rather than as
// a static site.
//
// Unlike a PHP-FPM backend (which speaks FastCGI and can never serve HTTP
// directly), an HTTP backend may legitimately be reachable on its own, so
// its routability is deliberately left alone — the relationship is recorded
// for classification and reporting, not used to suppress a route.
function correlateHttpProxies(records) {
  const runtimeSvc = require('./runtime')

  for (const web of records) {
    const proxies = web.serverConfig?.httpProxies || []
    if (!proxies.length) continue

    for (const url of proxies) {
      const parsed = splitHostPort(url)
      if (!parsed || parsed.local || !parsed.host) continue

      const backend = records.find(r => r !== web && matchesHost(r, parsed.host) && sharesNetwork(web, r))
      if (!backend) continue

      const backendRuntime =
        runtimeSvc.detectNode(backend, backend.processes) ||
        runtimeSvc.detectPython(backend, backend.processes)

      web.httpProxy = {
        target: `${parsed.host}:${parsed.port || 80}`,
        backendName: backend.composeService || backend.name,
        backendContainerName: backend.name,
        backendRuntime: backendRuntime || null,
      }
      backend.proxiedBy = [...(backend.proxiedBy || []), web.composeService || web.name]
      break
    }
  }
  return records
}

module.exports = {
  correlate, correlateHttpProxies, isFpmBackend, parseFastcgiTargets, parseUpstreams,
  splitHostPort, matchesHost, sharesNetwork, sharedNetworks, readFastcgiConfig,
  backendPhpVersion, CONFIG_DUMP_CMD,
}
