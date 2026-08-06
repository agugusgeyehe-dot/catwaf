// discovery/webservers.js — the web-server registry.
//
// Everything CatWAF needs to know about a *kind* of web server lives in one
// profile here: how to recognize it, where its configuration lives, and how
// to read useful facts out of that configuration. Adding a server is adding
// a profile — no detector, correlation or routing code changes.
//
//     web server
//     ├── nginx
//     ├── apache
//     ├── caddy
//     └── future servers
//
// ── Recognition ───────────────────────────────────────────────────────
// Never a single string. Each profile carries image patterns AND process
// patterns, and detection combines them into a confidence score:
//
//     running process matches      +55
//     container image matches      +45
//     listening on 80/443          +10   (corroborating only)
//                                  ---
//     capped at                    100
//
// A process match outweighs an image match because it is evidence of what
// is actually running, not what the image was built from. Neither alone is
// treated as certainty.
//
// Image matching has to cope with two naming conventions:
//   prefix/whole  httpd:2.4, apache, bitnami/apache:2.4
//   suffix        php:8.3-apache, wordpress:6-php8.2-apache, drupal:10-apache
// The suffix family is the most common way Apache actually ships, and is
// exactly what a naive /(^|\/)apache(:|$)/ misses. Conversely `apache/kafka`
// and `apache/airflow` are the Apache *Foundation*, not httpd, and must NOT
// match — hence the deliberate exclusion of a following "/".

// ── Config extraction helpers ─────────────────────────────────────────

// A port out of any of: "80", "*:80", "0.0.0.0:8080", "[::]:80", "443 https"
function portFromListenToken(token) {
  const t = String(token || '').trim().split(/\s+/)[0]
  if (!t) return null
  const v6 = /^\[[^\]]*\]:(\d+)$/.exec(t)
  if (v6) return Number(v6[1])
  const hostPort = /:(\d+)$/.exec(t)
  if (hostPort) return Number(hostPort[1])
  if (/^\d+$/.test(t)) return Number(t)
  return null
}

function collect(re, text, fn) {
  re.lastIndex = 0
  const out = []
  let m
  while ((m = re.exec(text)) !== null) {
    const v = fn(m)
    if (Array.isArray(v)) out.push(...v)
    else if (v != null) out.push(v)
  }
  return out
}

// Directives are matched after a line start, an opening brace, a semicolon
// or whitespace — nginx routinely writes a whole block on one line
// (`location /api { proxy_pass http://app:3000; }`), so anchoring to the
// start of a line silently misses them.
const RE = {
  // Apache
  apacheListen: /(?:^|[{;\s])Listen[ \t]+(\S+(?:[ \t]+\S+)?)/gim,
  apacheVhost: /<VirtualHost\s+([^>]+)>/gi,
  apacheDocRoot: /(?:^|[{;\s])DocumentRoot\s+"?([^"\s]+)"?/gim,
  apacheProxyPass: /(?:^|[{;\s])ProxyPass(?:Match)?\s+(?:\S+\s+)?(https?:\/\/[^\s"']+)/gim,
  // nginx
  nginxListen: /(?:^|[{;\s])listen[ \t]+([^;]+);/gim,
  nginxRoot: /(?:^|[{;\s])root[ \t]+([^;]+);/gim,
  nginxProxyPass: /(?:^|[{;\s])proxy_pass\s+(https?:\/\/[^\s;]+)\s*;/gim,
}

// Stock configs are full of commented-out examples — Fedora's httpd.conf
// ships `#Listen 12.34.56.78:80` and `#ServerName www.example.com:80`.
// Reading those as live directives would invent ports that nothing serves.
function stripComments(text) {
  return text.replace(/(^|\s)#[^\n]*/g, '$1')
}

// Unified parser. Directive names do not collide between servers, so one
// parser handles every profile — and a container with an unusual or mixed
// layout still yields whatever is present instead of nothing.
function parseServerConfig(configText) {
  const raw = String(configText || '')
  if (!raw.trim()) {
    return { listens: [], documentRoots: [], httpProxies: [], vhosts: [], empty: true }
  }
  const text = stripComments(raw)

  const listens = [
    ...collect(RE.apacheListen, text, m => portFromListenToken(m[1])),
    ...collect(RE.nginxListen, text, m => portFromListenToken(m[1])),
    ...collect(RE.apacheVhost, text, m => m[1].split(/\s+/).map(portFromListenToken)),
  ].filter(p => Number.isFinite(p) && p > 0 && p < 65536)

  const documentRoots = [
    ...collect(RE.apacheDocRoot, text, m => m[1]),
    ...collect(RE.nginxRoot, text, m => m[1].trim().split(/\s+/)[0]),
  ].filter(p => p && p.startsWith('/'))

  // Only http(s) upstreams here — FastCGI (fcgi:// and fastcgi_pass) is
  // handled by discovery/fastcgi.js, which knows how to resolve backends.
  const httpProxies = [
    ...collect(RE.apacheProxyPass, text, m => m[1]),
    ...collect(RE.nginxProxyPass, text, m => m[1]),
  ]

  return {
    listens: [...new Set(listens)],
    documentRoots: [...new Set(documentRoots)],
    httpProxies: [...new Set(httpProxies)],
    vhosts: collect(RE.apacheVhost, text, m => m[1]),
    empty: false,
  }
}

// ── Profiles ──────────────────────────────────────────────────────────

const PROFILES = [
  {
    id: 'nginx',
    label: 'nginx',
    frontsFastcgi: true,
    imagePatterns: [
      /(^|\/)(nginx|openresty)([:@.-]|$)/i,
      /[:-](nginx|openresty)([:@.-]|$)/i,
    ],
    // `nginx: master process ...` — the colon is part of the real ps output.
    processPatterns: [/(?:^|\/|\s)nginx(?::|\s|$)/mi],
    // `nginx -T` resolves includes, which is far better than guessing paths.
    configCommands: [
      'nginx -T 2>/dev/null',
      'cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null',
    ],
  },
  {
    id: 'apache',
    label: 'Apache',
    frontsFastcgi: true,
    imagePatterns: [
      // httpd:2.4, apache, apache2, bitnami/apache:2.4
      // (a following "/" is excluded so apache/kafka, apache/airflow,
      //  apache/spark — the Foundation's images — do not match)
      /(^|\/)(httpd|apache2?)([:@.-]|$)/i,
      // php:8.3-apache, wordpress:6-php8.2-apache, drupal:10-apache
      /[:-](httpd|apache2?)([:@.-]|$)/i,
    ],
    // Debian ships apache2, RHEL/Fedora and the official image ship httpd,
    // and some layouts run through apachectl/apache2ctl. Matching whole
    // path components keeps /opt/apache-tomcat/... from being mistaken for
    // httpd.
    processPatterns: [/(?:^|\/|\s)(httpd(?:\.\w+)?|apache2|apachectl|apache2ctl)(?:\s|$)/mi],
    configCommands: [
      // -S dumps the parsed vhost/Listen picture; it writes to stderr on
      // some builds, hence 2>&1.
      'apachectl -S 2>&1',
      'apache2ctl -S 2>&1',
      'httpd -S 2>&1',
      // Debian/Ubuntu
      'cat /etc/apache2/apache2.conf /etc/apache2/ports.conf /etc/apache2/sites-enabled/*.conf /etc/apache2/conf-enabled/*.conf 2>/dev/null',
      // official httpd image
      'cat /usr/local/apache2/conf/httpd.conf /usr/local/apache2/conf/extra/*.conf 2>/dev/null',
      // RHEL/Fedora/CentOS
      'cat /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf 2>/dev/null',
      // Alpine
      'cat /etc/apache2/httpd.conf 2>/dev/null',
    ],
  },
  {
    id: 'caddy',
    label: 'Caddy',
    frontsFastcgi: true,
    imagePatterns: [/(^|\/)caddy([:@.-]|$)/i, /[:-]caddy([:@.-]|$)/i],
    processPatterns: [/(?:^|\/|\s)caddy(?:\s|$)/mi],
    configCommands: ['cat /etc/caddy/Caddyfile 2>/dev/null'],
  },
]

const STANDARD_HTTP_PORTS = new Set([80, 443])

// Detect which web server (if any) a container is running.
// Returns null when nothing matches, so callers can treat "no web server"
// as a distinct case rather than a zero-confidence one.
function detect(container, processes) {
  const procText = (processes || []).join('\n')
  const image = String(container?.image || '')
  const ports = Array.isArray(container?.ports) ? container.ports : []

  let best = null
  for (const profile of PROFILES) {
    const imageHit = profile.imagePatterns.some(re => re.test(image))
    const processHit = profile.processPatterns.some(re => re.test(procText))
    if (!imageHit && !processHit) continue

    let confidence = 0
    const evidence = []
    if (processHit) {
      confidence += 55
      evidence.push(`${profile.label} process running`)
    }
    if (imageHit) {
      confidence += 45
      evidence.push(`image "${image}" matches ${profile.label}`)
    }
    if (ports.some(p => STANDARD_HTTP_PORTS.has(p.containerPort))) {
      confidence += 10
      evidence.push('listening on a standard HTTP port')
    }
    confidence = Math.min(100, confidence)

    if (!best || confidence > best.confidence) {
      best = { id: profile.id, label: profile.label, confidence, evidence, profile }
    }
  }
  return best
}

function byId(id) {
  return PROFILES.find(p => p.id === id) || null
}

// Shell command that dumps this server's configuration. Falls back to the
// union of every profile when the server is unknown, so an unrecognized
// container can still yield useful config.
//
// The trailing `true` matters: each command targets paths that may not
// exist, and `sh -c` exits with the status of the LAST one. Without it a
// perfectly readable config was reported as unreadable purely because the
// final `cat` found nothing.
function configCommandFor(serverId) {
  const profile = byId(serverId)
  const commands = profile
    ? profile.configCommands
    : PROFILES.flatMap(p => p.configCommands)
  return [...commands, 'true'].join('; ')
}

// Read and parse a container's web-server configuration. Entirely
// best-effort: a minimal image with no shell, a read-only rootfs, exec
// denied, or a stopped container all yield an empty result rather than an
// error, and never abort discovery.
function readConfig(dockerClient, container, serverId) {
  if (!container?.id || !container.running) return { text: null, ...parseServerConfig('') }
  let result
  try {
    result = dockerClient.execCapture(container.id, configCommandFor(serverId), { timeout: 6000 })
  } catch {
    return { text: null, ...parseServerConfig('') }
  }
  const text = result && result.ok && String(result.stdout || '').trim() ? result.stdout : null
  return { text, ...parseServerConfig(text) }
}

module.exports = {
  PROFILES, detect, byId, configCommandFor, readConfig,
  parseServerConfig, portFromListenToken, stripComments,
}
