// discovery/web.js — decide whether (and where) a container speaks HTTP.
//
// Port numbers alone are not evidence: plenty of non-web services publish
// ports in the 8000s, and plenty of real web apps run on unusual ports. The
// strongest signal is what the container is actually *running* — an nginx
// master process listening on :80 is an HTTP service whether or not anyone
// published that port to the host.
//
// ── Three distinct notions of reachability ───────────────────────────
//   exposed         the image/container declares the port (EXPOSE, or
//                   compose `expose:`). Says what the app listens on;
//                   says nothing about who can reach it.
//   published       Docker maps it to a host port (`ports: 8080:80`).
//                   Reachable from the host — and, notably, reachable
//                   while bypassing CatWAF entirely.
//   docker-internal listening on a Docker network with no host mapping.
//                   NOT reachable from the host, but perfectly reachable
//                   by Caddy once it joins that network — resolved by
//                   container/service name via Docker's embedded DNS.
//
// A container does NOT need a published host port to be a web application.
// The docker-internal case is in fact the better deployment: the app is
// reachable only through CatWAF, with no bypass path.
//
// ── Scoring ───────────────────────────────────────────────────────────
//   web server process/image (nginx, apache, caddy)               +25
//   app runtime process/image (Node.js, Python)                   +15
//   only exposed port on a container running a web/app server     +10
//   common HTTP port                                              +15
//   published to the host                                         +20
//   successful HTTP probe (host-published ports only)             +30
//   Traefik/Caddy routing labels                                  +15
//
//   isWeb at >= 30.
//
// The threshold sits above what a bare published port scores on its own
// (+20), so publishing e.g. Postgres on 5432 is not mistaken for a web
// service, while nginx on an internal :80 (+25 +15 = 40) is correctly
// identified without ever being published.

const http = require('http')

// A bonus, never a verdict on its own.
const COMMON_HTTP_PORTS = new Set([80, 443, 8080, 8081, 8000, 8001, 8888, 3000, 3001, 4000, 5000, 5173, 9000, 9090])

const WEB_THRESHOLD = 30

// Networks a sibling container could actually reach this one on. Docker's
// embedded DNS resolves names on user-defined networks; `host` and `none`
// provide no such alias, and the default `bridge` has no automatic DNS.
const UNROUTABLE_NETWORKS = new Set(['host', 'none'])

function usableNetworks(container) {
  return (container.networks || []).filter(n => n.name && !UNROUTABLE_NETWORKS.has(n.name))
}

function candidatePorts(container) {
  const seen = new Map()
  for (const p of container.ports) {
    if (p.protocol !== 'tcp') continue
    const existing = seen.get(p.containerPort)
    if (!existing || (p.published && !existing.published)) seen.set(p.containerPort, p)
  }
  return [...seen.values()].sort((a, b) => (b.published - a.published) || (a.containerPort - b.containerPort))
}

function probeHttp(hostIp, port, { timeoutMs = 1500 } = {}) {
  return new Promise(resolve => {
    const req = http.get({
      host: hostIp && hostIp !== '0.0.0.0' ? hostIp : '127.0.0.1',
      port,
      path: '/',
      timeout: timeoutMs,
      headers: { 'User-Agent': 'CatWAF-Auto-Discovery/1.0' },
    }, res => {
      let body = ''
      res.on('data', chunk => { if (body.length < 4096) body += chunk })
      res.on('end', () => {
        resolve({ ok: true, status: res.statusCode, headers: res.headers, bodySample: body.slice(0, 4096) })
      })
      res.resume()
    })
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }) })
    req.on('error', e => resolve({ ok: false, error: e.code || e.message }))
  })
}

function labelScore(labels = {}) {
  let score = 0
  const evidence = []
  if (labels['traefik.enable'] === 'true' || Object.keys(labels).some(k => k.startsWith('traefik.http'))) {
    score += 15; evidence.push('Traefik routing labels present')
  }
  if (Object.keys(labels).some(k => k.startsWith('caddy'))) {
    score += 15; evidence.push('Caddy labels present')
  }
  return { score, evidence }
}

function emptyResult(confidence, evidence) {
  return {
    isWeb: false, port: null, hostPort: null, published: false, exposed: false,
    reachability: 'none', networkAliases: [], confidence, evidence, httpCheck: null,
  }
}

// `serverInfo` is discovery/runtime.js detectServer() output, `appHint` is
// detectNode()/detectPython() output. Both are optional — without them this
// falls back to port heuristics alone, which is why index.js resolves them
// before calling here.
// `configPorts` are ports the web server's own configuration says it
// listens on (Apache `Listen`, nginx `listen`, `<VirtualHost *:8080>`).
// That is authoritative — far better than guessing from the port number —
// and is what lets an app on an unconventional port be identified.
async function detectWebPort(container, { skipHttpProbe = false, serverInfo = null, appHint = null, configPorts = [] } = {}) {
  const candidates = candidatePorts(container)
  const { score: labelBonus, evidence: labelEvidence } = labelScore(container.labels)
  const networks = usableNetworks(container)

  const declaredPorts = new Set((configPorts || []).filter(Number.isFinite))

  const runtimeEvidence = []
  let runtimeBonus = 0
  if (serverInfo?.server) {
    runtimeBonus += 25
    runtimeEvidence.push(`${serverInfo.server} is running in this container`)
  } else if (appHint?.label) {
    runtimeBonus += 15
    runtimeEvidence.push(`${appHint.label} runtime detected`)
  }

  if (!candidates.length) {
    return emptyResult(labelBonus, [...labelEvidence, 'no TCP ports exposed or published'])
  }

  const scored = candidates.map(c => {
    let score = labelBonus + runtimeBonus
    const evidence = [...labelEvidence, ...runtimeEvidence]

    if (c.published) {
      score += 20
      evidence.push(`port ${c.containerPort} published to host port ${c.hostPort}`)
    } else if (networks.length) {
      evidence.push(`port ${c.containerPort} reachable on Docker network ${networks.map(n => n.name).join(', ')}`)
    } else {
      evidence.push(`port ${c.containerPort} exposed but on no routable Docker network`)
    }

    if (declaredPorts.has(c.containerPort)) {
      score += 25
      evidence.push(`the web server's configuration listens on ${c.containerPort}`)
    }

    if (COMMON_HTTP_PORTS.has(c.containerPort)) {
      score += 15
      evidence.push(`${c.containerPort} is a common HTTP port`)
    }

    // A web/app server with exactly one exposed port — that port is what
    // it serves on, even if the number is unusual.
    if (runtimeBonus > 0 && candidates.length === 1) {
      score += 10
      evidence.push(`sole exposed port of a ${serverInfo?.server || appHint?.label} container`)
    }

    return { ...c, score, evidence }
  })

  scored.sort((a, b) => b.score - a.score)
  const best = scored[0]

  // Only host-published ports can be probed from here; a docker-internal
  // port is by definition not reachable from the host, and its absence of
  // a probe is not evidence against it.
  let httpCheck = null
  if (!skipHttpProbe && best.published && container.running) {
    httpCheck = await probeHttp(best.hostIp, best.hostPort)
    if (httpCheck.ok) {
      best.score += 30
      best.evidence.push(`HTTP ${httpCheck.status} on port ${best.hostPort}`)
    } else {
      best.evidence.push(`HTTP probe failed: ${httpCheck.error}`)
    }
  }

  const confidence = Math.max(0, Math.min(100, best.score))
  const reachability = best.published
    ? 'host-published'
    : (networks.length ? 'docker-internal' : 'none')

  return {
    isWeb: confidence >= WEB_THRESHOLD && reachability !== 'none',
    port: best.containerPort,
    hostPort: best.hostPort,
    published: best.published,
    exposed: true,
    reachability,
    networkAliases: networks.map(n => n.name),
    confidence,
    evidence: best.evidence,
    httpCheck,
  }
}

module.exports = {
  candidatePorts, probeHttp, detectWebPort, usableNetworks,
  COMMON_HTTP_PORTS, WEB_THRESHOLD, UNROUTABLE_NETWORKS,
}
