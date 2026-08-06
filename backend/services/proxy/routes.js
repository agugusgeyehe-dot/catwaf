// proxy/routes.js — turn discovered web-app containers into concrete
// reverse-proxy route plans (where to listen, where to send traffic).
//
// Container IPs churn on every restart, so upstreams always prefer the
// container/compose-service name (resolved by Docker's embedded DNS on
// whatever network the containers share) over `NetworkSettings...IPAddress`.
// A published host port is used only as a fallback when no shared network
// can be assumed, and is always called out as a fallback in `warnings`.

const net = require('net')

const DEFAULT_BASE_PORT = 8080
const DEFAULT_PORT_RANGE = 200 // scan 8080..8279 before giving up

function portFree(port) {
  return new Promise(resolve => {
    const srv = net.createServer()
    srv.once('error', () => resolve(false))
    srv.once('listening', () => srv.close(() => resolve(true)))
    srv.listen(port, '127.0.0.1')
  })
}

async function allocatePort({ preferred, taken, basePort = DEFAULT_BASE_PORT, range = DEFAULT_PORT_RANGE }) {
  const candidates = []
  if (preferred) candidates.push(preferred)
  for (let p = basePort; p < basePort + range; p++) candidates.push(p)

  for (const port of candidates) {
    if (taken.has(port)) continue
    if (await portFree(port)) return port
  }
  return null
}

function upstreamFor(container) {
  // Prefer the container's own name / compose service name — stable across
  // restarts, unlike its IP. This only resolves if Caddy shares a Docker
  // network with the container, so it requires a routable network to exist.
  const name = container.composeService || container.name
  const port = container.web.port
  const networks = container.web.networkAliases || []

  if (name && port && networks.length) {
    return {
      target: `${name}:${port}`,
      basis: 'docker-network-alias',
      warning: `Reaches "${container.name}" by name (${name}:${port}) on Docker network ${networks.join(', ')} — CatWAF's Caddy must be attached to that network. If routing fails, join Caddy to it (\`docker network connect ${networks[0]} <caddy-container>\`), or run \`catwaf docker\` so both are on the same compose network.`,
    }
  }

  // No routable network (host/none networking, or no network at all) — the
  // published host port is the only way in.
  if (container.web.published && container.web.hostPort) {
    return {
      target: `127.0.0.1:${container.web.hostPort}`,
      basis: 'published-host-port',
      warning: `Routing via the host-published port 127.0.0.1:${container.web.hostPort} instead of a Docker network — this container still bypasses CatWAF directly on that port. For full protection, stop publishing it from the container and let CatWAF be the only path in.`,
    }
  }

  return null
}

// Listen ports are sticky across runs: an app protected on :8080 must stay
// on :8080 when `catwaf start` runs again, or every restart would silently
// move the endpoint users and firewalls point at.
const PORT_ASSIGNMENT_KEY = 'auto_route_ports'

function loadAssignments(db) {
  try { return db.getState(PORT_ASSIGNMENT_KEY) || {} } catch { return {} }
}

function saveAssignments(db, assignments) {
  try { db.setState(PORT_ASSIGNMENT_KEY, assignments) } catch { /* best effort — a lost assignment only costs a port change */ }
}

// `webApps` is discovery.discover()'s `webApps` array. Returns
// { routes, skipped } — never throws; a container that can't be routed is
// reported in `skipped` with a reason, not silently dropped.
//
// `resolveUpstream` (from proxy/network.js) is injected so route planning
// can reflect what CatWAF's proxy can ACTUALLY reach, including attaching
// it to the app's Docker network. Without it, planning falls back to
// metadata-only inference via upstreamFor().
async function planRoutes(webApps, { basePort = DEFAULT_BASE_PORT, resolveUpstream = null, db = null, persist = true } = {}) {
  const routes = []
  const skipped = []
  const taken = new Set()

  const assignments = db ? loadAssignments(db) : {}
  const nextAssignments = {}
  // ports claimed by an app during THIS run (as opposed to merely reserved)
  const claimed = new Set()

  const keyFor = container => `${container.composeProject || ''}/${container.composeService || container.name}`

  // Reserve every already-assigned port BEFORE allocating any new one.
  // Without this, whichever app discovery happens to return first can take
  // a port that already belongs to another app, silently moving that app's
  // endpoint — a newly discovered Apache container would push an existing
  // nginx app off :8080 purely because Docker listed it first.
  for (const container of webApps) {
    const remembered = Number(assignments[keyFor(container)]) || null
    if (remembered) taken.add(remembered)
  }

  for (const container of webApps) {
    const upstream = resolveUpstream ? await resolveUpstream(container) : upstreamFor(container)

    if (!upstream || upstream.unreachable) {
      // Report exactly what was tried and why it failed — "unreachable" on
      // its own is not actionable.
      const detail = upstream?.diagnostics?.length
        ? upstream.diagnostics.join('; ')
        : 'no published host port and no routable Docker network address'
      skipped.push({
        name: container.name,
        reason: `CatWAF could not reach this container: ${detail}.`,
        diagnostics: upstream?.diagnostics || [],
      })
      continue
    }

    const key = keyFor(container)
    const remembered = Number(assignments[key]) || null

    // A port this app was already assigned is reused unconditionally — it is
    // almost certainly busy *because CatWAF is already listening on it* from
    // a previous run. Treating that as a conflict would move the endpoint on
    // every restart, breaking the URL, firewall rules and DNS pointing at it.
    // (It is in `taken` from the reservation pass above, which is why the
    // check is against *other* apps' claims, not this app's own.)
    // Freeness is only probed when choosing a NEW port.
    let listenPort = null
    if (remembered && !claimed.has(remembered)) {
      listenPort = remembered
    } else {
      listenPort = await allocatePort({
        preferred: container.web.published ? container.web.hostPort : null,
        taken,
        basePort,
      })
    }

    if (!listenPort) {
      skipped.push({ name: container.name, reason: 'No free host port available to listen on.' })
      continue
    }
    taken.add(listenPort)
    claimed.add(listenPort)

    const warnings = []
    if (upstream.warning) warnings.push(upstream.warning)

    if (upstream.attached === 'attached') {
      warnings.push(`CatWAF's proxy was attached to Docker network "${upstream.network}" so it can reach this container.`)
    } else if (upstream.attached === 'would-attach') {
      warnings.push(`CatWAF's proxy would be attached to Docker network "${upstream.network}" to reach this container.`)
    }
    if (upstream.volatile) {
      warnings.push(`Routing to the container IP ${upstream.target} because CatWAF's proxy runs outside Docker. Container IPs change when containers are recreated — re-run \`catwaf start\` after recreating this app, or run CatWAF's proxy in Docker to route by name instead.`)
    }

    const bypassPort = upstream.bypassPath ?? (container.web.published ? container.web.hostPort : null)
    if (bypassPort && listenPort !== bypassPort) {
      warnings.push(`Container still publishes port ${bypassPort} directly to the host — traffic there bypasses the WAF. Protected traffic is served on ${listenPort} instead.`)
    } else if (bypassPort && listenPort === bypassPort) {
      warnings.push(`This reuses the app's own published port (${listenPort}), so traffic can still bypass the WAF by reaching the container directly. Stop publishing that port from the container itself.`)
    }

    nextAssignments[key] = listenPort

    routes.push({
      name: container.composeService || container.name,
      containerName: container.name,
      containerId: container.id,
      listenPort,
      upstream: upstream.target,
      upstreamBasis: upstream.basis,
      network: upstream.network || null,
      attached: upstream.attached || null,
      volatileUpstream: !!upstream.volatile,
      bypassPort: bypassPort || null,
      framework: container.php?.framework || null,
      runtime: container.runtime?.label || null,
      phpConfidence: container.php?.isPhp ? container.php.confidence : null,
      reachability: container.web.reachability,
      warnings,
    })
  }

  // --dry-run must not change stored state either.
  if (db && persist) saveAssignments(db, nextAssignments)

  return { routes, skipped }
}

module.exports = {
  planRoutes, allocatePort, portFree, upstreamFor,
  DEFAULT_BASE_PORT, PORT_ASSIGNMENT_KEY,
}
