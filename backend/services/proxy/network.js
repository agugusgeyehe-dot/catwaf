// proxy/network.js — make CatWAF's proxy able to actually reach a
// discovered application.
//
// This is the step that turns "a route was generated" into "traffic can
// traverse the WAF". A Caddyfile that says `reverse_proxy nginx:80` is
// worthless if Caddy cannot resolve `nginx` — the site is not protected,
// it is broken. So CatWAF works out where its own proxy runs, what it can
// genuinely reach, and then PROVES reachability with a TCP connection
// before writing an upstream.
//
// ── Routing priority ─────────────────────────────────────────────────
//
// Containerized proxy (CatWAF's Caddy is itself a container):
//   1. `service:port` over a shared Docker network, attaching the proxy to
//      that network if needed. Docker's embedded DNS resolves the name, and
//      the app needs no host port at all — no bypass path around the WAF.
//
// Host-native proxy (CatWAF running directly on the host, e.g. on Fedora):
//   1. Published host port, if the app publishes one.
//   2. Container IP + internal port. On a normal Docker bridge network the
//      container subnet is routable from the host, so a host process can
//      reach 172.x.y.z:80 directly. A Docker DNS name like `nginx` must
//      NOT be used here — the host does not resolve Docker's embedded DNS.
//   3. Otherwise: unreachable, reported with the specific reason.
//
// Container IPs change when containers are recreated, so this path is
// marked `volatile` and re-resolved on every `catwaf start`.

const fs = require('fs')
const net = require('net')

// How CatWAF's own Caddy is deployed. Explicit env wins; otherwise we look
// for the containerized Caddy this repo's docker-compose.yml creates.
function detectProxyContainer(dockerClient) {
  const explicit = process.env.CATWAF_CADDY_CONTAINER
  if (explicit) return { name: explicit, source: 'CATWAF_CADDY_CONTAINER' }

  const list = dockerClient.listContainers()
  if (!list.ok) return null

  const candidates = list.containers.filter(c => {
    const name = String(c.Names || '')
    const image = String(c.Image || '')
    // `docker ps --format '{{json .}}'` reports State as "running" and
    // Status as "Up 3 minutes" — accept either spelling.
    const running = /^(up|running)/i.test(String(c.State || '')) || /^up/i.test(String(c.Status || ''))
    return running && (/catwaf.*caddy|caddy.*catwaf/i.test(name) || /catwaf.*caddy/i.test(image))
  })
  if (candidates.length === 1) return { name: candidates[0].Names, source: 'auto-detected' }
  if (candidates.length > 1) {
    const exact = candidates.find(c => String(c.Names || '') === 'catwaf-caddy')
    if (exact) return { name: exact.Names, source: 'auto-detected' }
  }
  return null
}

function networksOf(dockerClient, containerName) {
  const inspect = dockerClient.inspectContainer(containerName)
  const nets = inspect?.NetworkSettings?.Networks || {}
  return Object.keys(nets)
}

// Attach CatWAF's proxy to a Docker network. Idempotent: attaching an
// already-attached container is a no-op, not an error.
function attachToNetwork(dockerClient, proxyContainer, network) {
  const current = networksOf(dockerClient, proxyContainer)
  if (current.includes(network)) return { ok: true, alreadyAttached: true, network }

  const result = dockerClient.networkConnect(network, proxyContainer)
  if (!result.ok) {
    // A concurrent `catwaf start` may have won the race — re-check rather
    // than reporting a failure that is not one.
    if (networksOf(dockerClient, proxyContainer).includes(network)) {
      return { ok: true, alreadyAttached: true, network }
    }
    return { ok: false, network, error: result.error }
  }
  return { ok: true, attached: true, network }
}

// ── Container address resolution ──────────────────────────────────────
// Never trust a single field. Different Docker versions, network drivers
// and daemon configurations populate different places, and an empty
// IPAddress on one of them must not be read as "this container has no
// address" — that is what made a perfectly reachable nginx look unroutable.
function candidateAddresses(container, network, dockerClient) {
  const out = []
  const push = ip => {
    const clean = String(ip || '').trim().replace(/\/\d+$/, '')
    if (clean && !out.includes(clean)) out.push(clean)
  }

  // 1. the normalized per-network address (containers.js)
  const fromNormalized = (container.networks || []).find(n => n.name === network)
  push(fromNormalized?.ipAddress)

  // 2. straight from docker inspect, including IPv6 and the legacy
  //    top-level field used by the default bridge
  const inspect = container.id && dockerClient?.inspectContainer
    ? dockerClient.inspectContainer(container.id)
    : null
  const netObj = inspect?.NetworkSettings?.Networks?.[network]
  push(netObj?.IPAddress)
  push(netObj?.GlobalIPv6Address)
  push(inspect?.NetworkSettings?.IPAddress)

  // 3. the network's own view of its members — populated even when the
  //    container-side endpoint data is sparse
  if (dockerClient?.inspectNetwork) {
    const netInspect = dockerClient.inspectNetwork(network)
    const members = netInspect?.Containers || {}
    const entry = members[container.id]
      || Object.values(members).find(m => m && m.Name === container.name)
    push(entry?.IPv4Address)
    push(entry?.IPv6Address)
  }

  return out
}

// Is this a network whose addresses a host process can route to at all?
function describeNetwork(dockerClient, network) {
  const info = dockerClient?.inspectNetwork ? dockerClient.inspectNetwork(network) : null
  if (!info) return { driver: null, internal: false, known: false }
  return {
    driver: info.Driver || null,
    internal: !!info.Internal,
    known: true,
  }
}

// Prove the address is actually reachable and the port is actually
// listening, rather than assuming it from metadata.
function tcpReachable(host, port, timeoutMs = 1200) {
  return new Promise(resolve => {
    const socket = new net.Socket()
    let settled = false
    const done = result => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(result)
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => done({ ok: true }))
    socket.once('timeout', () => done({ ok: false, error: 'timeout' }))
    socket.once('error', e => done({ ok: false, error: e.code || e.message }))
    socket.connect(port, host)
  })
}

function containerIpOn(container, network) {
  const net_ = (container.networks || []).find(n => n.name === network)
  return net_?.ipAddress || null
}

// Decide the real upstream for one discovered container. Returns null when
// there is genuinely no reachable path — callers must not invent one.
// `unreachable` carries the specific diagnosis for the user-facing message.
async function resolveUpstream(container, { dockerClient, proxy, dryRun = false, verifyReachable = true } = {}) {
  const port = container.web?.port
  const serviceName = container.composeService || container.name
  const appNetworks = container.web?.networkAliases || []

  // ── Containerized proxy: prefer the Docker network path ──────────────
  if (proxy?.container && appNetworks.length) {
    const shared = appNetworks.find(n => proxy.networks.includes(n))
    if (shared) {
      return {
        target: `${serviceName}:${port}`,
        basis: 'docker-network-alias',
        network: shared,
        attached: 'already',
        bypassPath: container.web.published ? container.web.hostPort : null,
      }
    }

    const joinable = appNetworks[0]
    if (dryRun) {
      return {
        target: `${serviceName}:${port}`,
        basis: 'docker-network-alias',
        network: joinable,
        attached: 'would-attach',
        bypassPath: container.web.published ? container.web.hostPort : null,
      }
    }

    const attach = attachToNetwork(dockerClient, proxy.container, joinable)
    if (attach.ok) {
      proxy.networks.push(joinable)
      return {
        target: `${serviceName}:${port}`,
        basis: 'docker-network-alias',
        network: joinable,
        attached: attach.alreadyAttached ? 'already' : 'attached',
        bypassPath: container.web.published ? container.web.hostPort : null,
      }
    }
    // fall through — attachment failed, try a host-visible path instead
  }

  // ── Host-native proxy ────────────────────────────────────────────────
  // 1. A published host port is the simplest reachable path.
  if (container.web?.published && container.web.hostPort) {
    return {
      target: `127.0.0.1:${container.web.hostPort}`,
      basis: 'published-host-port',
      network: null,
      bypassPath: container.web.hostPort,
    }
  }

  // 2. Container IP on a routable bridge network. A host process cannot
  //    resolve Docker's embedded DNS, so the IP — never the service name —
  //    is what has to go into the Caddyfile here.
  const diagnostics = []
  for (const network of appNetworks) {
    const netInfo = describeNetwork(dockerClient, network)
    if (netInfo.known && netInfo.internal) {
      diagnostics.push(`network "${network}" is marked internal, so the host cannot route to it`)
      continue
    }
    if (netInfo.known && netInfo.driver && !['bridge', 'macvlan', 'ipvlan'].includes(netInfo.driver)) {
      diagnostics.push(`network "${network}" uses the "${netInfo.driver}" driver, which is not routable from this host`)
      continue
    }

    const addresses = candidateAddresses(container, network, dockerClient)
    if (!addresses.length) {
      diagnostics.push(`no IP address could be read for "${container.name}" on network "${network}"`)
      continue
    }

    for (const ip of addresses) {
      if (!verifyReachable) {
        return { target: `${ip}:${port}`, basis: 'container-ip', network, volatile: true, bypassPath: null }
      }
      const probe = await tcpReachable(ip, port)
      if (probe.ok) {
        return {
          target: `${ip}:${port}`,
          basis: 'container-ip',
          network,
          volatile: true,
          bypassPath: null,
          verified: true,
        }
      }
      diagnostics.push(`${ip}:${port} is not reachable from this host (${probe.error})`)
    }
  }

  return {
    unreachable: true,
    diagnostics,
    serviceName,
    port,
    networks: appNetworks,
  }
}

// Build the proxy-side context once per run.
function describeProxy(dockerClient) {
  const inContainer = fs.existsSync('/.dockerenv')
  const found = detectProxyContainer(dockerClient)
  if (!found) return { container: null, networks: [], inContainer, source: null }
  return {
    container: found.name,
    networks: networksOf(dockerClient, found.name),
    inContainer,
    source: found.source,
  }
}

module.exports = {
  describeProxy, resolveUpstream, attachToNetwork, detectProxyContainer,
  networksOf, candidateAddresses, describeNetwork, tcpReachable, containerIpOn,
}
