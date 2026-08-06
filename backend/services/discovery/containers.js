// discovery/containers.js — turn raw `docker ps` + `docker inspect` output
// into a stable shape the rest of the discovery pipeline can rely on.
//
// Docker metadata is frequently partial in the wild (a container that
// exited between `ps` and `inspect`, an image with no exposed ports, a
// container with no compose labels). Every field below has a safe default
// so downstream code never has to null-check its way through this.

// Known non-web infrastructure images. This is a display hint only ("no
// HTTP service detected") — it never excludes a container from scanning,
// since plenty of these ship an HTTP admin UI on other images.
const INFRA_IMAGE_RE = /(^|\/)(redis|postgres|postgresql|mysql|mariadb|mongo|mongodb|memcached|rabbitmq|elasticsearch|kafka|zookeeper|etcd|cassandra|influxdb|consul)(:|$)/i

function parseEnvList(list) {
  const env = {}
  for (const entry of (Array.isArray(list) ? list : [])) {
    const i = String(entry).indexOf('=')
    if (i === -1) continue
    env[entry.slice(0, i)] = entry.slice(i + 1)
  }
  return env
}

function normalizePorts(inspect) {
  const ports = []
  const seen = new Set()

  const portMap = inspect?.NetworkSettings?.Ports || {}
  for (const [key, bindings] of Object.entries(portMap)) {
    const [containerPortStr, protocol = 'tcp'] = key.split('/')
    const containerPort = Number(containerPortStr)
    if (!Number.isFinite(containerPort)) continue
    if (Array.isArray(bindings) && bindings.length) {
      for (const b of bindings) {
        const hostPort = Number(b.HostPort)
        ports.push({ containerPort, protocol, published: Number.isFinite(hostPort), hostPort: Number.isFinite(hostPort) ? hostPort : null, hostIp: b.HostIp || null })
      }
    } else {
      ports.push({ containerPort, protocol, published: false, hostPort: null, hostIp: null })
    }
    seen.add(key)
  }

  const exposed = inspect?.Config?.ExposedPorts || {}
  for (const key of Object.keys(exposed)) {
    if (seen.has(key)) continue
    const [containerPortStr, protocol = 'tcp'] = key.split('/')
    const containerPort = Number(containerPortStr)
    if (!Number.isFinite(containerPort)) continue
    ports.push({ containerPort, protocol, published: false, hostPort: null, hostIp: null })
  }

  return ports
}

function normalizeNetworks(inspect) {
  const nets = inspect?.NetworkSettings?.Networks || {}
  return Object.entries(nets).map(([name, n]) => ({
    name,
    ipAddress: n?.IPAddress || null,
    aliases: Array.isArray(n?.Aliases) ? n.Aliases : [],
  }))
}

function stripLeadingSlash(name) {
  return typeof name === 'string' ? name.replace(/^\//, '') : name
}

// Docker LABELS are arbitrary text chosen by whoever built or ran the
// container — including newlines, braces and quotes. Compose service names
// flow into generated Caddy configuration (`reverse_proxy <service>:<port>`),
// so an unsanitised label lets any container on the host corrupt the config
// CatWAF writes, and with it the protection of every other app.
//
// Docker's own naming rules for containers and compose services are far
// narrower than what a label can hold, so anything outside them is rejected
// rather than escaped, and the container's real (Docker-validated) name is
// used instead.
const SAFE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/
const MAX_NAME_LEN = 128

function safeName(value, fallback = null) {
  if (typeof value !== 'string') return fallback
  const v = value.trim()
  if (!v || v.length > MAX_NAME_LEN) return fallback
  if (!SAFE_NAME_RE.test(v)) return fallback
  return v
}

// `psEntry` comes from `docker ps --format '{{json .}}'` (always present for
// a container that existed at scan time). `inspect` comes from
// `docker inspect` and may be null if the container disappeared or the
// daemon refused the request — everything below degrades gracefully.
function normalize(psEntry, inspect) {
  const incomplete = !inspect

  const id = inspect?.Id || psEntry?.ID || null
  // `docker ps` joins multiple names with a comma; keep the first.
  const rawName = stripLeadingSlash(inspect?.Name) || String(psEntry?.Names || '').split(',')[0] || id || 'unknown'
  const name = safeName(rawName, safeName(id) || 'unknown')
  const image = inspect?.Config?.Image || psEntry?.Image || 'unknown'
  const labels = inspect?.Config?.Labels || {}
  // Falls back to the container's Docker-validated name when the label is
  // absent or not a plain name (see safeName above).
  const composeService = safeName(labels['com.docker.compose.service'], name)

  return {
    id,
    name,
    image,
    running: inspect ? !!inspect?.State?.Running : /^up/i.test(psEntry?.State || psEntry?.Status || ''),
    labels,
    env: parseEnvList(inspect?.Config?.Env),
    cmd: Array.isArray(inspect?.Config?.Cmd) ? inspect.Config.Cmd.join(' ') : (psEntry?.Command || null),
    entrypoint: Array.isArray(inspect?.Config?.Entrypoint) ? inspect.Config.Entrypoint.join(' ') : null,
    ports: normalizePorts(inspect),
    networks: normalizeNetworks(inspect),
    composeService,
    composeProject: safeName(labels['com.docker.compose.project'], null),
    infraHint: INFRA_IMAGE_RE.test(image),
    incomplete,
  }
}

module.exports = { normalize, normalizePorts, normalizeNetworks, safeName, INFRA_IMAGE_RE }
