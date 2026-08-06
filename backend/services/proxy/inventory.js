// proxy/inventory.js — what is *actually* in the live Caddyfile right now.
//
// The port assignments in the database record what CatWAF intended; this
// reads what it wrote. Those two can disagree — an operator can delete the
// generated region by hand (the header comment invites it), and a plan that
// failed to apply leaves assignments behind with nothing serving them. The
// dashboard has to show the second thing, because that is what traffic hits.
//
// Deliberately a reader only: nothing here writes, reloads or repairs. The
// generated region has exactly one writer, proxy/apply.js, and it rebuilds
// the whole region from scratch every time.

const caddySvc = require('../caddy')
const generator = require('./generator')

// buildAutoRegion() emits, per route:
//
//   # <name> (<runtime>) — container <containerName>
//   :<port> {
//       reverse_proxy <upstream>[ { ... }]
//       ...
//   }
//
// so the header comment and the two directives below it are enough to
// reconstruct the route without keeping a second copy of it anywhere.
const HEADER_RE = /^#\s*(.+?)\s*\((.+?)\)\s*—\s*container\s+(.+?)\s*$/
const LISTEN_RE = /^:(\d{1,5})\s*\{\s*$/
const UPSTREAM_RE = /^reverse_proxy\s+(\S+)/

function autoRegion(content) {
  const { AUTO_MARKER_START, AUTO_MARKER_END } = generator
  const start = content.indexOf(AUTO_MARKER_START)
  const end = content.indexOf(AUTO_MARKER_END)
  if (start === -1 || end === -1 || end < start) return null
  return content.slice(start + AUTO_MARKER_START.length, end)
}

// Returns [] both when there is no generated region and when the Caddyfile
// cannot be read at all. The two are distinguished by read(), below, which
// the API uses so "CatWAF cannot read its own config" is never presented as
// "no applications are protected".
function parseRoutes(content) {
  const region = autoRegion(content)
  if (region === null) return []

  const routes = []
  let pending = null

  for (const raw of region.split('\n')) {
    const line = raw.trim()

    const header = HEADER_RE.exec(line)
    if (header) {
      pending = { name: header[1], runtime: header[2], containerName: header[3] }
      continue
    }

    const listen = LISTEN_RE.exec(line)
    if (listen) {
      routes.push({
        name: pending?.name || `:${listen[1]}`,
        runtime: pending?.runtime || null,
        containerName: pending?.containerName || null,
        listenPort: Number(listen[1]),
        upstream: null,
      })
      pending = null
      continue
    }

    const upstream = UPSTREAM_RE.exec(line)
    if (upstream && routes.length && routes[routes.length - 1].upstream === null) {
      // Strip the scheme the gRPC path adds, so the reported upstream is the
      // address an operator would recognise.
      routes[routes.length - 1].upstream = upstream[1].replace(/^h2c:\/\//, '')
    }
  }

  return routes
}

function read() {
  let content
  try {
    content = caddySvc.readCaddyfile()
  } catch (e) {
    return {
      ok: false,
      error: `CatWAF cannot read its Caddyfile at ${caddySvc.CADDYFILE_PATH}: ${e.message}`,
      routes: [],
      hasRegion: false,
    }
  }
  return {
    ok: true,
    error: null,
    caddyfile: caddySvc.CADDYFILE_PATH,
    hasRegion: autoRegion(content) !== null,
    routes: parseRoutes(content),
  }
}

module.exports = { read, parseRoutes, autoRegion }
