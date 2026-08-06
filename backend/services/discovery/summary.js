// discovery/summary.js — the safe, shared projection of a discovered
// container.
//
// Discovery records carry the container's raw environment and labels, which
// routinely hold database passwords and API keys. Nothing outside this
// module should ever hand a discovery record to a caller: the CLI's `--json`
// output and the dashboard's API both go through here, so the allowlist of
// fields that may leave the process is written down exactly once.

function summarizeContainer(ctr) {
  return {
    name: ctr.composeService || ctr.name,
    containerName: ctr.name,
    image: ctr.image,
    running: ctr.running,
    isWeb: !!ctr.web?.isWeb,
    webServer: ctr.server?.label || ctr.server?.server || null,
    webServerConfidence: ctr.server?.confidence ?? null,
    runtime: ctr.runtime?.label || null,
    framework: ctr.php?.framework || null,
    port: ctr.web?.hostPort || ctr.web?.port || null,
    published: !!ctr.web?.published,
    reachability: ctr.web?.reachability || null,
    networks: (ctr.networks || []).map(n => n.name),
    phpConfidence: ctr.php?.isPhp ? ctr.php.confidence : null,
    fastcgiBackend: ctr.fastcgi?.backendName ? ctr.fastcgi.target : null,
    fastcgiBasis: ctr.fastcgi?.basis || null,
    fpmBackendFor: ctr.fpm?.servesFor?.length ? ctr.fpm.servesFor : null,
    incomplete: !!ctr.incomplete,
  }
}

// The evidence trail behind a classification, for the "why does CatWAF think
// this is a PHP app?" disclosure.
//
// The detectors do not agree on a shape: web/runtime/server push plain
// strings, php pushes `{ signal, detail, points }` scoring entries. Flattening
// that here rather than at each display site is what keeps a consumer from
// having to know, and stops a UI from rendering "[object Object]".
//
// On content: these strings name images, processes, ports, config directives
// and files. Where a detector reads an environment variable it quotes only
// variables it looks for by name and whose value is a version or a marker
// (`PHP_VERSION`, `WORDPRESS_*`) — never an arbitrary variable, so a database
// password or an API key in the container's environment cannot reach here.
function toEvidenceLine(entry) {
  if (typeof entry === 'string') return entry
  if (entry && typeof entry === 'object' && typeof entry.detail === 'string') return entry.detail
  return String(entry)
}

function evidenceFor(ctr) {
  const lines = source => (Array.isArray(source) ? source : []).map(toEvidenceLine)
  return {
    web: lines(ctr.web?.evidence),
    php: lines(ctr.php?.evidence),
    runtime: lines(ctr.runtime?.evidence),
    server: lines(ctr.server?.evidence),
  }
}

module.exports = { summarizeContainer, evidenceFor }
