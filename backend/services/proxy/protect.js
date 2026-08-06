// proxy/protect.js — the full "put my website behind CatWAF" pipeline.
//
//   discover -> resolve upstreams (attaching the proxy to Docker networks
//   as needed) -> plan routes -> generate -> validate -> back up -> apply
//   atomically -> reload -> VERIFY WITH REAL TRAFFIC -> report
//
// The last step is the one that matters. Everything before it only proves
// CatWAF wrote a syntactically valid file; only the verification step
// proves the request path is actually
//
//     client -> CatWAF -> Coraza/CRS -> upstream
//
// so a route is reported as `protected` only when a real CRS payload was
// really refused and a real benign request really succeeded. If either
// check fails the route is reported unprotected, with the reason.
//
// Idempotency: rerunning regenerates CatWAF's own marked region from
// scratch and leaves every other part of the Caddyfile untouched, so
// repeated runs converge rather than accumulating duplicate routes.
// Listen ports are remembered (see proxy/routes.js) so an app keeps the
// endpoint it was already published on.

const discovery = require('../discovery')
const dockerMod = require('../discovery/docker')
const routesSvc = require('./routes')
const applySvc = require('./apply')
const networkSvc = require('./network')
const caddySvc = require('../caddy')
const verifySvc = require('./verify')

async function protect({
  dockerClient = dockerMod,
  state,
  db = null,
  dryRun = false,
  skipVerify = false,
  skipHttpProbe = false,
  startProxy = null,
} = {}) {
  const report = await discovery.discover({ dockerClient, skipHttpProbe })
  if (!report.ok) {
    return { ok: false, stage: 'discovery', code: report.code, error: report.message, containers: [] }
  }

  const proxy = networkSvc.describeProxy(dockerClient)

  const { routes, skipped } = await routesSvc.planRoutes(report.webApps, {
    db,
    // --dry-run must not persist port assignments either.
    persist: !dryRun,
    resolveUpstream: container => networkSvc.resolveUpstream(container, { dockerClient, proxy, dryRun }),
    basePort: Number(process.env.CATWAF_AUTO_BASE_PORT) || undefined,
  })

  // What discovery found is a fact about the environment and is reported
  // identically on every path from here on. Omitting it from one branch
  // previously made an apply FAILURE read as "no web application found",
  // which hid the real error and made `auto` look like it discovered
  // nothing while `auto --dry-run` discovered the app fine.
  const base = {
    containers: report.containers,
    webApps: report.webApps,
    routes,
    skipped,
    proxy,
  }

  if (!routes.length) {
    return { ...base, ok: true, stage: 'plan', noRoutes: true }
  }

  const applied = applySvc.apply({ routes, waf: state.WAF, dryRun })
  if (!applied.ok) {
    return { ...base, ok: false, stage: 'apply', error: applied.error, message: applied.message }
  }

  if (dryRun) {
    return { ...base, ok: true, dryRun: true, stage: 'dry-run', config: applied.config }
  }

  // Applied — but not yet proven. Do not call anything protected here.
  const result = {
    ...base,
    ok: true,
    stage: 'applied',
    backup: applied.backup,
    reloaded: applied.reloaded,
    reloadError: applied.reloadError,
  }

  if (skipVerify) return { ...result, verification: null }

  // A written config protects nothing if no proxy is serving it. A reload
  // failure usually just means Caddy is not running at all — on a fresh
  // install nothing has started it yet. Starting it is part of "put my
  // website behind CatWAF", not something to hand back to the user.
  let proxyStarted = null
  if (!applied.reloaded && startProxy && !caddySvc.isCaddyRunning()) {
    try {
      proxyStarted = startProxy()
    } catch (e) {
      proxyStarted = { ok: false, error: e.message }
    }
    result.proxyStarted = proxyStarted
  }

  const live = applied.reloaded || (proxyStarted && proxyStarted.ok)
  if (!live) {
    const why = proxyStarted && !proxyStarted.ok
      ? `the WAF proxy could not be started (${proxyStarted.error || 'unknown'})`
      : `Caddy did not reload (${applied.reloadError || 'unknown'})`
    return {
      ...result,
      verification: {
        results: routes.map(r => ({
          name: r.name,
          protected: false,
          reason: `${why}, so the new configuration is not live yet.`,
        })),
        protectedCount: 0,
        allProtected: false,
      },
    }
  }

  // verifyRoutes retries while the proxy comes up, so a just-started Caddy
  // is given time to bind before anything is declared unprotected.
  const verification = await verifySvc.verifyRoutes(routes)
  return { ...result, stage: verification.allProtected ? 'protected' : 'unverified', verification }
}

module.exports = { protect }
