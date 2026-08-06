// discovery/runtime.js — web server and application runtime classification.
//
// Kept as small independent detectors (one function per family) precisely
// so adding a new runtime later is "add a function + register it", not a
// rewrite of a giant if/else chain.
//
// Which *web servers* exist is not decided here — that lives in
// discovery/webservers.js, so nginx, Apache and anything added later share
// one recognition path instead of each getting its own branch.

const webservers = require('./webservers')

// `server` is the profile id ('nginx' | 'apache' | 'caddy' | null) and is
// what the rest of the pipeline keys on. `label` is for humans ("Apache"),
// `confidence` is 0-100 (see webservers.js for the scoring).
function detectServer(container, processes) {
  const hit = webservers.detect(container, processes)
  if (!hit) return { server: null, label: null, confidence: 0, evidence: [] }
  return {
    server: hit.id,
    label: hit.label,
    confidence: hit.confidence,
    evidence: hit.evidence,
  }
}

function detectNode(container, processes) {
  const procText = (processes || []).join('\n')
  const imageHit = /(^|\/)node(:|$)/i.test(container.image)
  const processHit = /\bnode\b/i.test(procText)
  if (!imageHit && !processHit) return null
  const versionMatch = /node:(\d+)/i.exec(container.image)
  return {
    type: 'node',
    label: 'Node.js',
    version: versionMatch ? versionMatch[1] : null,
    evidence: [imageHit ? 'image is a Node.js base image' : null, processHit ? 'node process running' : null].filter(Boolean),
  }
}

function detectPython(container, processes) {
  const procText = (processes || []).join('\n')
  const imageHit = /(^|\/)python(:|$)/i.test(container.image)
  const processHit = /\b(python3?|gunicorn|uvicorn|flask|django)\b/i.test(procText)
  if (!imageHit && !processHit) return null
  const versionMatch = /python:(\d+\.\d+)/i.exec(container.image)
  return {
    type: 'python',
    label: 'Python',
    version: versionMatch ? versionMatch[1] : null,
    evidence: [imageHit ? 'image is a Python base image' : null, processHit ? 'Python process running (gunicorn/uvicorn/flask/django)' : null].filter(Boolean),
  }
}

// `phpInfo` comes from discovery/php.js, `serverInfo` from detectServer()
// above (call it first — php.js also consults it for its own scoring),
// `fastcgi` from discovery/fastcgi.js when this container proxies to a
// separate PHP-FPM backend, and `httpProxy` when it reverse-proxies to a
// non-PHP application container (Apache/nginx in front of Node or Python).
//
// PHP is never assumed: a web server with no PHP anywhere is classified by
// what it actually fronts — a proxied runtime, or static content.
function classify(container, { phpInfo, serverInfo, processes, webInfo, fastcgi, httpProxy } = {}) {
  const serverId = serverInfo?.server || null
  const serverLabel = serverInfo?.label || serverId

  if (phpInfo?.isPhp) {
    const evidence = ['PHP confidence >= threshold']
    if (fastcgi?.backendName) evidence.push(`FastCGI backend: ${fastcgi.target}`)
    return {
      type: 'php',
      label: phpInfo.runtime || 'PHP',
      version: null,
      server: serverId,
      serverLabel,
      fastcgiBackend: fastcgi?.backendName ? fastcgi.target : null,
      evidence,
    }
  }

  const node = detectNode(container, processes)
  if (node) return { ...node, server: serverId, serverLabel }

  const python = detectPython(container, processes)
  if (python) return { ...python, server: serverId, serverLabel }

  // A web server that reverse-proxies to an application container: the
  // application's runtime is what this endpoint actually serves.
  if (httpProxy?.backendRuntime) {
    return {
      type: httpProxy.backendRuntime.type,
      label: httpProxy.backendRuntime.label,
      version: httpProxy.backendRuntime.version || null,
      server: serverId,
      serverLabel,
      httpProxyBackend: httpProxy.target,
      evidence: [`${serverLabel || 'web server'} proxies to ${httpProxy.target} (${httpProxy.backendRuntime.label})`],
    }
  }

  if (serverId && webInfo?.isWeb) {
    return {
      type: 'static',
      label: `static (${serverLabel})`,
      version: null,
      server: serverId,
      serverLabel,
      evidence: [`serving via ${serverLabel} with no detected app runtime`],
    }
  }

  if (webInfo?.isWeb) {
    return { type: 'unknown', label: 'unknown web service', version: null, server: serverId, serverLabel, evidence: [] }
  }

  return null
}

module.exports = { detectServer, detectNode, detectPython, classify }
