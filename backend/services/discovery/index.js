// discovery/index.js — orchestrates the full `catwaf auto` discovery
// pipeline: Docker -> containers -> web ports -> correlation -> PHP/runtime
// classification.
//
// This runs in three passes rather than one, because some facts are only
// knowable by looking at containers *together*. A split nginx + PHP-FPM
// deployment is the motivating case: neither container looks like a PHP web
// app on its own (see discovery/fastcgi.js), so correlation has to happen
// after every container has been observed but before anything is classified.
//
//   pass 1  observe   — normalize metadata, processes, web ports, web server
//   pass 2  correlate — link web servers to their PHP-FPM backends
//   pass 3  classify  — PHP confidence + runtime, now correlation-aware
//
// Every container is processed defensively: one container with incomplete
// metadata, a mid-scan exit, or an inspect failure must never abort the
// scan for the rest.

const dockerMod = require('./docker')
const containersSvc = require('./containers')
const webSvc = require('./web')
const phpSvc = require('./php')
const runtimeSvc = require('./runtime')
const fastcgiSvc = require('./fastcgi')
const webservers = require('./webservers')

async function observeOne(dockerClient, psEntry, { skipHttpProbe }) {
  const inspect = dockerClient.inspectContainer(psEntry.ID)
  const normalized = containersSvc.normalize(psEntry, inspect)

  const processes = normalized.running ? dockerClient.topProcesses(normalized.id) : null

  // What the container is running is resolved BEFORE its ports, because it
  // is the strongest evidence that a port speaks HTTP — an nginx process on
  // :80 is an HTTP service whether or not that port is published. These two
  // detectors depend only on the container and its processes, so there is no
  // circularity with runtime.classify(), which runs later and needs webInfo.
  const serverInfo = runtimeSvc.detectServer(normalized, processes)
  const appHint = runtimeSvc.detectNode(normalized, processes) || runtimeSvc.detectPython(normalized, processes)

  // Read the web server's own configuration once, here, rather than again
  // per consumer. It tells us three things nothing else can: which port it
  // actually Listens on, where its DocumentRoot is (so PHP probes look in
  // the right place), and what it proxies to. Entirely best-effort — a
  // minimal image with no shell yields an empty result, never an error.
  const serverConfig = serverInfo.server
    ? webservers.readConfig(dockerClient, normalized, serverInfo.server)
    : { text: null, listens: [], documentRoots: [], httpProxies: [], empty: true }

  const webInfo = await webSvc.detectWebPort(normalized, {
    skipHttpProbe, serverInfo, appHint, configPorts: serverConfig.listens,
  })

  return { ...normalized, processes, web: webInfo, server: serverInfo, serverConfig }
}

function classifyOne(record, dockerClient) {
  const phpInfo = phpSvc.detect(record, {
    dockerClient,
    webInfo: record.web,
    processes: record.processes,
    serverInfo: record.server,
    fastcgi: record.fastcgi,
    // DocumentRoot from the server's own config, so PHP is found in
    // non-standard webroots instead of only the conventional guesses.
    extraWebroots: record.serverConfig?.documentRoots || [],
  })
  const runtimeInfo = runtimeSvc.classify(record, {
    phpInfo,
    serverInfo: record.server,
    processes: record.processes,
    webInfo: record.web,
    fastcgi: record.fastcgi,
    httpProxy: record.httpProxy,
  })
  record.php = phpInfo
  record.runtime = runtimeInfo
  return record
}

async function discover({ dockerClient = dockerMod, skipHttpProbe = false } = {}) {
  const availability = dockerClient.isAvailable()
  if (!availability.ok) {
    return { ok: false, code: availability.code, message: availability.message, containers: [] }
  }

  const listResult = dockerClient.listContainers()
  if (!listResult.ok) {
    return { ok: false, code: listResult.code, message: listResult.message, containers: [] }
  }

  const containers = []
  const errors = []

  // pass 1 — observe
  for (const psEntry of listResult.containers) {
    try {
      containers.push(await observeOne(dockerClient, psEntry, { skipHttpProbe }))
    } catch (e) {
      errors.push({ name: psEntry?.Names || psEntry?.ID || 'unknown', error: e.message })
    }
  }

  // pass 2 — correlate web servers with their PHP-FPM backends
  try {
    fastcgiSvc.correlate(containers, dockerClient)
  } catch (e) {
    errors.push({ name: 'fastcgi-correlation', error: e.message })
  }

  // pass 3 — classify
  for (const record of containers) {
    try {
      classifyOne(record, dockerClient)
    } catch (e) {
      errors.push({ name: record.name, error: e.message })
      record.php = record.php || { isPhp: false, confidence: 0, evidence: [] }
      record.runtime = record.runtime || null
    }
  }

  // A PHP-FPM backend serves FastCGI, not HTTP. It is part of a web
  // application but is never itself a routable one — CatWAF protects the
  // web server in front of it, not the FPM socket behind it.
  for (const record of containers) {
    if (record.fpm?.isBackend && record.fpm.servesFor.length && record.web) {
      record.web.isWeb = false
      record.web.evidence = [...(record.web.evidence || []), `PHP-FPM backend for ${record.fpm.servesFor.join(', ')} — not directly routable`]
    }
  }

  const webApps = containers.filter(c => c.web?.isWeb)

  return { ok: true, containers, webApps, errors }
}

module.exports = { discover, createDockerClient: dockerMod.createDockerClient }
