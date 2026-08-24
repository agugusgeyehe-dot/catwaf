#!/usr/bin/env node

// Standalone benchmark harness: measures what CatWAF's edge-ban region (and,
// when a Coraza-enabled Caddy is installed, the coraza_waf directive) costs
// on top of a plain Caddy reverse proxy. Real requests over raw HTTP
// keep-alive sessions driven from this process — no new dependencies.
//
// Usage:
//   node scripts/bench.js [--requests 20000] [--concurrency 50]
//
// Output is a markdown table ready to paste into docs/performance.md.

const fs = require('fs')
const net = require('net')
const os = require('os')
const path = require('path')
const http = require('http')
const { execFileSync, spawn } = require('child_process')

const ROOT = path.join(__dirname, '..')
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-bench-'))

const argv = process.argv.slice(2)
function flagNum(name, def) {
  const i = argv.indexOf(name)
  if (i === -1 || !argv[i + 1]) return def
  const n = Number(argv[i + 1])
  return Number.isFinite(n) && n > 0 ? n : def
}

const REQUESTS = Math.floor(flagNum('--requests', 20000))
const CONCURRENCY = Math.min(Math.floor(flagNum('--concurrency', 50)), REQUESTS)
const WARMUP = Math.min(200, REQUESTS)
const SCENARIO_BUDGET_MS = 20000
const TOTAL_BUDGET_MS = 55000
const BOOT_TIMEOUT_MS = 10000

function resolveCaddy() {
  for (const candidate of ['caddy', path.join(ROOT, 'bin', 'vendor', 'caddy')]) {
    try { execFileSync(candidate, ['version'], { timeout: 8000 }); return candidate } catch {}
  }
  return null
}

function hasCorazaModule(bin) {
  try {
    return execFileSync(bin, ['list-modules'], { timeout: 8000 }).toString().includes('http.handlers.waf')
  } catch { return false }
}

function caddyVersion(bin) {
  try { return execFileSync(bin, ['version'], { timeout: 8000 }).toString().trim() } catch { return 'unknown' }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.unref()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
  })
}

function get(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, res => {
      res.resume()
      res.on('end', () => resolve(res.statusCode))
    })
    req.on('error', reject)
    req.setTimeout(4000, () => req.destroy(new Error('timeout')))
  })
}

async function waitFor(fn, attempts = 40, delayMs = 250) {
  for (let i = 0; i < attempts; i++) {
    try { if (await fn()) return true } catch {}
    await new Promise(r => setTimeout(r, delayMs))
  }
  return false
}

function childClosed(child) {
  return new Promise(resolve => { if (child.exitCode !== null) resolve(); else child.on('close', resolve) })
}

const ORIGIN_SCRIPT = `
const http = require('http')
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': 2 })
  res.end('ok')
})
server.keepAliveTimeout = 65000
server.headersTimeout = 66000
server.listen(Number(process.env.BENCH_ORIGIN_PORT), '127.0.0.1')
`

function renderConfig(kind, adminPort, sitePort, originPort) {
  const lines = ['{', `    admin 127.0.0.1:${adminPort}`]
  if (kind === 'coraza') lines.push('    order coraza_waf first')
  lines.push('}', '', `:${sitePort} {`)
  if (kind === 'coraza') {
    // Minimal non-matching rule: measures the Coraza hop, not CRS cost.
    lines.push(
      '    coraza_waf {',
      '        directives `',
      '            SecRuleEngine On',
      '            SecRule ARGS "@contains catwaf_bench_never_matches" "id:10001,phase:2,deny,status:403,nolog"',
      '        `',
      '    }',
    )
  }
  // Same shape backend/services/edgeBans.js renders; 192.0.2.0/24 is
  // TEST-NET-1, so this matcher is active but bans nobody real.
  if (kind === 'edge' || kind === 'coraza') {
    lines.push(
      '    @catwaf_edge_bans remote_ip 192.0.2.1',
      '    handle @catwaf_edge_bans {',
      '        abort',
      '    }',
    )
  }
  lines.push(
    kind === 'plain'
      ? `    reverse_proxy 127.0.0.1:${originPort}`
      : '    handle {',
  )
  if (kind !== 'plain') {
    lines.push(`        reverse_proxy 127.0.0.1:${originPort}`, '    }')
  }
  lines.push('}', '')
  return lines.join('\n')
}

// Drives `total` GETs against `url` with at most `concurrency` in flight,
// reusing keep-alive sockets via one Agent. Latency is per-request wall
// time from dispatch to response end.
function drive(url, total, concurrency, deadlineMs) {
  return new Promise(done => {
    const agent = new http.Agent({ keepAlive: true, maxSockets: concurrency, maxFreeSockets: concurrency })
    const latencies = new Array(total)
    let nextId = 0
    let completed = 0
    let errors = 0
    let inflight = 0
    let settled = false
    const t0 = process.hrtime.bigint()

    const timer = deadlineMs ? setTimeout(finish, deadlineMs) : null

    function finish() {
      if (settled) return
      settled = true
      clearTimeout(timer)
      agent.destroy()
      const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6
      done({
        latencies: latencies.slice(0, completed).filter(Number.isFinite).sort((a, b) => a - b),
        errors,
        elapsedMs,
        partial: completed < total,
        completed,
      })
    }

    function record(id, start, failed) {
      if (settled) return
      inflight--
      latencies[id] = Number(process.hrtime.bigint() - start) / 1e6
      completed++
      if (failed) errors++
      if (completed >= total) finish()
      else launch()
    }

    function launch() {
      while (!settled && inflight < concurrency && nextId < total) {
        const id = nextId++
        inflight++
        const start = process.hrtime.bigint()
        let recorded = false
        const once = (failed) => { if (!recorded) { recorded = true; record(id, start, failed) } }
        const req = http.get(url, { agent }, res => {
          res.resume()
          res.on('end', () => once(false))
          res.on('error', () => once(true))
        })
        req.on('error', () => once(true))
      }
    }

    launch()
  })
}

function pct(sorted, q) {
  if (!sorted.length) return NaN
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((q / 100) * sorted.length) - 1))
  return sorted[idx]
}

async function runScenario(name, kind, originPort, deadlineMs) {
  const adminPort = await freePort()
  const sitePort = await freePort()
  const cfgPath = path.join(WORK, `Caddyfile-${kind}`)
  fs.writeFileSync(cfgPath, renderConfig(kind, adminPort, sitePort, originPort))

  const proc = spawn(CADDY_BIN, ['run', '--config', cfgPath, '--adapter', 'caddyfile'], { stdio: 'ignore' })
  const url = `http://127.0.0.1:${sitePort}/`
  try {
    const up = await waitFor(async () => (await get(url)) === 200, Math.ceil(BOOT_TIMEOUT_MS / 250), 250)
    if (!up) throw new Error(`caddy did not come up for scenario "${name}"`)

    await drive(url, WARMUP, CONCURRENCY, 15000)
    const r = await drive(url, REQUESTS, CONCURRENCY, deadlineMs)

    const seconds = r.elapsedMs / 1000
    return {
      name,
      requests: r.completed,
      rps: r.completed / seconds,
      p50: pct(r.latencies, 50),
      p95: pct(r.latencies, 95),
      errors: r.errors,
      partial: r.partial,
    }
  } finally {
    try { proc.kill('SIGKILL') } catch {}
    await childClosed(proc)
  }
}

let CADDY_BIN = null

function cleanup() {
  try { fs.rmSync(WORK, { recursive: true, force: true }) } catch {}
  try { if (originProc) originProc.kill('SIGKILL') } catch {}
}
process.on('exit', cleanup)
process.on('SIGINT', () => { cleanup(); process.exit(130) })
process.on('SIGTERM', () => { cleanup(); process.exit(143) })

let originProc = null

;(async () => {
  CADDY_BIN = resolveCaddy()
  if (!CADDY_BIN) {
    console.error('No usable caddy binary found (looked at: `caddy`, bin/vendor/caddy).')
    console.error('')
    console.error('Install one first:')
    console.error('  node scripts/ensure-caddy.js          # downloads a pinned Coraza-enabled build')
    console.error('  npm install                           # postinstall does this automatically')
    console.error('  xcaddy build --with github.com/corazawaf/coraza-caddy/v2   # or build your own')
    console.error('')
    console.error('Then re-run: node scripts/bench.js')
    process.exit(1)
  }

  const originPort = await freePort()
  originProc = spawn(process.execPath, ['-e', ORIGIN_SCRIPT], {
    env: { ...process.env, BENCH_ORIGIN_PORT: String(originPort) },
    stdio: 'ignore',
  })
  const originUp = await waitFor(async () => (await get(`http://127.0.0.1:${originPort}/`)) === 200)
  if (!originUp) throw new Error('bench origin did not start')

  const scenarios = [
    { name: 'plain reverse_proxy', kind: 'plain' },
    { name: '+ edge-ban region (bans nothing)', kind: 'edge' },
  ]
  if (hasCorazaModule(CADDY_BIN)) {
    scenarios.push({ name: '+ edge-ban region + coraza_waf (no CRS)', kind: 'coraza' })
  }

  const startedAt = Date.now()
  const rows = []
  for (const s of scenarios) {
    const elapsed = Date.now() - startedAt
    const budgetLeft = TOTAL_BUDGET_MS - elapsed - 5000
    if (budgetLeft <= 3000) { console.log(`skipping "${s.name}" — time budget exhausted`); break }
    const row = await runScenario(s.name, s.kind, originPort, Math.min(SCENARIO_BUDGET_MS, budgetLeft))
    rows.push(row)
    console.log(`${row.name}: ${Math.round(row.rps)} rps  p50 ${row.p50.toFixed(2)}ms  p95 ${row.p95.toFixed(2)}ms  errors ${row.errors}${row.partial ? '  (partial: time budget hit)' : ''}`)
  }

  const now = new Date().toISOString().slice(0, 10)
  const table = [
    `### Benchmark — CatWAF edge layers (${now})`,
    '',
    '| Scenario | Requests | Concurrency | RPS | p50 (ms) | p95 (ms) | Errors |',
    '| --- | ---: | ---: | ---: | ---: | ---: | ---: |',
    ...rows.map(r =>
      `| ${r.name} | ${r.requests} | ${CONCURRENCY} | ${r.rps.toFixed(0)} | ${r.p50.toFixed(2)} | ${r.p95.toFixed(2)} | ${r.errors} |`),
    '',
    `<details><summary>Environment</summary>`,
    '',
    `- Date: ${now}`,
    `- Caddy: \`${caddyVersion(CADDY_BIN)}\``,
    `- Node: \`${process.version}\``,
    `- Platform: \`${os.platform()} ${os.release()} ${os.arch()}\``,
    `- Loopback only, single machine — treat these numbers as relative, not absolute.`,
    '',
    '</details>',
    '',
  ].join('\n')

  console.log('\nMarkdown for docs/performance.md:\n')
  console.log(table)
  cleanup()
  process.exit(0)
})().catch(e => {
  console.error('\nBench error:', e.message)
  cleanup()
  process.exit(1)
})
