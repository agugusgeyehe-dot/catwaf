#!/usr/bin/env node


const fs = require('fs')
const path = require('path')
const { spawn, spawnSync, execFileSync } = require('child_process')

const PROJECT_ROOT = path.join(__dirname, '..')
require(path.join(PROJECT_ROOT, 'backend', 'services', 'env.js')).load()

function log(msg) { console.log(`[dev] ${msg}`) }

function hasWorkingCoraza(bin) {
  try {
    const out = execFileSync(bin, ['list-modules'], { timeout: 5000 }).toString()
    return out.includes('http.handlers.waf')
  } catch { return false }
}

function findCaddyBinary() {
  const vendored = path.join(PROJECT_ROOT, 'bin', 'vendor', 'caddy')
  for (const candidate of ['caddy', vendored]) {
    if (hasWorkingCoraza(candidate)) return candidate
  }
  return null
}

function caddyAlreadyRunning() {
  try { execFileSync('pgrep', ['-x', 'caddy'], { timeout: 3000 }); return true } catch { return false }
}

function wafBlock(indent, auditLogPath) {
  return `${indent}coraza_waf {
${indent}    load_owasp_crs
${indent}    directives \`
${indent}        Include @coraza.conf-recommended
${indent}        Include @crs-setup.conf.example
${indent}        Include @owasp_crs/*.conf
${indent}        SecRuleEngine On
${indent}        SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1"
${indent}        SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=1"
${indent}        SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"
${indent}        SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:tx.allowed_methods=GET POST HEAD OPTIONS PUT DELETE PATCH"
${indent}        SecRequestBodyAccess On
${indent}        SecAuditEngine RelevantOnly
${indent}        SecAuditLogParts ABCEFHZ
${indent}        SecAuditLogType Serial
${indent}        SecAuditLog ${auditLogPath}
${indent}        SecAuditLogFormat JSON
${indent}    \`
${indent}}`
}

function writeDevCaddyfile({ externalDashboardPort, externalApiPort, vitePort, backendPort }) {
  const dataDir = path.join(PROJECT_ROOT, 'data')
  fs.mkdirSync(dataDir, { recursive: true })
  const auditLogPath = path.join(dataDir, 'coraza-dev-audit.json')

  const content = `# Caddyfile.dev — generated automatically by \`npm run dev\`, regenerated on
# every run. This is NOT the Caddyfile \`catwaf --setup\` manages (that one
# lives at ./Caddyfile and is never touched by this script) — it's a
# throwaway dev-only front so requests to :${externalDashboardPort}/:${externalApiPort} pass through
# Coraza before reaching Vite/the backend. Safe to delete.

{
    admin 127.0.0.1:2019
    order coraza_waf first
}

http://localhost:${externalDashboardPort} {
${wafBlock('    ', auditLogPath)}
    reverse_proxy 127.0.0.1:${vitePort}
}

http://localhost:${externalApiPort} {
${wafBlock('    ', auditLogPath)}
    reverse_proxy 127.0.0.1:${backendPort}
}
`
  const caddyfilePath = path.join(PROJECT_ROOT, 'Caddyfile.dev')
  fs.writeFileSync(caddyfilePath, content, 'utf8')
  return caddyfilePath
}

function main() {
  spawnSync(process.execPath, [path.join(PROJECT_ROOT, 'scripts', 'ensure-catai-runtime.js')], { stdio: 'inherit' })

  const externalDashboardPort = Number(process.env.VITE_DEV_PORT_EXTERNAL || 3000)
  const externalApiPort = Number(process.env.PORT || 8000)

  const tasks = [
    { name: 'backend', color: 'blue', cmd: 'npm:dev:backend' },
    { name: 'frontend', color: 'magenta', cmd: 'npm:dev:frontend' },
  ]
  const env = { ...process.env }

  const caddyBin = findCaddyBinary()
  if (!caddyBin) {
    log('Caddy with the Coraza module isn\'t available — dev traffic will NOT pass through the WAF.')
    log('`npm install` fetches it automatically; see docs/installation.md if that failed.')
  } else if (caddyAlreadyRunning()) {
    log('A Caddy process is already running — leaving it alone rather than starting a second one.')
    log('If it isn\'t fronting this dev session, traffic won\'t be WAF-inspected.')
  } else {
    const vitePort = Number(process.env.CATWAF_DEV_VITE_PORT || 5173)
    const backendPort = Number(process.env.CATWAF_DEV_BACKEND_PORT || 8001)

    writeDevCaddyfile({ externalDashboardPort, externalApiPort, vitePort, backendPort })

    env.PORT = String(backendPort)
    env.VITE_DEV_PORT = String(vitePort)
    env.VITE_BACKEND_PORT = String(backendPort)
    env.VITE_HMR_CLIENT_PORT = String(externalDashboardPort)
    if (!env.CORS_ORIGIN) env.CORS_ORIGIN = `http://localhost:${externalDashboardPort}`

    tasks.push({ name: 'caddy', color: 'green', cmd: `${caddyBin} run --config Caddyfile.dev --adapter caddyfile` })
    log(`WAF is in the loop — dashboard http://localhost:${externalDashboardPort}, API http://localhost:${externalApiPort}`)
    log(`(internally: Vite on :${vitePort}, backend on :${backendPort})`)
  }

  const concurrentlyBin = path.join(PROJECT_ROOT, 'node_modules', '.bin', 'concurrently')
  const child = spawn(concurrentlyBin, [
    '-k',
    '-n', tasks.map(t => t.name).join(','),
    '-c', tasks.map(t => t.color).join(','),
    ...tasks.map(t => t.cmd),
  ], { cwd: PROJECT_ROOT, stdio: 'inherit', env })

  child.on('exit', (code) => process.exit(code ?? 0))
  child.on('error', (e) => { log(`Failed to start: ${e.message}`); process.exit(1) })
}

main()
