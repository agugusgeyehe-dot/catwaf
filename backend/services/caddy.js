
const fs = require('fs')
const state = require('./state')
const auditSvc = require('./audit')
const {
  escapeForDirective, isValidIpOrCidr,
  ALLOWED_VARIABLES, ALLOWED_OPERATORS, ALLOWED_ACTIONS, ALLOWED_PHASES,
} = require('./sanitize')

const { execFileSync } = require('child_process')

const path = require('path')
const PROJECT_ROOT = path.join(__dirname, '..', '..')

const WAF_MARKER_START = '# @@CATWAF_WAF_START@@'
const WAF_MARKER_END   = '# @@CATWAF_WAF_END@@'

function candidatePaths() {
  const out = []

  try {
    const unit = execFileSync('systemctl', ['cat', 'caddy'], { encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'] })
    const m = /^ExecStart=.*?--config\s+(\S+)/m.exec(unit)
    if (m) out.push(m[1])
  } catch {}

  out.push(
    path.join(PROJECT_ROOT, 'Caddyfile'),
    '/etc/caddy/Caddyfile',
    '/usr/local/etc/caddy/Caddyfile',
    '/opt/homebrew/etc/Caddyfile',
    '/usr/local/etc/Caddyfile',
  )
  return [...new Set(out)]
}

function scorePath(p) {
  let score = 0
  try {
    const body = fs.readFileSync(p, 'utf8')
    score += 10
    if (body.includes(WAF_MARKER_START)) score += 100
  } catch { return 0 }
  try { fs.accessSync(p, fs.constants.W_OK); score += 5 } catch {}
  return score
}

function detectCaddyfilePath() {
  if (process.env.CADDYFILE_PATH) return process.env.CADDYFILE_PATH

  const scored = candidatePaths()
    .map(p => ({ p, score: scorePath(p) }))
    .filter(c => c.score > 0)
    .sort((a, b) => b.score - a.score)

  if (scored.length) return scored[0].p

  return path.join(PROJECT_ROOT, 'Caddyfile')
}

const CADDYFILE_PATH  = detectCaddyfilePath()
const CADDYFILE_SOURCE = process.env.CADDYFILE_PATH ? 'CADDYFILE_PATH' : 'auto-detected'
const CORAZA_LIST_DIR = process.env.CORAZA_LIST_DIR || '/etc/coraza/lists'
const CADDY_ADMIN_URL = (process.env.CADDY_ADMIN_URL || 'http://127.0.0.1:2019').replace(/\/+$/, '')
const AUDIT_LOG_PATH  = process.env.CORAZA_AUDIT_LOG || '/var/log/coraza/audit.json'

const ADMIN_CLIENT_SCRIPT = `
let body = ''
process.stdin.on('data', c => { body += c })
process.stdin.on('end', async () => {
  const url = process.env.CW_ADMIN_URL + process.env.CW_ADMIN_PATH
  const method = process.env.CW_ADMIN_METHOD
  const opts = { method, signal: AbortSignal.timeout(Number(process.env.CW_ADMIN_TIMEOUT)) }
  if (method !== 'GET') {
    opts.headers = {
      'Content-Type': process.env.CW_ADMIN_CTYPE,
      'Origin': process.env.CW_ADMIN_URL,
    }
    opts.body = body
  }
  try {
    const res = await fetch(url, opts)
    const text = await res.text()
    process.stdout.write(text)
    process.exit(res.ok ? 0 : 1)
  } catch (e) {
    process.stderr.write(e.message)
    process.exit(1)
  }
})
`

function adminApiRequest(method, apiPath, body = '', contentType = 'application/json', timeoutMs = 10000) {
  const out = execFileSync(process.execPath, ['-e', ADMIN_CLIENT_SCRIPT], {
    input: body,
    timeout: timeoutMs + 2000,
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      CW_ADMIN_URL: CADDY_ADMIN_URL,
      CW_ADMIN_PATH: apiPath,
      CW_ADMIN_METHOD: method,
      CW_ADMIN_CTYPE: contentType,
      CW_ADMIN_TIMEOUT: String(timeoutMs),
    },
  })
  return out.toString()
}


function num(value, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const n = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(n)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(n)))
}

function oneOf(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback
}

function buildWAFBlock(waf) {
  const lines = []
  lines.push(WAF_MARKER_START)
  lines.push('# CatWAF WAF Rules — auto-generated, do not edit manually')
  lines.push('')

  lines.push('  coraza_waf {')
  lines.push('    load_owasp_crs')
  lines.push('    directives `')
  lines.push('      Include @coraza.conf-recommended')
  lines.push('      Include @crs-setup.conf.example')
  lines.push('      Include @owasp_crs/*.conf')
  const blockingPL = num(waf.paranoia_level, 1, { min: 1, max: 4 })
  const detectionPL = Math.max(blockingPL, num(waf.executing_paranoia_level, 2, { min: 1, max: 4 }))
  const methods = (Array.isArray(waf.allowed_methods) ? waf.allowed_methods : [])
    .filter(m => typeof m === 'string' && /^[A-Za-z]{3,10}$/.test(m))
    .map(m => m.toUpperCase())

  lines.push(`      SecRuleEngine ${oneOf(waf.engine, ['On', 'DetectionOnly', 'Off'], 'On')}`)
  lines.push(`      SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=${blockingPL}"`)
  lines.push(`      SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=${detectionPL}"`)
  lines.push(`      SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=${num(waf.inbound_anomaly_threshold, 5, { min: 1, max: 1000 })},setvar:tx.outbound_anomaly_score_threshold=${num(waf.outbound_anomaly_threshold, 4, { min: 1, max: 1000 })}"`)
  lines.push(`      SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:tx.allowed_methods=${(methods.length ? methods : ['GET', 'POST', 'HEAD', 'OPTIONS']).join(' ')}"`)
  lines.push(`      SecAction "id:900120,phase:1,pass,t:none,nolog,setvar:tx.early_blocking=${waf.early_blocking ? '1' : '0'}"`)
  lines.push(`      SecRequestBodyAccess ${waf.request_body_inspection ? 'On' : 'Off'}`)
  lines.push(`      SecResponseBodyAccess ${waf.response_body_inspection ? 'On' : 'Off'}`)
  lines.push(`      SecRequestBodyLimit ${num(waf.max_request_body_size, 13107200, { min: 1024, max: 1073741824 })}`)

  let ruleId = 9100
  for (const ip of (waf.ip_blacklist || [])) {
    if (!isValidIpOrCidr(ip.ip)) continue
    lines.push(`      SecRule REMOTE_ADDR "@ipMatch ${ip.ip}" "id:${ruleId++},phase:1,deny,status:403,msg:'CatWAF Blacklisted IP ${ip.ip}'"`)
  }

  ruleId = 9200
  for (const ip of (waf.ip_whitelist || [])) {
    if (!isValidIpOrCidr(ip.ip)) continue
    lines.push(`      SecRule REMOTE_ADDR "@ipMatch ${ip.ip}" "id:${ruleId++},phase:1,allow,msg:'CatWAF Whitelisted IP ${ip.ip}'"`)
  }

  if (waf.geo_blocking && waf.geo_blocking.length > 0) {
    const codes = waf.geo_blocking.filter(cc => /^[A-Z]{2}$/.test(cc))
    if (codes.length > 0) lines.push(`      SecRule GEO:COUNTRY_CODE "@pm ${codes.join(' ')}" "id:9001,phase:1,deny,status:403,msg:'CatWAF Geo Block'"`)
  }

  ruleId = 9300
  for (const r of (waf.custom_rules || [])) {
    if (!r || typeof r !== 'object' || r.enabled === false) continue
    const variable = oneOf(r.variable, [...ALLOWED_VARIABLES], 'ARGS')
    const operator = oneOf(r.operator, [...ALLOWED_OPERATORS], 'contains')
    const action = oneOf(r.action, [...ALLOWED_ACTIONS], 'deny')
    const phase = oneOf(num(r.phase, 2, { min: 1, max: 5 }), [...ALLOWED_PHASES], 2)
    const id = /^\d{1,10}$/.test(String(r.id)) ? String(r.id) : String(ruleId++)
    const value = escapeForDirective(r.value)
    const name = escapeForDirective(r.name)
    lines.push(`      SecRule ${variable} "@${operator} ${value}" "id:${id},phase:${phase},${action},log,msg:'${name}'"`)
  }

  for (const e of (waf.rule_exclusions || [])) {
    if (!e || typeof e !== 'object') continue
    if (!/^\d{1,10}(-\d{1,10})?$/.test(String(e.rule_id))) continue
    lines.push(`      SecRuleUpdateTargetById ${e.rule_id} "!${escapeForDirective(e.target)}:${escapeForDirective(e.value)}"`)
  }

  const RULE_CATS = state.RULE_CATEGORIES
  for (const [id, cat] of Object.entries(RULE_CATS)) {
    if (!cat.enabled) {
      lines.push(`      SecRuleRemoveById ${id}000-${id}999`)
    }
  }

  for (const ruleId of (waf.disabled_rules || [])) {
    if (!/^\d{3,7}$/.test(String(ruleId))) continue
    lines.push(`      SecRuleRemoveById ${ruleId}`)
  }

  if (waf.allowed_content_types && waf.allowed_content_types.length > 0) {
    const contentTypes = waf.allowed_content_types.map(t => escapeForDirective(String(t))).join('|')
    lines.push(`      SecAction "id:900006,phase:1,pass,t:none,nolog,setvar:'tx.allowed_request_content_type=${contentTypes}.replace(/\\|/,\' \')'"`)
  }

  const sampling = num(waf.sampling_percentage, 100, { min: 0, max: 100 })
  if (sampling > 0 && sampling < 100) {
    lines.push(`      SecRule TX:SAMPLING_RNDM "@lt ${100 - sampling}" "id:900500,phase:1,pass,nolog,skipAfter:END_SAMPLING"`)
    lines.push(`      SecMarker END_SAMPLING`)
  }

  const phpExcl = waf.php_exclusions || {}
  let phpRuleId = 9400
  if (phpExcl.wordpress) {
    lines.push(`      SecRule REQUEST_URI "@beginsWith /wp-admin" "id:${phpRuleId++},phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`)
    lines.push(`      SecRule REQUEST_URI "@contains /wp-json" "id:${phpRuleId++},phase:1,pass,nolog,ctl:ruleRemoveById=941000-941999"`)
  }
  if (phpExcl.laravel) {
    lines.push(`      SecRule ARGS:_token "@rx ^[A-Za-z0-9+/=]{40}$" "id:${phpRuleId++},phase:2,pass,nolog,ctl:ruleRemoveTargetById=941100;ARGS:_token"`)
  }
  if (phpExcl.drupal) {
    lines.push(`      SecRule REQUEST_URI "@beginsWith /admin/views" "id:${phpRuleId++},phase:1,pass,nolog,ctl:ruleRemoveById=942000-942999"`)
  }
  if (phpExcl.joomla) {
    lines.push(`      SecRule REQUEST_URI "@contains /administrator" "id:${phpRuleId++},phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`)
  }

  if (waf.blocked_user_agents && waf.blocked_user_agents.length > 0) {
    const pattern = waf.blocked_user_agents
      .map(u => escapeForDirective(String(u)).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      .join('|')
    lines.push(`      SecRule REQUEST_HEADERS:User-Agent "@rx (?i)${pattern}" "id:9050,phase:1,deny,status:403,log,msg:'CatWAF Blocked Scanner UA'"`)
  }

  lines.push(`      SecAuditEngine ${waf.audit_log ? 'RelevantOnly' : 'Off'}`)
  lines.push('      SecAuditLogParts ABCEFHZ')
  lines.push('      SecAuditLogType Serial')
  lines.push(`      SecAuditLog ${AUDIT_LOG_PATH}`)
  lines.push('      SecAuditLogFormat JSON')

  lines.push('    `')
  lines.push('  }')
  lines.push('')
  lines.push(WAF_MARKER_END)
  return lines.join('\n')
}


const ORDER_DIRECTIVE = 'order coraza_waf first'

function globalOptionsRange(content) {
  const m = content.match(/^(?:[ \t]*(?:#[^\n]*)?\n)*[ \t]*\{/)
  if (!m) return null
  const start = m[0].lastIndexOf('{') + m.index
  let depth = 0
  for (let i = start; i < content.length; i++) {
    const ch = content[i]
    if (ch === '{') depth++
    else if (ch === '}') {
      depth--
      if (depth === 0) return { start, end: i }
    }
  }
  return null
}

function lastSiteBlockClose(content) {
  const global = globalOptionsRange(content)
  let idx = content.lastIndexOf('}')
  while (idx !== -1) {
    if (!global || idx > global.end) return idx
    idx = content.lastIndexOf('}', idx - 1)
  }
  return -1
}

function ensureGlobalOrderDirective(content) {
  const globalBlockMatch = content.match(/^(?:[ \t]*(?:#[^\n]*)?\n)*[ \t]*\{([\s\S]*?)\n\}/)
  if (globalBlockMatch) {
    if (globalBlockMatch[1].includes('order coraza_waf')) return content
    const insertAt = globalBlockMatch.index + globalBlockMatch[0].length - 2
    return content.slice(0, insertAt) + `\n    ${ORDER_DIRECTIVE}` + content.slice(insertAt)
  }
  return `{\n    ${ORDER_DIRECTIVE}\n}\n\n${content}`
}

function patchWAFCaddyfile(waf) {
  let content = readCaddyfile()
  const newBlock = buildWAFBlock(waf)

  if (content.includes(WAF_MARKER_START) && content.includes(WAF_MARKER_END)) {
    const startIdx = content.indexOf(WAF_MARKER_START)
    const endIdx   = content.indexOf(WAF_MARKER_END)
    const before = content.slice(0, startIdx)
    const after  = content.slice(endIdx + WAF_MARKER_END.length)
    content = before + newBlock + after
  } else {
    const insertAt = lastSiteBlockClose(content)
    if (insertAt === -1) {
      throw new Error(
        'This Caddyfile has no site block for CatWAF to protect. ' +
        'Add a site block (for example `:8081 { reverse_proxy 127.0.0.1:3000 }`) pointing at the application you want to protect, then apply again.'
      )
    }
    content = content.slice(0, insertAt) + '\n' + newBlock + '\n' + content.slice(insertAt)
  }

  content = ensureGlobalOrderDirective(content)
  try {
    fs.writeFileSync(CADDYFILE_PATH, content, 'utf8')
  } catch (e) {
    if (e.code === 'EACCES' || e.code === 'EPERM') {
      throw new Error(
        `Cannot write the Caddyfile at ${CADDYFILE_PATH} (permission denied). ` +
        `CatWAF found this file ${CADDYFILE_SOURCE === 'CADDYFILE_PATH' ? 'via CADDYFILE_PATH' : 'by auto-detection'}, ` +
        `but is not running as a user that can modify it. Either run CatWAF as a user with write access ` +
        `to it, or point CADDYFILE_PATH at a Caddyfile you can write and have Caddy load that one.`
      )
    }
    throw e
  }
}


function applyToCaddy(label, req) {
  let caddyResult = { reloaded: false, error: 'skipped' }
  try {
    patchWAFCaddyfile(state.WAF)
    caddyResult = reloadCaddy()
    auditSvc.audit(req, label, '', { reloaded: caddyResult.reloaded, engine: state.WAF.engine, pl: state.WAF.paranoia_level })
  } catch (e) {
    caddyResult = { reloaded: false, error: e.message }
    auditSvc.audit(req, label + '.error', e.message)
  }
  return caddyResult
}

function readCaddyfile() {
  try { return fs.readFileSync(CADDYFILE_PATH, 'utf8') }
  catch (e) { throw new Error(`Cannot read Caddyfile at ${CADDYFILE_PATH}: ${e.message}`) }
}

function firstLine(msg) {
  return String(msg || '').split('\n').find(l => l.trim()) || String(msg || '').trim()
}

function reloadCaddy() {
  const attempts = []

  try {
    execFileSync('caddy', ['reload', '--config', CADDYFILE_PATH], { timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'] })
    return { reloaded: true, error: null, method: 'caddy-binary' }
  } catch (e) {
    attempts.push(`local caddy binary: ${firstLine(e.stderr?.toString() || e.message)}`)
  }

  try {
    adminApiRequest('POST', '/load', readCaddyfile(), 'text/caddyfile')
    return { reloaded: true, error: null, method: 'admin-api' }
  } catch (e) {
    attempts.push(`admin api ${CADDY_ADMIN_URL}: ${firstLine(e.stderr?.toString() || e.stdout?.toString() || e.message)}`)
  }

  return { reloaded: false, error: attempts.join(' | '), method: null }
}

function isCaddyRunning() {
  try { adminApiRequest('GET', '/config/', '', 'application/json', 3000); return true } catch {}
  try { execFileSync('pgrep', ['-x', 'caddy'], { timeout: 3000 }); return true } catch {}
  return false
}

function getCaddyModules() {
  try { return execFileSync('caddy', ['list-modules'], { timeout: 5000 }).toString() } catch {}
  return ''
}

function getCaddyPid() {
  try {
    const out = execFileSync('pgrep', ['-x', 'caddy'], { timeout: 3000 }).toString().trim()
    const pid = parseInt(out.split('\n')[0], 10)
    if (Number.isFinite(pid)) return pid
  } catch {}
  return null
}

let reloadQueueTimer = null
let reloadQueuePending = false
function queueCaddyReload() {
  reloadQueuePending = true
  if (reloadQueueTimer) return
  reloadQueueTimer = setTimeout(() => {
    reloadQueueTimer = null
    if (!reloadQueuePending) return
    reloadQueuePending = false
    const result = reloadCaddy()
    if (!result.reloaded) console.error('[CatWAF] Queued reload failed:', result.error)
  }, 800)
}

module.exports = {
  CADDYFILE_PATH, CADDYFILE_SOURCE, CORAZA_LIST_DIR, CADDY_ADMIN_URL, AUDIT_LOG_PATH,
  detectCaddyfilePath, candidatePaths, scoreCaddyfilePath: scorePath,
  lastSiteBlockClose, globalOptionsRange,
  buildWAFBlock, patchWAFCaddyfile, readCaddyfile, reloadCaddy,
  isCaddyRunning, getCaddyModules, getCaddyPid,
  applyToCaddy, queueCaddyReload,
  isReloadPending: () => reloadQueuePending,
}
