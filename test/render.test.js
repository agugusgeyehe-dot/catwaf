const os = require('os'), fs = require('fs'), path = require('path')
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-val-'))
process.env.DB_DIR = DIR
process.env.JWT_SECRET = 'a'.repeat(64)
process.env.CADDYFILE_PATH = path.join(DIR, 'Caddyfile')
process.env.CORAZA_AUDIT_LOG = path.join(DIR, 'logs', 'audit.json')
fs.mkdirSync(path.join(DIR,'logs'),{recursive:true}); fs.writeFileSync(process.env.CORAZA_AUDIT_LOG,'')
fs.writeFileSync(process.env.CADDYFILE_PATH, '{\n}\n\nexample.com {\n    reverse_proxy 127.0.0.1:3000\n}\n')
const ROOT = path.join(__dirname, '..')
const state = require(ROOT + '/backend/services/state')
const caddy = require(ROOT + '/backend/services/caddy')
const settings = require(ROOT + '/backend/services/settings')
const { execFileSync } = require('child_process')
let pass = 0, fail = 0

// Strip coraza (module not in this binary) so we validate OUR directives.
const orig = caddy.buildCorazaSnippet
function validate(label) {
  let content = caddy.renderCaddyfile(caddy.readCaddyfile(), state.WAF)
  content = content.replace(/^\s*order coraza_waf first\s*$/m, '')
    .replace(/ {2}coraza_waf[\s\S]*?\n  \}\n/m, '')
  const f = path.join(DIR, 'test.Caddyfile'); fs.writeFileSync(f, content)
  try { execFileSync('caddy', ['validate','--config',f,'--adapter','caddyfile'], {stdio:['ignore','pipe','pipe']}); pass++; console.log('  ok   ' + label) }
  catch(e){ fail++; console.log('  FAIL ' + label + '\n' + (e.stderr?.toString()||e.message).split('\n').filter(l=>/error|Error/.test(l)).slice(0,4).join('\n')) }
}
validate('baseline')

// A default install must not render a `forward_auth` hop back into CatWAF's
// own API. While that hop exists, Caddy reads a failed dial as a denial, so
// stopping the CatWAF API takes the protected website down with it — and a
// default install should never carry that dependency. This is the regression
// guard for the tools_fingerprint default; see the comment on that group in
// backend/services/settings/schema.js.
{
  const check = (name, cond, extra) => cond
    ? (pass++, console.log('  ok   ' + name))
    : (fail++, console.log('  FAIL ' + name, extra === undefined ? '' : JSON.stringify(extra).slice(0, 200)))

  const enforce = require(ROOT + '/backend/services/enforce')
  check('no runtime-enforcement feature is on by default', enforce.isActive() === false, enforce.activeFeatures())

  const baselineBlock = caddy.buildWAFBlock(state.WAF)
  check('a default install renders no forward_auth hop into the CatWAF API',
    !baselineBlock.includes('forward_auth'))
  check('a default install still refuses known scanner user-agents in Coraza',
    baselineBlock.includes('CatWAF Blocked Scanner UA'))
  check('a default install still loads the OWASP CRS',
    baselineBlock.includes('load_owasp_crs'))

  // …and the hop is still rendered when an operator opts in, so this is a
  // default change and not a silently removed feature.
  settings.set('tools_fingerprint', { enabled: true })
  check('enabling scanner fingerprinting renders the hop again',
    caddy.buildWAFBlock(state.WAF).includes('forward_auth'))
  settings.set('tools_fingerprint', { enabled: false })
  check('disabling it removes the hop again',
    !caddy.buildWAFBlock(state.WAF).includes('forward_auth'))
}
settings.set('access', { reject_unknown_host: true, known_hosts: ['example.com'], enforce_method_allowlist: true, allowed_methods: ['GET','POST'], waf_bypass_paths: ['/webhook/*'], blocked_status_code: 404, max_body_size_mb: 25, max_header_size_kb: 16 })
settings.set('headers', { preset: 'strict' })
settings.set('cookies', { enabled: true, exclude: ['legacy_id'] })
settings.set('compression', { enabled: true })
settings.set('client_cache', { enabled: true, no_store_paths: ['/api/*'] })
settings.set('redirects', { enabled: true, rules: [{ match_host: 'www.example.com', from: '/old', to: '/new', status: 301, enabled: true }] })
settings.set('robots', { enabled: true, disallow_paths: ['/admin'] })
settings.set('security_txt', { enabled: true, contact: ['mailto:sec@example.com'], expires: '2027-01-01' })
settings.set('real_ip', { enabled: true, preset: 'private' })
settings.set('proxy', { http3: true, upstream_tls_verify: true, protocol: 'https', retry_on: ['5xx'], max_retries: 3, fail_duration_sec: 30 })
settings.set('tls', { profile: 'modern', acme_email: 'a@example.com' })
settings.set('mtls', { mode: 'request' })
settings.set('cors', { enabled: true, allow_origins: ['https://app.example.com'], on_failure: 'deny' })
settings.set('error_pages', { enabled: true, pages: [{ status: 404, html: '<h1>nope</h1>' }], fallback_html: '<h1>err</h1>' })
settings.set('connections', { enabled: true, read_timeout_sec: 30, write_timeout_sec: 30 })
validate('full settings')
settings.set('real_ip', { proxy_protocol: true, proxy_protocol_allow: ['10.0.0.0/8'] })
settings.set('basic_auth', { enabled: true, username: 'ops', password_hash: '$2a$12$abcdefghijklmnopqrstuv', path: '/admin/*' })
settings.set('proxy', { auth_request_enabled: true, auth_request_url: '127.0.0.1:9091', auth_request_signin_url: 'https://auth.example.com/login' })
validate('proxy protocol + basic auth + forward auth')
settings.set('origin', { type: 'static-folder', root: '/var/www/html', browse: true })
settings.set('access', { unknown_host_action: 'status' })
validate('static origin')
settings.set('origin', { type: 'php-fpm', root: '/var/www/html', php_upstream: 'unix//run/php/php-fpm.sock' })
settings.set('tls', { cert_source: 'self-signed' })
validate('php-fpm origin + self-signed')
settings.set('raw_config', { enabled: true, global_http: 'debug', per_site: 'header X-Extra "1"', catch_all: 'header X-CatchAll "1"' })
validate('raw config injection')
console.log(`\n${pass} passed, ${fail} failed\n`)
fs.rmSync(DIR, { recursive: true, force: true })
process.exit(fail ? 1 : 0)
