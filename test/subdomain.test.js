
const os = require('os')
const fs = require('fs')
const path = require('path')

const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'catwaf-subdomain-'))
process.env.JWT_SECRET = 'q'.repeat(64)
process.env.DB_DIR = DATA_DIR

const ROOT = path.join(__dirname, '..')

let pass = 0, fail = 0
const failures = []
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok   ' + name) }
  else { fail++; failures.push(name); console.log('  FAIL ' + name, extra === undefined ? '' : JSON.stringify(extra).slice(0, 200)) }
}

const { domainIsValid, domainInfoFor, localDomainInfo } = require(path.join(ROOT, 'src/tui/setup.js'))

console.log('\n== domain validation ==')
for (const good of ['example.com', 'my-site.co.uk', 'a.b.c.example.io', 'xn--80ak6aa92e.com', 'test123.dev']) {
  check(`accepts ${good}`, domainIsValid(good) === true)
}
for (const bad of [
  '', 'localhost', 'example', '-bad.com', 'bad-.com', 'exa mple.com',
  'example.com {', 'example.com {\n}\nrespond "pwned"', 'ex`ample.com',
  'example.com}', 'exa\nmple.com', 'http://example.com', 'example.com/path',
  'exam"ple.com', '../../etc/passwd', 'a'.repeat(64) + '.com',
]) {
  check(`rejects ${JSON.stringify(bad).slice(0, 40)}`, domainIsValid(bad) === false)
}

console.log('\n== subdomain derivation ==')
const info = domainInfoFor('example.com')
check('dashboard host is catwaf.<domain>', info.dashboardHost === 'catwaf.example.com', info)
check('api host is api.catwaf.<domain>', info.apiHost === 'api.catwaf.example.com', info)
check('dashboard URL is https', info.dashboardUrl === 'https://catwaf.example.com', info)
check('api URL is https', info.apiUrl === 'https://api.catwaf.example.com', info)
check('dashboard and API are different hosts', info.dashboardHost !== info.apiHost)

// Locally the backend serves the dashboard and the API on one origin — the
// port it actually listens on. localhost:8081 is the Vite dev server and is
// not something a local install binds.
const local = localDomainInfo()
const localPort = process.env.PORT || 8000
check('local mode uses the API port', local.dashboardUrl === `http://localhost:${localPort}`, local)
check('local mode serves dashboard and API on one origin', local.dashboardUrl === local.apiUrl, local)
check('local mode marks itself local', local.local === true)
check('local mode API is on a different port', local.apiUrl === 'http://localhost:8000', local)

console.log('\n== the generated Caddyfile is well formed ==')
// Mirrors the domain branch of setup.js's writeCaddyfile. There is no local
// branch here on purpose: without a domain, setup.js writes no control-panel
// site block at all (the backend serves the dashboard and API on PORT
// itself), so there is nothing for this helper to mirror.
function siteBlocks(i, distPath = '/opt/catwaf/frontend/dist', port = 8000) {
  return `${i.dashboardHost} {\n    handle {\n        root * ${distPath}\n        try_files {path} /index.html\n        file_server\n    }\n}\n` +
    `${i.apiHost} {\n    reverse_proxy 127.0.0.1:${port}\n}\n`
}
const generated = siteBlocks(info)
check('contains the dashboard site block', generated.includes('catwaf.example.com {'))
check('contains the API site block', generated.includes('api.catwaf.example.com {'))
check('API block reverse-proxies to the local API port', /api\.catwaf\.example\.com \{\s*reverse_proxy 127\.0\.0\.1:8000/.test(generated))
check('braces are balanced', (generated.match(/\{/g) || []).length === (generated.match(/\}/g) || []).length)
check('no stray directive could have been injected', !/respond|SecRuleEngine|import |exec/.test(generated))

console.log('\n== the API trusts the generated dashboard origin ==')
process.env.DOMAIN = 'example.com'
process.env.CORS_ORIGIN = 'https://catwaf.example.com'
delete require.cache[require.resolve(path.join(ROOT, 'backend/server.js'))]
const { app } = require(path.join(ROOT, 'backend/server.js'))

const server = app.listen(0, '127.0.0.1', async () => {
  const base = `http://127.0.0.1:${server.address().port}`
  const res = await fetch(base + '/healthz')
  const csp = res.headers.get('content-security-policy') || ''
  check('CSP connect-src includes the generated API subdomain',
    csp.includes('https://api.catwaf.example.com'), csp.slice(0, 200))
  check('CSP connect-src includes the dashboard origin',
    csp.includes('https://catwaf.example.com'), csp.slice(0, 200))

  const cors = await fetch(base + '/api/auth/status', { headers: { Origin: 'https://catwaf.example.com' } })
  check('the generated dashboard origin passes CORS',
    cors.headers.get('access-control-allow-origin') === 'https://catwaf.example.com',
    cors.headers.get('access-control-allow-origin'))

  const evil = await fetch(base + '/api/auth/status', { headers: { Origin: 'https://evil.example.com' } })
  check('an unrelated origin does not pass CORS',
    evil.headers.get('access-control-allow-origin') === null)

  console.log(`\n${pass} passed, ${fail} failed`)
  if (failures.length) console.log('failed: ' + failures.join(' | '))
  server.close()
  try { fs.rmSync(DATA_DIR, { recursive: true, force: true }) } catch {}
  process.exit(fail ? 1 : 0)
})
