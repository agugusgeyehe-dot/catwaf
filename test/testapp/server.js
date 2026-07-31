#!/usr/bin/env node

const http = require('http')

const PORT = Number(process.env.TEST_APP_PORT || 8080)
const HOST = process.env.TEST_APP_HOST || '127.0.0.1'

const BANNER = [
  '==========================================',
  '   CATWAF SECURITY TEST ENVIRONMENT',
  '',
  '        INTENTIONALLY VULNERABLE',
  '          LOCAL TESTING ONLY',
  '==========================================',
].join('\n')

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

const PAGE = (reqPath, query) => `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>CatWAF Test App — INTENTIONALLY VULNERABLE</title></head>
<body style="font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;line-height:1.6">
<pre style="background:#300;color:#fbb;padding:1rem;border-radius:8px">CATWAF SECURITY TEST ENVIRONMENT

INTENTIONALLY VULNERABLE
LOCAL TESTING ONLY</pre>

<p>If you can read this, the request <strong>reached the application</strong> —
meaning the WAF <em>allowed</em> it.</p>

<p>A request that Coraza blocks never gets here; Caddy returns 403 before this
app is ever reached.</p>

<h2>Request as received</h2>
<table border="1" cellpadding="6" style="border-collapse:collapse">
<tr><td>Path</td><td><code>${esc(reqPath)}</code></td></tr>
<tr><td>Query</td><td><code>${esc(query || '(none)')}</code></td></tr>
</table>

<h2>Try these</h2>
<ul>
  <li><a href="/">/</a> — normal request, should be allowed</li>
  <li><a href="/?id=1+UNION+SELECT+1,2,3--">SQL injection pattern</a> — should be blocked</li>
  <li><a href="/?q=%3Cscript%3Ealert(1)%3C/script%3E">XSS pattern</a> — should be blocked</li>
</ul>

<p style="color:#900"><strong>This app deliberately performs no input
validation and no escaping of the values it echoes back below. It exists only
to prove the WAF in front of it is doing the filtering. Never expose it.</strong></p>

<h2>Unescaped echo (the actual vulnerability)</h2>
<div>${query || ''}</div>
</body></html>`

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost')

  if (url.pathname === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ ok: true, app: 'catwaf-test-app', vulnerable: true }))
  }

  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(PAGE(url.pathname, url.search.replace(/^\?/, '')))
})

server.listen(PORT, HOST, () => {
  console.log(BANNER)
  console.log(`\nListening on http://${HOST}:${PORT}`)
  if (HOST !== '0.0.0.0') {
    console.log('Bound to loopback only. Set TEST_APP_HOST=0.0.0.0 to expose it')
    console.log('inside a container network (docker-compose does this).')
  } else {
    console.log('WARNING: bound to 0.0.0.0 — only do this inside an isolated')
    console.log('container network with no published ports.')
  }
})
