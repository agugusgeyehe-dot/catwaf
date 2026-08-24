
const express = require('express')
const fs = require('fs')
const router = express.Router()
const rateLimit = require('express-rate-limit')
const auditSvc = require('../services/audit')
const caddySvc = require('../services/caddy')
const netGuard = require('../services/netGuard')
const { writeRequired } = require('../middleware/auth')

// The origin probe makes a real outbound TCP connection to a caller-chosen
// public host:port. Admin-only is not enough — throttle it so the endpoint
// cannot be looped into a third-party port-scan.
const scannerLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: req => req.user?.username || req.ip || 'unknown',
  message: { detail: 'Too many scans in a short period — wait a minute.' },
})

// Cloudflare's published ranges change rarely; caching them avoids an
// outbound fetch per scan and keeps a scan honest when the fetch fails.
let cfRangesCache = { text: null, at: 0 }
async function cloudflareRanges() {
  if (cfRangesCache.text !== null && Date.now() - cfRangesCache.at < 10 * 60 * 1000) return cfRangesCache.text
  const text = await fetch('https://www.cloudflare.com/ips-v4', { signal: AbortSignal.timeout(8000) })
    .then(r => r.text()).catch(() => null)
  if (text !== null) cfRangesCache = { text, at: Date.now() }
  return cfRangesCache.text
}

router.post('/api/scanner/origin-exposure', writeRequired, scannerLimiter, async (req, res) => {
  const { domain, origin_ip, origin_port, authorized } = req.body || {}

  if (origin_ip && authorized !== true) {
    return res.status(400).json({
      detail: 'Scanning an IP requires explicit authorization. Set authorized: true to confirm you own or are authorized to test this host.',
    })
  }

  const checks = []

  if (domain) {
    try {
      const dns = require('dns').promises
      const addrs = await dns.resolve4(domain).catch(() => [])
      const v4text = await cloudflareRanges()
      const cfRanges = String(v4text || '').trim().split('\n').filter(Boolean)
      const behindCf = cfRanges.length > 0 && addrs.length > 0 && addrs.every(ip => cfRanges.some(r => inRange(ip, r)))
      checks.push({ name: 'Domain resolves through Cloudflare', pass: behindCf, detail: addrs.join(', ') || 'no A records found' })
    } catch (e) {
      checks.push({ name: 'Domain resolves through Cloudflare', pass: false, detail: e.message })
    }
  }

  if (origin_ip) {
    const why = netGuard.reasonNotPublic(String(origin_ip))
    if (why) {
      return res.status(400).json({
        detail: `Refusing to scan ${origin_ip}: ${why}. This check is for a publicly routable origin address.`,
      })
    }
    const port = Number(origin_port ?? 8082)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return res.status(400).json({ detail: 'origin_port must be a whole number between 1 and 65535.' })
    }
    try {
      const net = require('net')
      const reachable = await new Promise((resolve) => {
        const sock = net.createConnection({ host: origin_ip, port, timeout: 3000 })
        sock.on('connect', () => { sock.destroy(); resolve(true) })
        sock.on('error', () => resolve(false))
        sock.on('timeout', () => { sock.destroy(); resolve(false) })
      })
      checks.push({
        name: `Origin IP ${origin_ip}:${port} directly reachable`,
        pass: !reachable,
        detail: reachable ? 'REACHABLE — origin is exposed, direct bypass possible' : 'not reachable — good, origin is locked down',
      })
    } catch (e) {
      checks.push({ name: 'Origin IP direct reachability', pass: null, detail: e.message })
    }
  }

  try {
    const content = fs.readFileSync(caddySvc.CADDYFILE_PATH, 'utf8')
    checks.push({ name: 'Origin firewall rule active in Caddyfile', pass: content.includes('@@CATWAF_CF_LOCK_START@@'), detail: content.includes('@@CATWAF_CF_LOCK_START@@') ? 'present' : 'missing — run the Cloudflare Wizard "Lock Origin" step' })
  } catch (e) {
    checks.push({ name: 'Origin firewall rule active in Caddyfile', pass: false, detail: e.message })
  }

  const exposed = checks.some(c => c.pass === false)
  auditSvc.audit(req, 'scanner.origin-exposure', domain||origin_ip||'', { exposed, authorized: authorized === true })
  res.json({ exposed, checks, scanned_at: auditSvc.now() })
})

// Hoisted so the Cloudflare check above can reach it.
function inRange(ip, cidr) {
  const [range, bits] = cidr.split('/')
  const mask = ~((1 << (32 - +bits)) - 1)
  const toInt = a => a.split('.').reduce((acc,o)=>(acc<<8)+ +o, 0)
  return (toInt(ip) & mask) === (toInt(range) & mask)
}

module.exports = router
