
const express = require('express')
const router = express.Router()
const state = require('../services/state')
const auditSvc = require('../services/audit')
const caddySvc = require('../services/caddy')
const { writeRequired } = require('../middleware/auth')
const { isValidIpOrCidr, isValidCountryCode, ipCoveredBy, normalizeClientIp } = require('../services/sanitize')

function pruneExpired() {
  const t = Date.now()
  for (const k of ['ip_whitelist','ip_blacklist'])
    state.WAF[k] = state.WAF[k].filter(e => !e.expires_at || new Date(e.expires_at).getTime() > t)
}
router.get('/api/ip/whitelist', (req, res) => { pruneExpired(); res.json(state.WAF.ip_whitelist) })
router.get('/api/ip/blacklist', (req, res) => { pruneExpired(); res.json(state.WAF.ip_blacklist) })
router.post('/api/ip/add', writeRequired, (req, res) => {
  const { ip, list, note, ttl_minutes } = req.body || {}
  if (!isValidIpOrCidr(ip)) return res.status(400).json({ detail: 'ip must be a valid IPv4/IPv6 address or CIDR range' })
  if (list === 'blacklist' && ipCoveredBy(req.ip, ip)) {
    return res.status(400).json({
      detail: `"${ip}" covers your own address (${normalizeClientIp(req.ip)}) — blocking it would lock you out of CatWAF. Narrow the range, or add it from a different network.`,
      code: 'SELF_BLOCK',
    })
  }
  if (note !== undefined && (typeof note !== 'string' || note.length > 256)) return res.status(400).json({ detail: 'note must be a string (max 256 chars)' })
  const entry = { ip, note: note || '', added_at: auditSvc.now(), expires_at: ttl_minutes ? new Date(Date.now()+ttl_minutes*60000).toISOString() : null }
  if (list === 'whitelist') state.WAF.ip_whitelist.push(entry)
  else if (list === 'blacklist') state.WAF.ip_blacklist.push(entry)
  else return res.status(400).json({ detail: 'list must be whitelist/blacklist' })
  state.saveWAF(true)
  const caddy = caddySvc.applyToCaddy('ip.add', req)
  res.json({ message: 'Added', entry, caddy_reloaded: caddy.reloaded })
})
router.delete('/api/ip/:list/:ip', writeRequired, (req, res) => {
  const k = `ip_${req.params.list}`
  if (!state.WAF[k]) return res.status(400).json({ detail: 'Invalid list' })
  const before = state.WAF[k].length
  state.WAF[k] = state.WAF[k].filter(e => e.ip !== req.params.ip)
  if (state.WAF[k].length === before) return res.status(404).json({ detail: 'Not found' })
  state.saveWAF(true)
  const caddy = caddySvc.applyToCaddy('ip.remove', req)
  res.json({ message: 'Removed', caddy_reloaded: caddy.reloaded })
})

router.get('/api/geo', (req, res) => res.json({ blocked_countries: state.WAF.geo_blocking }))
router.post('/api/geo/:cc', writeRequired, (req, res) => {
  const cc = req.params.cc.toUpperCase()
  if (!isValidCountryCode(cc)) return res.status(400).json({ detail: 'cc must be a 2-letter ISO country code' })
  const i = state.WAF.geo_blocking.indexOf(cc)
  if (i >= 0) state.WAF.geo_blocking.splice(i,1); else state.WAF.geo_blocking.push(cc)
  state.saveWAF(true)
  const caddy = caddySvc.applyToCaddy('geo.toggle', req)
  res.json({ blocked_countries: state.WAF.geo_blocking, caddy_reloaded: caddy.reloaded })
})

module.exports = router
