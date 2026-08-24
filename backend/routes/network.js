
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
  let expiresAt = null
  if (ttl_minutes !== undefined && ttl_minutes !== null) {
    const minutes = Number(ttl_minutes)
    // Without this check, "abc" coerced to NaN and produced an "Invalid
    // Date" stamp that pruneExpired() silently dropped on the next read —
    // the API reported success for an entry that never existed.
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > 525600) {
      return res.status(400).json({ detail: 'ttl_minutes must be a whole number of minutes between 1 and 525600 (one year), or omitted' })
    }
    expiresAt = new Date(Date.now() + minutes * 60000).toISOString()
  }
  const entry = { ip, note: note || '', added_at: auditSvc.now(), expires_at: expiresAt }
  if (list !== 'whitelist' && list !== 'blacklist') return res.status(400).json({ detail: 'list must be whitelist/blacklist' })
  const storeKey = `ip_${list}`
  const { sync } = state.updateWAF(w => { w[storeKey].push(entry) }, { label: 'ip.add', req, syncCaddy: true })
  res.json({ message: 'Added', entry, caddy_reloaded: sync.reloaded })
})
router.delete('/api/ip/:list/:ip', writeRequired, (req, res) => {
  const k = `ip_${req.params.list}`
  if (!state.WAF[k]) return res.status(400).json({ detail: 'Invalid list' })
  let removed = false
  const { sync } = state.updateWAF(w => {
    const before = w[k].length
    w[k] = w[k].filter(e => e.ip !== req.params.ip)
    removed = w[k].length !== before
  }, { label: 'ip.remove', req, syncCaddy: true })
  if (!removed) return res.status(404).json({ detail: 'Not found' })
  res.json({ message: 'Removed', caddy_reloaded: sync.reloaded })
})

router.get('/api/geo', (req, res) => res.json({ blocked_countries: state.WAF.geo_blocking }))
router.post('/api/geo/:cc', writeRequired, (req, res) => {
  const cc = req.params.cc.toUpperCase()
  if (!isValidCountryCode(cc)) return res.status(400).json({ detail: 'cc must be a 2-letter ISO country code' })
  const { sync } = state.updateWAF(w => {
    const i = w.geo_blocking.indexOf(cc)
    if (i >= 0) w.geo_blocking.splice(i, 1); else w.geo_blocking.push(cc)
  }, { label: 'geo.toggle', req, syncCaddy: true })
  res.json({ blocked_countries: state.WAF.geo_blocking, caddy_reloaded: sync.reloaded })
})

module.exports = router
