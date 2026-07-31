
let geoip = null
let loadError = null
try {
  geoip = require('geoip-lite')
} catch (e) {
  loadError = e.message
}

const PRIVATE_V4 = [
  /^0\./,
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^198\.1[89]\./,
  /^22[4-9]\.|^2[3-5]\d\./,
]

const PRIVATE_V6 = [
  /^::1$/,
  /^::$/,
  /^f[cd]/i,
  /^fe[89ab]/i,
  /^ff/i,
]

function normalize(ip) {
  if (typeof ip !== 'string') return null
  const trimmed = ip.trim()
  if (!trimmed) return null
  const bare = trimmed.replace(/^\[|\]$/g, '').split('%')[0]
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(bare)
  return mapped ? mapped[1] : bare
}

function isPrivateIp(ip) {
  const addr = normalize(ip)
  if (!addr) return true
  if (addr.includes(':')) return PRIVATE_V6.some(re => re.test(addr))
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(addr)) return true
  if (addr.split('.').some(o => Number(o) > 255)) return true
  return PRIVATE_V4.some(re => re.test(addr))
}

function lookup(ip) {
  if (!geoip) return null
  const addr = normalize(ip)
  if (!addr || isPrivateIp(addr)) return null

  let geo
  try {
    geo = geoip.lookup(addr)
  } catch {
    return null
  }
  if (!geo || !Array.isArray(geo.ll) || geo.ll.length !== 2) return null
  const [lat, lon] = geo.ll
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null
  if (lat < -90 || lat > 90 || lon < -180 || lon > 180) return null

  return {
    country_code: geo.country || null,
    city: geo.city || null,
    lat,
    lon,
  }
}

function available() {
  return { ok: !!geoip, error: loadError }
}

module.exports = { lookup, isPrivateIp, available }
