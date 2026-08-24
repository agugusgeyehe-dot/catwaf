
// Canonical dotted-quad form (no leading zeros) — the only spelling allowed
// to reach the geoip library.
const CANONICAL_V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

const fs = require('fs')
const path = require('path')

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
  // Only canonical addresses reach the geoip library. Non-canonical spellings
  // ("010.000.000.001", junk, hostnames) must never be parsed by the bundled
  // IP parser — its leading-zero handling has had CVEs, and a misparse here
  // could only ever misreport a country, but there is no reason to hand it
  // anything that is not already a clean address.
  if (!addr || isPrivateIp(addr)) return null
  if (addr.includes(':')) {
    if (!/^[\da-fA-F:]+$/.test(addr)) return null
  } else if (!CANONICAL_V4.test(addr)) return null

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
  return { ok: !!geoip, error: loadError, database_age_days: databaseAgeDays() }
}

// The bundled MaxMind database is static — it does not update itself, and
// country blocking degrades as the world renumbers. Surfacing its age makes
// that visible instead of silent.
function databaseAgeDays() {
  try {
    const dir = path.join(path.dirname(require.resolve('geoip-lite/package.json')), 'data')
    let latest = 0
    for (const f of fs.readdirSync(dir)) {
      const st = fs.statSync(path.join(dir, f))
      if (st.mtimeMs > latest) latest = st.mtimeMs
    }
    if (!latest) return null
    return Math.floor((Date.now() - latest) / 86_400_000)
  } catch { return null }
}

module.exports = { lookup, isPrivateIp, available }
