
const net = require('net')
const dns = require('dns').promises

const V4_BLOCKED = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
]

function v4ToInt(ip) {
  return ip.split('.').reduce((acc, o) => ((acc << 8) + Number(o)) >>> 0, 0) >>> 0
}

function v4InBlock(ip, network, bits) {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  return (v4ToInt(ip) & mask) === (v4ToInt(network) & mask)
}

function v6Groups(ip) {
  let addr = ip.split('%')[0]
  const [head, tail] = addr.includes('::') ? addr.split('::') : [addr, null]
  const headParts = head ? head.split(':').filter(Boolean) : []
  const tailParts = tail ? tail.split(':').filter(Boolean) : []
  const fill = 8 - headParts.length - tailParts.length
  if (fill < 0) return null
  const parts = [...headParts, ...Array(tail === null ? 0 : fill).fill('0'), ...tailParts]
  if (parts.length !== 8) return null
  return parts.map(p => parseInt(p, 16) & 0xffff)
}

function v6InBlock(groups, prefixHex, bits) {
  const target = v6Groups(prefixHex)
  if (!target) return false
  let remaining = bits
  for (let i = 0; i < 8 && remaining > 0; i++) {
    const take = Math.min(16, remaining)
    const mask = take === 0 ? 0 : (0xffff << (16 - take)) & 0xffff
    if ((groups[i] & mask) !== (target[i] & mask)) return false
    remaining -= take
  }
  return true
}

const V6_BLOCKED = [
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96],
  ['100::', 64],
  ['2001:db8::', 32],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
]

function reasonNotPublic(ip) {
  const family = net.isIP(ip)
  if (family === 0) return 'not a valid IP address'

  if (family === 4) {
    for (const [network, bits] of V4_BLOCKED) {
      if (v4InBlock(ip, network, bits)) return `${ip} is in the reserved range ${network}/${bits}`
    }
    return null
  }

  const embedded = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(ip)
  if (embedded && net.isIP(embedded[1]) === 4) {
    const why = reasonNotPublic(embedded[1])
    if (why) return why
  }

  const groups = v6Groups(embedded ? ip.replace(/(\d{1,3}(?:\.\d{1,3}){3})$/, '0:0') : ip)
  if (!groups) return `${ip} could not be parsed`
  for (const [prefix, bits] of V6_BLOCKED) {
    if (v6InBlock(groups, prefix, bits)) return `${ip} is in the reserved range ${prefix}/${bits}`
  }
  return null
}

function isPubliclyRoutable(ip) {
  return reasonNotPublic(ip) === null
}

async function resolvePublicAddresses(hostname) {
  if (typeof hostname !== 'string' || hostname.length === 0 || hostname.length > 253) {
    throw Object.assign(new Error('Invalid hostname.'), { status: 400 })
  }
  if (net.isIP(hostname) !== 0) {
    const why = reasonNotPublic(hostname)
    if (why) throw Object.assign(new Error(`Refusing to connect: ${why}.`), { status: 400 })
    return [hostname]
  }

  let addrs
  try {
    addrs = await dns.lookup(hostname, { all: true, verbatim: true })
  } catch {
    throw Object.assign(new Error(`Could not resolve ${hostname}.`), { status: 400 })
  }
  if (!addrs.length) throw Object.assign(new Error(`Could not resolve ${hostname}.`), { status: 400 })

  for (const { address } of addrs) {
    const why = reasonNotPublic(address)
    if (why) throw Object.assign(new Error(`Refusing to connect: ${hostname} resolves to ${address}, which is not publicly routable.`), { status: 400 })
  }
  return addrs.map(a => a.address)
}

const MAX_REDIRECTS = 3
const ALLOWED_PROTOCOLS = new Set(['https:', 'http:'])

async function guardedFetch(rawUrl, { timeoutMs = 8000, method = 'GET', headers = {}, body = null } = {}) {
  let url
  try { url = new URL(rawUrl) } catch { throw Object.assign(new Error('Invalid URL.'), { status: 400 }) }

  // Redirects can change the method out from under us, so both travel
  // through the hop loop together rather than being captured once.
  let sendMethod = method
  let sendBody = body
  let sendHeaders = headers

  const visited = []
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
      throw Object.assign(new Error(`Refusing to follow a ${url.protocol} URL.`), { status: 400 })
    }
    await resolvePublicAddresses(url.hostname)
    visited.push(url.toString())

    const res = await fetch(url.toString(), {
      method: sendMethod,
      headers: sendHeaders,
      ...(sendBody == null ? {} : { body: sendBody }),
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    })

    const location = res.headers.get('location')
    if (![301, 302, 303, 307, 308].includes(res.status) || !location) {
      return { response: res, chain: visited }
    }
    try { url = new URL(location, url) } catch {
      throw Object.assign(new Error('Redirect target is not a valid URL.'), { status: 400 })
    }

    // 307/308 preserve the method and body; 301/302/303 degrade to a bodyless
    // GET, which is what browsers do and what keeps a secret-bearing POST body
    // from being replayed to a redirect target.
    if (res.status !== 307 && res.status !== 308) {
      sendMethod = 'GET'
      if (sendBody != null) {
        sendBody = null
        sendHeaders = Object.fromEntries(
          Object.entries(sendHeaders).filter(([k]) => k.toLowerCase() !== 'content-type'),
        )
      }
    }
  }
  throw Object.assign(new Error(`Too many redirects (more than ${MAX_REDIRECTS}).`), { status: 400 })
}

module.exports = {
  isPubliclyRoutable,
  reasonNotPublic,
  resolvePublicAddresses,
  guardedFetch,
  MAX_REDIRECTS,
}
