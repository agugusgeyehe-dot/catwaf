// intel/probe.js — reverse client-port probing (idea #5).
//
// The mirror image of the origin-exposure problem CatWAF already documents:
// instead of asking "can an attacker reach my origin directly?", this asks
// "is the thing connecting to me actually a forwarding node hiding the real
// attacker?" An open 3128/1080/9050 on a *client* address is a strong signal
// of an open proxy or relay, which IP and ASN blocklists alone miss.
//
// Shipped disabled, and it stays that way unless the operator reads what
// they are turning on. Connecting back to a visitor's address is not free:
// it costs latency on the request path, and it can generate abuse reports
// against your own server. TRADEOFFS below is surfaced verbatim in the UI so
// that is a decision, not a surprise.

const net = require('net')

const cache = require('./cache')
const settings = require('../settings')
const netGuard = require('../netGuard')
const { normalizeClientIp } = require('../sanitize')

const NS = 'client-probe'

const TRADEOFFS = [
  'CatWAF opens a TCP connection back to the visitor\'s address. Some networks and hosting providers treat that as port scanning and will file an abuse report against your server.',
  'The first request from an unseen address waits for the probe. With the default 400 ms timeout and five ports probed in parallel, that is up to ~400 ms added to that one request; later requests are answered from cache.',
  'A positive result is a strong hint, not proof — carrier-grade NAT and some corporate gateways legitimately have these ports open.',
]

function probePort(ip, port, timeoutMs) {
  return new Promise(resolve => {
    const socket = new net.Socket()
    let settled = false
    const done = open => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(open)
    }
    socket.setTimeout(timeoutMs)
    socket.once('connect', () => done(true))
    socket.once('timeout', () => done(false))
    socket.once('error', () => done(false))
    try { socket.connect(port, ip) } catch { done(false) }
  })
}

async function probe(ip, opts = {}) {
  const cfg = { ...settings.get('client_probe'), ...opts }
  const addr = normalizeClientIp(String(ip || '').trim())
  if (!addr) return { open: [], skipped: 'no address' }

  // Never probe anything that is not a public address: a private range means
  // probing our own infrastructure, which is both useless and dangerous.
  if (!netGuard.isPubliclyRoutable(addr)) return { open: [], skipped: 'not a public address' }

  const ports = cfg.ports.map(p => Number(p)).filter(p => Number.isInteger(p) && p > 0 && p < 65536).slice(0, 20)
  if (!ports.length) return { open: [], skipped: 'no ports configured' }

  return cache.through(NS, addr, cfg.cache_minutes * 60 * 1000, async () => {
    const results = await Promise.all(ports.map(async port => ({ port, open: await probePort(addr, port, cfg.timeout_ms) })))
    const open = results.filter(r => r.open).map(r => r.port)
    return { open, probed: ports.length, at: new Date().toISOString() }
  })
}

// `suspicious` is passed in by the enforcement pipeline: with
// `only_suspicious` on (the default), an address that nothing else has
// flagged is never probed, which keeps the latency cost off ordinary
// visitors entirely.
async function evaluate(ip, { suspicious = false } = {}) {
  const cfg = settings.get('client_probe')
  if (!cfg.enabled) return null
  if (cfg.only_suspicious && !suspicious) return null

  let result
  try { result = await probe(ip) } catch { return null }
  if (!result.open || !result.open.length) return null

  return {
    decision: cfg.action === 'ban' ? 'ban' : cfg.action === 'challenge' ? 'challenge' : 'flag',
    source: 'client_probe',
    banSeconds: 3600,
    reason: `Relay ports open on the client address (${result.open.join(', ')}) — this connection is very likely a proxy hiding the real origin.`,
    open_ports: result.open,
  }
}

module.exports = { probe, probePort, evaluate, TRADEOFFS, NS }
