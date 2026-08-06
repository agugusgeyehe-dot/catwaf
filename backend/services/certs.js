// certs.js — certificate inspection and validation for the TLS settings
// (ideas #20-#23).
//
// The self-signed fallback (#20) does not generate anything: Caddy's
// `tls internal` issues from its own local CA, which is strictly better than
// a hand-rolled OpenSSL certificate — it is renewed automatically and it can
// be trusted locally. So "self-signed" here means selecting that issuer, and
// this module's job is the part that genuinely needs doing: checking an
// uploaded certificate before it is accepted (#21), and reporting what is
// actually being served and when it expires.
//
// Validating before applying matters more here than almost anywhere else: a
// mismatched cert/key pair does not fail at validation time in an obvious
// way, it fails when a visitor tries to connect.

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const db = require('./db')
const settings = require('./settings')

function assetPath(...parts) {
  return path.join(path.dirname(db.DB_PATH), 'caddy', ...parts)
}

function inspect(certPem) {
  if (!certPem || typeof certPem !== 'string') return { ok: false, error: 'No certificate supplied.' }
  let cert
  try {
    cert = new crypto.X509Certificate(certPem)
  } catch (e) {
    return { ok: false, error: `That does not parse as a certificate: ${e.message}` }
  }

  const validTo = new Date(cert.validTo)
  const validFrom = new Date(cert.validFrom)
  const daysRemaining = Math.floor((validTo.getTime() - Date.now()) / 86_400_000)

  return {
    ok: true,
    subject: cert.subject,
    issuer: cert.issuer,
    // A certificate whose issuer is its own subject is self-signed; worth
    // saying out loud, because uploading one by accident is a common way to
    // end up with browser warnings nobody can explain.
    self_signed: cert.subject === cert.issuer,
    serial: cert.serialNumber,
    valid_from: validFrom.toISOString(),
    valid_to: validTo.toISOString(),
    days_remaining: daysRemaining,
    expired: daysRemaining < 0,
    expiring_soon: daysRemaining >= 0 && daysRemaining <= 30,
    hosts: (cert.subjectAltName || '')
      .split(',')
      .map(s => s.trim().replace(/^DNS:/, ''))
      .filter(s => s && !s.includes(':')),
    key_type: cert.publicKey?.asymmetricKeyType || null,
    key_size: cert.publicKey?.asymmetricKeyDetails?.modulusLength || cert.publicKey?.asymmetricKeyDetails?.namedCurve || null,
    fingerprint: cert.fingerprint256,
  }
}

function validatePair(certPem, keyPem) {
  const details = inspect(certPem)
  if (!details.ok) return details

  let key
  try {
    key = crypto.createPrivateKey(keyPem)
  } catch (e) {
    return { ok: false, error: `That does not parse as a private key: ${e.message}` }
  }

  // The authoritative check: sign with the private key and verify with the
  // certificate's public key. Comparing moduli only works for RSA, and
  // comparing exported DER misses encoding differences.
  try {
    const cert = new crypto.X509Certificate(certPem)
    if (!cert.checkPrivateKey(key)) {
      return { ok: false, error: 'The private key does not match this certificate. Check that both files come from the same issuance.' }
    }
  } catch (e) {
    return { ok: false, error: `The certificate and key could not be checked against each other: ${e.message}` }
  }

  const warnings = []
  if (details.expired) warnings.push(`This certificate expired on ${details.valid_to.slice(0, 10)}.`)
  else if (details.expiring_soon) warnings.push(`This certificate expires in ${details.days_remaining} day(s).`)
  if (details.self_signed) warnings.push('This certificate is self-signed, so browsers will warn visitors unless they have been told to trust it.')

  return { ok: true, ...details, warnings }
}

function validateChain(caPem) {
  if (!caPem) return { ok: false, error: 'No CA bundle supplied.' }
  const blocks = String(caPem).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || []
  if (!blocks.length) return { ok: false, error: 'No PEM certificate blocks found in that bundle.' }
  const certs = []
  for (const [i, block] of blocks.entries()) {
    const details = inspect(block)
    if (!details.ok) return { ok: false, error: `Certificate #${i + 1} in the bundle is unreadable: ${details.error}` }
    certs.push(details)
  }
  return { ok: true, count: certs.length, certificates: certs }
}

// What Caddy is actually being told to do, and what CatWAF can see of the
// certificates on disk. Deliberately reports both the configured intent and
// the observed reality, because those two disagreeing is the whole reason
// domain-https-setup troubleshooting exists.
function status() {
  const cfg = settings.get('tls')
  const out = {
    cert_source: cfg.cert_source,
    profile: cfg.profile,
    acme_provider: cfg.acme_provider,
    acme_challenge: cfg.acme_challenge,
    self_signed_fallback: cfg.self_signed_fallback,
    wildcard: cfg.wildcard,
    custom: null,
    acme_storage: null,
  }

  if (cfg.cert_source === 'custom' && cfg.custom_cert_pem) {
    out.custom = inspect(cfg.custom_cert_pem)
    const written = assetPath('certs', 'site-cert.pem')
    out.custom.written_to = fs.existsSync(written) ? written : null
  }

  // Caddy stores issued certificates under its data directory; reporting
  // what is there answers "did issuance actually succeed?" without needing
  // to read Caddy's logs.
  const caddyData = process.env.XDG_DATA_HOME
    ? path.join(process.env.XDG_DATA_HOME, 'caddy')
    : path.join(process.env.HOME || '/root', '.local', 'share', 'caddy')
  const acmeDir = path.join(caddyData, 'certificates')
  if (fs.existsSync(acmeDir)) {
    const found = []
    const walk = (dir, depth = 0) => {
      if (depth > 3) return
      let entries = []
      try { entries = fs.readdirSync(dir, { withFileTypes: true }) } catch { return }
      for (const entry of entries) {
        const full = path.join(dir, entry.name)
        if (entry.isDirectory()) { walk(full, depth + 1); continue }
        if (!entry.name.endsWith('.crt')) continue
        try {
          const details = inspect(fs.readFileSync(full, 'utf8'))
          if (details.ok) found.push({ file: entry.name, hosts: details.hosts, valid_to: details.valid_to, days_remaining: details.days_remaining, issuer: details.issuer })
        } catch { /* unreadable certificate — skip it */ }
      }
    }
    walk(acmeDir)
    out.acme_storage = { path: acmeDir, certificates: found }
  }

  return out
}

// Practical guidance the dashboard shows next to the DNS-01 selector, since
// the failure it prevents (choosing dns-01 without the provider module) is
// the most common way this configuration goes wrong.
function acmeAdvice() {
  const cfg = settings.get('tls')
  const caddyModules = require('./caddyModules')
  const advice = []

  if (cfg.acme_challenge === 'dns-01') {
    const check = caddyModules.checkDnsProvider(cfg.dns_provider)
    if (!check.ok) advice.push({ level: 'error', message: check.hint })
    if (!cfg.dns_api_token) advice.push({ level: 'error', message: 'DNS-01 needs an API token for the DNS provider.' })
  }
  if (cfg.wildcard && cfg.acme_challenge !== 'dns-01') {
    advice.push({ level: 'error', message: 'A wildcard certificate can only be issued through the DNS-01 challenge.' })
  }
  if (cfg.acme_provider === 'custom' && !cfg.acme_ca_url) {
    advice.push({ level: 'error', message: 'A custom ACME provider needs its directory URL.' })
  }
  if (!cfg.acme_email && cfg.cert_source === 'acme') {
    advice.push({ level: 'warn', message: 'Without an ACME account email you will not be warned by the CA before a certificate expires.' })
  }
  if (cfg.acme_fallback) {
    advice.push({ level: 'info', message: 'If the primary provider fails or rate-limits, Caddy will try the other one before giving up.' })
  }
  return advice
}

module.exports = { inspect, validatePair, validateChain, status, acmeAdvice }
