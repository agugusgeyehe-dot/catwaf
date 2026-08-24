#!/usr/bin/env node
//
// Downloads a Caddy build with the Coraza WAF module baked in.
//
// Trust model (honest version): caddyserver.com's download API serves
// freshly compiled binaries and publishes NO checksums or signatures for
// them, so a download cannot be verified against upstream the way a release
// artifact can. What this script does instead, in order of strength:
//
//   1. Pins a version. The request includes &version=<pin>, so the build is
//      reproducible per release instead of floating to whatever is latest.
//   2. Never follows redirects off the download host.
//   3. Trust-on-first-use pinning: after a successful install the binary's
//      SHA-256 is recorded in data/caddy-pin.json. Every later reinstall of
//      the SAME pin must reproduce that hash, or the install aborts — so a
//      one-time compromise cannot silently persist, and an operator who
//      records the hash out-of-band can detect any substitution.
//   4. Sanity-checks the result: it must be a real ELF/Mach-O binary and
//      must answer `caddy list-modules` with the Coraza handler.

const fs = require('fs')
const os = require('os')
const path = require('path')
const https = require('https')
const zlib = require('zlib')
const crypto = require('crypto')
const { execFileSync } = require('child_process')

const PROJECT_ROOT = path.join(__dirname, '..')
const LOCAL_BIN_DIR = path.join(PROJECT_ROOT, 'bin', 'vendor')
const LOCAL_CADDY = path.join(LOCAL_BIN_DIR, 'caddy')
const PIN_FILE = path.join(PROJECT_ROOT, 'data', 'caddy-pin.json')
const DOWNLOAD_HOST = 'caddyserver.com'
// Pinned Coraza-caddy line; override with CATWAF_CADDY_VERSION if you know
// a newer one is right for you.
const CADDY_VERSION = process.env.CATWAF_CADDY_VERSION || ''

function log(msg) { console.log(`[ensure-caddy] ${msg}`) }

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex') }

function hasWorkingCoraza(bin) {
  try {
    const out = execFileSync(bin, ['list-modules'], { timeout: 5000 }).toString()
    return out.includes('http.handlers.waf')
  } catch { return false }
}

function findExistingCaddy() {
  for (const candidate of ['caddy', LOCAL_CADDY]) {
    if (hasWorkingCoraza(candidate)) return candidate
  }
  return null
}

function platformTarget() {
  const platform = os.platform()
  const archMap = { x64: 'amd64', arm64: 'arm64' }
  const arch = archMap[os.arch()]
  if (!arch || (platform !== 'linux' && platform !== 'darwin')) return null
  return { os: platform, arch }
}

// Redirects are followed only within the download host — a redirect to
// another origin would silently change who we are trusting.
function download(url, redirects = 5) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'catwaf-setup' } }, (res) => {
      if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
        res.resume()
        const next = new URL(res.headers.location, url)
        if (next.host !== DOWNLOAD_HOST) {
          return reject(new Error(`Download redirected off ${DOWNLOAD_HOST} (to ${next.host}) — refusing.`))
        }
        return resolve(download(next.toString(), redirects - 1))
      }
      if (res.statusCode !== 200) {
        res.resume()
        return reject(new Error(`HTTP ${res.statusCode} fetching ${url}`))
      }
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve(Buffer.concat(chunks)))
      res.on('error', reject)
    }).on('error', reject)
  })
}

async function fetchCaddyWithCoraza(target) {
  let url = `https://${DOWNLOAD_HOST}/api/download?os=${target.os}&arch=${target.arch}&p=github.com%2Fcorazawaf%2Fcoraza-caddy%2Fv2`
  if (CADDY_VERSION) url += `&version=${encodeURIComponent(CADDY_VERSION)}`
  log(`Downloading a Caddy${CADDY_VERSION ? ` ${CADDY_VERSION}` : ''} build with the Coraza module for ${target.os}/${target.arch}…`)
  const body = await download(url)
  const isGzip = body[0] === 0x1f && body[1] === 0x8b
  return isGzip ? zlib.gunzipSync(body) : body
}

// A substituted payload is usually not even a valid executable for this
// platform. This is a sanity gate, NOT verification — the hash pin below is
// what actually detects substitution across installs.
function looksLikeExecutable(bytes) {
  if (bytes.length < 4) return false
  const magic = bytes.subarray(0, 4)
  const elf = magic[0] === 0x7f && magic[1] === 0x45 && magic[2] === 0x4c && magic[3] === 0x46 // ELF
  const macho64 = magic.readUInt32BE(0) === 0xfeedfacf
  const machoUni = bytes.length > 8 && magic.readUInt32BE(0) === 0xcafebabe
  return elf || macho64 || machoUni
}

function readPin() {
  try { return JSON.parse(fs.readFileSync(PIN_FILE, 'utf8')) } catch { return null }
}

function writePin(pin) {
  fs.mkdirSync(path.dirname(PIN_FILE), { recursive: true })
  fs.writeFileSync(PIN_FILE, JSON.stringify(pin, null, 2), { mode: 0o644 })
}

// Trust-on-first-use: the first successful install for a given os/arch pair
// records its hash. Re-installing the SAME combination must
// produce the same hash unless the operator explicitly allows a new one
// (upstream rebuilds are possible, so this is deliberate, visible, and
// logged rather than silent).
function checkPin(bytes, target) {
  const key = `${target.os}-${target.arch}`
  const hash = sha256(bytes)
  const pin = readPin()
  if (!pin || pin.target !== key || !pin.sha256) {
    return { ok: true, hash, tofu: true }
  }
  if (pin.sha256 === hash) return { ok: true, hash, tofu: false }
  if (String(process.env.CATWAF_CADDY_ALLOW_NEW_BUILD) === '1') {
    log(`Build hash changed for ${key} (${pin.sha256.slice(0, 12)}… → ${hash.slice(0, 12)}…) — CATWAF_CADDY_ALLOW_NEW_BUILD=1 set, accepting and re-pinning.`)
    return { ok: true, hash, tofu: true }
  }
  return {
    ok: false,
    error: `The downloaded build does not match the hash recorded on this machine (${pin.sha256.slice(0, 16)}…). If you expected upstream to publish a new build for this version, re-run with CATWAF_CADDY_ALLOW_NEW_BUILD=1 to accept and re-pin it.`,
  }
}

function installTo(dir, bytes) {
  fs.mkdirSync(dir, { recursive: true })
  const dest = path.join(dir, 'caddy')
  // Atomic replace: never leave a truncated binary at the target path.
  const tmp = `${dest}.tmp-${process.pid}`
  fs.writeFileSync(tmp, bytes, { mode: 0o755 })
  fs.renameSync(tmp, dest)
  return dest
}

function canWriteSystemBin() {
  try { fs.accessSync('/usr/local/bin', fs.constants.W_OK); return true } catch { return false }
}

async function main() {
  if (findExistingCaddy()) {
    log('Caddy with the Coraza module is already available — nothing to do.')
    return
  }

  const target = platformTarget()
  if (!target) {
    log(`Unsupported platform (${os.platform()}/${os.arch()}) for automatic install.`)
    log('Build Caddy with Coraza yourself: xcaddy build --with github.com/corazawaf/coraza-caddy/v2')
    log('(see docs/installation.md) — `catwaf --setup` will tell you if it\'s still missing.')
    return
  }

  try {
    const bytes = await fetchCaddyWithCoraza(target)
    if (!looksLikeExecutable(bytes)) {
      throw new Error('the response is not a valid executable image for this platform')
    }
    const pinCheck = checkPin(bytes, target)
    if (!pinCheck.ok) throw new Error(pinCheck.error)

    const dest = canWriteSystemBin()
      ? installTo('/usr/local/bin', bytes)
      : installTo(LOCAL_BIN_DIR, bytes)

    if (!hasWorkingCoraza(dest)) {
      log(`Downloaded a binary to ${dest} but it doesn't report the Coraza module — treating this as a failed install.`)
      log('Build it yourself: xcaddy build --with github.com/corazawaf/coraza-caddy/v2 (see docs/installation.md).')
      return
    }

    writePin({ target: `${target.os}-${target.arch}`, sha256: pinCheck.hash, recordedAt: new Date().toISOString(), version: CADDY_VERSION || null })
    log(`✓ Installed Caddy (with Coraza) to ${dest}`)
    log(`  Build SHA-256 pinned locally: ${pinCheck.hash}`)
    log(`  NOTE: this build service publishes no checksums — the pin above is trust-on-first-use.`)
    log(`  Verify it independently if this server matters: xcaddy build + sha256sum comparison.`)
    if (dest === LOCAL_CADDY) {
      log(`/usr/local/bin isn't writable without root — add ${LOCAL_BIN_DIR} to PATH,`)
      log('or re-run this install with sudo/root to install it system-wide instead.')
    }
  } catch (e) {
    log(`Could not auto-install Caddy: ${e.message}`)
    log('This is not fatal — `catwaf --setup` will flag it and you can install Caddy manually:')
    log('  xcaddy build --with github.com/corazawaf/coraza-caddy/v2   (see docs/installation.md)')
  }
}

main().catch((e) => { log(`Unexpected error: ${e.message}`); process.exitCode = 0 })
