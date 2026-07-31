#!/usr/bin/env node

const fs = require('fs')
const os = require('os')
const path = require('path')
const https = require('https')
const zlib = require('zlib')
const { execFileSync } = require('child_process')

const PROJECT_ROOT = path.join(__dirname, '..')
const LOCAL_BIN_DIR = path.join(PROJECT_ROOT, 'bin', 'vendor')
const LOCAL_CADDY = path.join(LOCAL_BIN_DIR, 'caddy')

function log(msg) { console.log(`[ensure-caddy] ${msg}`) }

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

function download(url, redirects = 5) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'catwaf-setup' } }, (res) => {
      if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
        res.resume()
        return resolve(download(res.headers.location, redirects - 1))
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
  const url = `https://caddyserver.com/api/download?os=${target.os}&arch=${target.arch}&p=github.com%2Fcorazawaf%2Fcoraza-caddy%2Fv2`
  log(`Downloading a Caddy build with the Coraza module for ${target.os}/${target.arch}…`)
  const body = await download(url)
  const isGzip = body[0] === 0x1f && body[1] === 0x8b
  return isGzip ? zlib.gunzipSync(body) : body
}

function installTo(dir, bytes) {
  fs.mkdirSync(dir, { recursive: true })
  const dest = path.join(dir, 'caddy')
  fs.writeFileSync(dest, bytes, { mode: 0o755 })
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
    const dest = canWriteSystemBin()
      ? installTo('/usr/local/bin', bytes)
      : installTo(LOCAL_BIN_DIR, bytes)

    if (!hasWorkingCoraza(dest)) {
      log(`Downloaded a binary to ${dest} but it doesn't report the Coraza module — treating this as a failed install.`)
      log('Build it yourself: xcaddy build --with github.com/corazawaf/coraza-caddy/v2 (see docs/installation.md).')
      return
    }

    log(`✓ Installed Caddy (with Coraza) to ${dest}`)
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
