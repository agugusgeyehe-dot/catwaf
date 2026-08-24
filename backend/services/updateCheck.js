// updateCheck.js — "is there a newer CatWAF?" against the GitHub releases
// of this project. Read-only: CatWAF never auto-installs anything. The
// result is cached for a day so the dashboard and CLI can show it without
// hammering the API.
//
// Verification honesty: GitHub release assets are used as-is. Until the
// project publishes signed artifacts, the check tells you a new version
// EXISTS — the operator performs and verifies the upgrade themselves via
// the documented setup.sh path.

const pkg = require('../../package.json')
const settings = require('./settings')
const netGuard = require('./netGuard')

const REPO = 'agugusgeyehe-dot/catwaf'
const API_URL = `https://api.github.com/repos/${REPO}/releases/latest`
const RELEASES_URL = `https://github.com/${REPO}/releases`
const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000

const STATE_KEY = 'update_check_state'

function loadState() {
  const s = require('./db').getState(STATE_KEY)
  return s && typeof s === 'object' ? s : {}
}

// Prerelease tags (v1.3.0-rc1) are not stable releases and must never
// trigger an upgrade prompt.
function parseVersion(tag) {
  const raw = String(tag || '')
  if (!raw || /[-+]/.test(raw.replace(/^v/, ''))) return null
  const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(raw)
  if (!m) return null
  return { major: +m[1], minor: +m[2], patch: +m[3] }
}

function isNewer(candidate, current) {
  const c = parseVersion(candidate)
  const cur = parseVersion(current)
  if (!c || !cur) return false
  if (c.major !== cur.major) return c.major > cur.major
  if (c.minor !== cur.minor) return c.minor > cur.minor
  return c.patch > cur.patch
}

async function check({ force = false } = {}) {
  const current = pkg.version
  const state = loadState()

  if (!force && state.lastCheckedAt && Date.now() - state.lastCheckedAt < CHECK_INTERVAL_MS) {
    return {
      ...state,
      current,
      upToDate: !isNewer(state.latestVersion, current),
      cached: true,
    }
  }

  let latestVersion = null
  let notesUrl = RELEASES_URL
  let error = null
  let noReleases = false
  try {
    const { response } = await netGuard.guardedFetch(API_URL, {
      timeoutMs: 8000,
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'catwaf-update-check',
      },
    })
    // A 404 means the repository has no published releases yet (or is
    // private). That is a normal early-project state, not a failure.
    if (response.status === 404) {
      noReleases = true
    } else {
      if (!response.ok) throw new Error(`GitHub answered ${response.status}`)
      const data = await response.json()
      latestVersion = String(data.tag_name || '').replace(/^v/, '') || null
      if (data.html_url) notesUrl = data.html_url
    }
  } catch (e) {
    error = e.message
    // A failed check must not pin the previous state for another 24h:
    // keep the old latestVersion but leave lastCheckedAt untouched so the
    // next scheduler tick retries.
    const prev = loadState()
    if (!prev.latestVersion && !prev.noReleases) {
      return { ...prev, current, upToDate: true, cached: true, error }
    }
    return { ...prev, current, upToDate: !isNewer(prev.latestVersion, current), cached: true, error }
  }

  const next = {
    lastCheckedAt: Date.now(),
    latestVersion,
    current,
    notesUrl,
    noReleases,
    ...(error ? { error } : {}),
  }
  try { require('./db').setState(STATE_KEY, next) } catch {}

  return {
    ...next,
    upToDate: latestVersion ? !isNewer(latestVersion, current) : true,
    cached: false,
  }
}

function upgradeInstructions(result) {
  if (!result.latestVersion || result.upToDate) return []
  return [
    `A newer CatWAF is available: ${result.latestVersion} (running ${result.current}).`,
    `Notes: ${result.notesUrl}`,
    'Upgrade manually so you can read what changes:',
    `  curl -fsSLo setup.sh https://raw.githubusercontent.com/${REPO}/v${result.latestVersion}/setup.sh`,
    '  less setup.sh',
    '  sudo bash setup.sh   # re-runs safely over an existing install',
  ]
}

module.exports = { check, isNewer, parseVersion, upgradeInstructions, REPO, _internals: { STATE_KEY, loadState } }
