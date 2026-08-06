// toolsFingerprint — scores an incoming request against a library of known
// offensive scanner-tool signatures (backend/services/toolsFingerprint/signatures/).
//
// Two tiers, deliberately treated differently by the caller:
//   'exact' — the User-Agent literally matches a known tool's signature regex.
//             High confidence, safe to ban on sight.
//   'close' — no exact match, but the User-Agent is textually similar to a
//             known tool's canonical UA and/or the header shape looks like a
//             scripted client rather than a browser. Lower confidence — the
//             caller should challenge, not ban, to avoid punishing an
//             unusually-configured but legitimate visitor.

const fs = require('fs')
const path = require('path')

const SIGNATURES_DIR = path.join(__dirname, 'signatures')

const SIGNATURES = fs.readdirSync(SIGNATURES_DIR)
  .filter(f => f.endsWith('.js') && f !== 'common.js')
  .map(f => require(path.join(SIGNATURES_DIR, f)))

const DEFAULT_CLOSE_THRESHOLD = 0.55

function bigrams(str) {
  const s = String(str).toLowerCase()
  const grams = []
  for (let i = 0; i < s.length - 1; i++) grams.push(s.slice(i, i + 2))
  return grams
}

// Dice coefficient over character bigrams — a cheap, dependency-free way to
// score two strings as "textually similar" (handles version bumps, minor
// obfuscation) without pulling in a Levenshtein library.
function diceCoefficient(a, b) {
  if (!a || !b) return 0
  if (a === b) return 1
  const bgA = bigrams(a)
  const bgB = bigrams(b)
  if (!bgA.length || !bgB.length) return 0
  const counts = new Map()
  for (const g of bgA) counts.set(g, (counts.get(g) || 0) + 1)
  let matches = 0
  for (const g of bgB) {
    const c = counts.get(g) || 0
    if (c > 0) { matches++; counts.set(g, c - 1) }
  }
  return (2 * matches) / (bgA.length + bgB.length)
}

function uaScore(userAgent, sig) {
  if (!userAgent) return 0
  if (sig.userAgentExact.some(rx => rx.test(userAgent))) return 1
  let best = 0
  for (const canon of sig.userAgentCanonical) {
    best = Math.max(best, diceCoefficient(userAgent, canon))
  }
  return best
}

function isExactUAMatch(userAgent, sig) {
  return !!userAgent && sig.userAgentExact.some(rx => rx.test(userAgent))
}

function headerScore(headerNames, sig) {
  if (!headerNames || !headerNames.length) return 0
  const observed = new Set(headerNames.map(h => String(h).toLowerCase()))
  const { typicalHeaderNames, missingBrowserHeaders } = sig.headerProfile

  let inter = 0
  const union = new Set([...typicalHeaderNames, ...observed])
  for (const h of typicalHeaderNames) if (observed.has(h)) inter++
  const jaccard = union.size ? inter / union.size : 0

  let missingCount = 0
  for (const h of missingBrowserHeaders) if (!observed.has(h)) missingCount++
  const missingRatio = missingBrowserHeaders.length ? missingCount / missingBrowserHeaders.length : 0

  return 0.5 * jaccard + 0.5 * missingRatio
}

function score(request, sig) {
  return 0.7 * uaScore(request.userAgent, sig) + 0.3 * headerScore(request.headers, sig)
}

// Returns the best match as { tool, score, tier } or null if nothing crosses
// the close threshold. An exact User-Agent match always wins and is reported
// as tier 'exact' regardless of header shape.
function fingerprint({ userAgent, headers } = {}, { closeThreshold = DEFAULT_CLOSE_THRESHOLD } = {}) {
  const request = { userAgent, headers }

  const exactHit = SIGNATURES.find(sig => isExactUAMatch(userAgent, sig))
  if (exactHit) {
    return { tool: exactHit.name, score: 1, tier: 'exact' }
  }

  let best = null
  for (const sig of SIGNATURES) {
    const s = score(request, sig)
    if (!best || s > best.score) best = { tool: sig.name, score: s }
  }
  if (!best || best.score < closeThreshold) return null
  return { ...best, tier: 'close' }
}

module.exports = { fingerprint, uaScore, headerScore, score, CLOSE_THRESHOLD: DEFAULT_CLOSE_THRESHOLD, SIGNATURES }
