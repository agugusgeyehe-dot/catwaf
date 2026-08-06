// challenge/providers.js — pluggable third-party challenge backends
// (idea #3).
//
// Some site owners want a managed provider: a vendor watching bot networks
// across millions of sites has signal a self-hosted captcha cannot. Each
// adapter implements the same two things — how to render the widget, and
// `verify(token) -> bool` — so adding another provider later is one entry in
// this table, not a change to the challenge flow.
//
// Verification always goes through netGuard.guardedFetch, the same SSRF-safe
// client every other outbound call uses, because the verify URL for the
// self-hosted options (mCaptcha) is operator-supplied.

const netGuard = require('../netGuard')

const PROVIDERS = {
  recaptcha: {
    label: 'Google reCAPTCHA v2',
    script: 'https://www.google.com/recaptcha/api.js',
    widget: siteKey => `<div class="g-recaptcha" data-sitekey="${siteKey}"></div>`,
    responseField: 'g-recaptcha-response',
    verifyUrl: () => 'https://www.google.com/recaptcha/api/siteverify',
  },
  hcaptcha: {
    label: 'hCaptcha',
    script: 'https://js.hcaptcha.com/1/api.js',
    widget: siteKey => `<div class="h-captcha" data-sitekey="${siteKey}"></div>`,
    responseField: 'h-captcha-response',
    verifyUrl: () => 'https://api.hcaptcha.com/siteverify',
  },
  turnstile: {
    label: 'Cloudflare Turnstile',
    script: 'https://challenges.cloudflare.com/turnstile/v0/api.js',
    widget: siteKey => `<div class="cf-turnstile" data-sitekey="${siteKey}"></div>`,
    responseField: 'cf-turnstile-response',
    verifyUrl: () => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
  },
  mcaptcha: {
    label: 'mCaptcha (self-hosted)',
    script: null,
    widget: siteKey => `<div class="m-captcha" data-sitekey="${siteKey}"></div>`,
    responseField: 'mcaptcha__token',
    // Self-hosted, so the operator supplies the instance URL.
    verifyUrl: cfg => cfg.provider_verify_url,
  },
}

function get(name) {
  return PROVIDERS[name] || null
}

function list() {
  return Object.entries(PROVIDERS).map(([id, p]) => ({
    id,
    label: p.label,
    self_hosted: id === 'mcaptcha',
    needs_verify_url: id === 'mcaptcha',
    response_field: p.responseField,
  }))
}

// Content-Security-Policy needs to allow the provider's script and frame for
// the challenge page specifically. Returned here so the page builder and any
// header policy stay in agreement about which origins are involved.
function cspSources(name) {
  const origins = {
    recaptcha: ['https://www.google.com', 'https://www.gstatic.com'],
    hcaptcha: ['https://js.hcaptcha.com', 'https://newassets.hcaptcha.com'],
    turnstile: ['https://challenges.cloudflare.com'],
    mcaptcha: [],
  }
  return origins[name] || []
}

async function verify(name, token, cfg, remoteIp) {
  const provider = get(name)
  if (!provider) return { ok: false, error: `Unknown challenge provider "${name}"` }
  if (!cfg.secret_key) return { ok: false, error: 'No provider secret key is configured.' }
  if (typeof token !== 'string' || !token || token.length > 4096) return { ok: false, error: 'Missing or malformed challenge response.' }

  const url = provider.verifyUrl(cfg)
  if (!url) return { ok: false, error: 'No verification URL is configured for this provider.' }

  const body = new URLSearchParams({ secret: cfg.secret_key, response: token })
  if (remoteIp) body.set('remoteip', remoteIp)

  try {
    const { response } = await netGuard.guardedFetch(url, {
      method: 'POST',
      timeoutMs: 8000,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    const data = await response.json().catch(() => null)
    if (!data) return { ok: false, error: 'The provider returned an unreadable response.' }
    if (data.success === true) return { ok: true, score: typeof data.score === 'number' ? data.score : null }
    return { ok: false, error: `Verification rejected${Array.isArray(data['error-codes']) ? `: ${data['error-codes'].join(', ')}` : ''}` }
  } catch (e) {
    return { ok: false, error: `Could not reach the challenge provider: ${e.message}` }
  }
}

module.exports = { PROVIDERS, get, list, verify, cspSources }
