
const CF_BASE = 'https://api.cloudflare.com/client/v4'
const CF_STORE = { token: null, zone_id: null, record_id: null }

async function cfFetch(path, token, opts = {}) {
  const res = await fetch(`${CF_BASE}${path}`, {
    ...opts,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    },
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok || data.success === false) {
    const msg = data?.errors?.[0]?.message || `Cloudflare API error (${res.status})`
    const err = new Error(msg)
    err.status = res.status
    err.cfErrors = data?.errors
    throw err
  }
  return data
}

module.exports = { CF_BASE, CF_STORE, cfFetch }
