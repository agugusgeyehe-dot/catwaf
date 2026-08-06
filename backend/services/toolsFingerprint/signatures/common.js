// Shared header-shape defaults for tool fingerprints. Real scanners are
// scripted HTTP clients — they send the handful of headers their library
// needs and essentially never send the browser-only headers below, so
// "missing" here doubles as signal rather than noise.

const TYPICAL_HEADER_NAMES = ['host', 'accept', 'accept-encoding', 'connection', 'content-length', 'user-agent']

const MISSING_BROWSER_HEADERS = [
  'accept-language', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest',
  'upgrade-insecure-requests', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
]

module.exports = { TYPICAL_HEADER_NAMES, MISSING_BROWSER_HEADERS }
