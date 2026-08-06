const { TYPICAL_HEADER_NAMES, MISSING_BROWSER_HEADERS } = require('./common')

module.exports = {
  name: 'acunetix',
  userAgentExact: [/acunetix/i],
  userAgentCanonical: [
    "Mozilla/5.0 (compatible; Acunetix)",
  ],
  headerProfile: {
    typicalHeaderNames: TYPICAL_HEADER_NAMES,
    missingBrowserHeaders: MISSING_BROWSER_HEADERS,
  },
}
