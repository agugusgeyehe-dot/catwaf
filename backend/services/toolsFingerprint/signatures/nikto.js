const { TYPICAL_HEADER_NAMES, MISSING_BROWSER_HEADERS } = require('./common')

module.exports = {
  name: 'nikto',
  userAgentExact: [/nikto/i],
  userAgentCanonical: [
    "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)",
  ],
  headerProfile: {
    typicalHeaderNames: TYPICAL_HEADER_NAMES,
    missingBrowserHeaders: MISSING_BROWSER_HEADERS,
  },
}
