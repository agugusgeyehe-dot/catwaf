const { TYPICAL_HEADER_NAMES, MISSING_BROWSER_HEADERS } = require('./common')

module.exports = {
  name: 'ffuf',
  userAgentExact: [/ffuf/i],
  userAgentCanonical: [
    "Fuzz Faster U Fool v2.1.0",
  ],
  headerProfile: {
    typicalHeaderNames: TYPICAL_HEADER_NAMES,
    missingBrowserHeaders: MISSING_BROWSER_HEADERS,
  },
}
