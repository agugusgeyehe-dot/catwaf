const { TYPICAL_HEADER_NAMES, MISSING_BROWSER_HEADERS } = require('./common')

module.exports = {
  name: 'burpsuite',
  userAgentExact: [/burp/i],
  userAgentCanonical: [
    "Mozilla/5.0 (compatible; Burp Suite Professional)",
  ],
  headerProfile: {
    typicalHeaderNames: TYPICAL_HEADER_NAMES,
    missingBrowserHeaders: MISSING_BROWSER_HEADERS,
  },
}
