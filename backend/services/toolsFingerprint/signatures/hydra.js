const { TYPICAL_HEADER_NAMES, MISSING_BROWSER_HEADERS } = require('./common')

module.exports = {
  name: 'hydra',
  userAgentExact: [/hydra/i],
  userAgentCanonical: [
    "Mozilla/4.0 (Hydra)",
  ],
  headerProfile: {
    typicalHeaderNames: TYPICAL_HEADER_NAMES,
    missingBrowserHeaders: MISSING_BROWSER_HEADERS,
  },
}
