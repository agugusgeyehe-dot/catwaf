const { TYPICAL_HEADER_NAMES, MISSING_BROWSER_HEADERS } = require('./common')

module.exports = {
  name: 'nuclei',
  userAgentExact: [/nuclei/i],
  userAgentCanonical: [
    "Mozilla/5.0 (Nuclei - Open-source project (github.com/projectdiscovery/nuclei))",
  ],
  headerProfile: {
    typicalHeaderNames: TYPICAL_HEADER_NAMES,
    missingBrowserHeaders: MISSING_BROWSER_HEADERS,
  },
}
