const { TYPICAL_HEADER_NAMES, MISSING_BROWSER_HEADERS } = require('./common')

module.exports = {
  name: 'sqlmap',
  userAgentExact: [/sqlmap/i],
  userAgentCanonical: [
    "sqlmap/1.7.2#stable (http://sqlmap.org)",
    "sqlmap",
  ],
  headerProfile: {
    typicalHeaderNames: TYPICAL_HEADER_NAMES,
    missingBrowserHeaders: MISSING_BROWSER_HEADERS,
  },
}
