const { TYPICAL_HEADER_NAMES, MISSING_BROWSER_HEADERS } = require('./common')

module.exports = {
  name: 'nmap',
  userAgentExact: [/nmap|nse/i],
  userAgentCanonical: [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
  ],
  headerProfile: {
    typicalHeaderNames: TYPICAL_HEADER_NAMES,
    missingBrowserHeaders: MISSING_BROWSER_HEADERS,
  },
}
