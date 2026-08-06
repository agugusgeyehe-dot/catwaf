const { TYPICAL_HEADER_NAMES, MISSING_BROWSER_HEADERS } = require('./common')

module.exports = {
  name: 'dirbuster',
  userAgentExact: [/dirbuster/i],
  userAgentCanonical: [
    "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)",
  ],
  headerProfile: {
    typicalHeaderNames: TYPICAL_HEADER_NAMES,
    missingBrowserHeaders: MISSING_BROWSER_HEADERS,
  },
}
