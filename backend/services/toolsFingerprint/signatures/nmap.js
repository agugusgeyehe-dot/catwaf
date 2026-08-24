const { TYPICAL_HEADER_NAMES, MISSING_BROWSER_HEADERS } = require('./common')

module.exports = {
  name: 'nmap',
  // "nse" must be word-bounded: unanchored, it matched the substring "nse"
  // inside innocent user agents ("Onset…", "U…nse…en"), and an exact-tier
  // hit here means an automatic site-wide ban of that visitor.
  userAgentExact: [/nmap|\bnse\b/i],
  userAgentCanonical: [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
  ],
  headerProfile: {
    typicalHeaderNames: TYPICAL_HEADER_NAMES,
    missingBrowserHeaders: MISSING_BROWSER_HEADERS,
  },
}
