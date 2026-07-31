
const SCANNER_SIGNATURES = [
  { name: 'sqlmap',            rx: /sqlmap/i },
  { name: 'nikto',             rx: /nikto/i },
  { name: 'nmap',              rx: /nmap|nse/i },
  { name: 'masscan',           rx: /masscan/i },
  { name: 'zgrab',             rx: /zgrab/i },
  { name: 'dirbuster',         rx: /dirbuster/i },
  { name: 'gobuster',          rx: /gobuster/i },
  { name: 'dirsearch',         rx: /dirsearch/i },
  { name: 'ffuf',              rx: /ffuf/i },
  { name: 'wfuzz',             rx: /wfuzz/i },
  { name: 'hydra',             rx: /hydra/i },
  { name: 'burpsuite',         rx: /burp/i },
  { name: 'nuclei',            rx: /nuclei/i },
  { name: 'curl',              rx: /^curl\//i },
  { name: 'python-requests',   rx: /python-requests/i },
  { name: 'go-http-client',    rx: /go-http-client/i },
  { name: 'wget',              rx: /^wget\//i },
  { name: 'acunetix',          rx: /acunetix/i },
  { name: 'nessus',            rx: /nessus/i },
  { name: 'openvas',           rx: /openvas/i },
  { name: 'metasploit',        rx: /metasploit/i },
  { name: 'postman',           rx: /postman/i },
]

function fingerprintUA(ua) {
  if (!ua) return { is_scanner: false, tool: null, category: null }
  const hit = SCANNER_SIGNATURES.find(s => s.rx.test(ua))
  if (!hit) return { is_scanner: false, tool: null, category: null }
  const offensiveTools = ['sqlmap','nikto','nmap','masscan','zgrab','dirbuster','gobuster','dirsearch','ffuf','wfuzz','hydra','burpsuite','nuclei','acunetix','nessus','openvas','metasploit']
  const httpClients = ['curl','python-requests','go-http-client','wget','postman']
  return {
    is_scanner: true, tool: hit.name,
    category: offensiveTools.includes(hit.name) ? 'offensive' : httpClients.includes(hit.name) ? 'http-client' : 'other',
  }
}


module.exports = { SCANNER_SIGNATURES, fingerprintUA }
