
const state = require('./state')
const scanner = require('./scanner')

const TRACE_RULES = [
  { id:'920100', cat:'920', phase:1, name:'Invalid HTTP Request Line', var:'REQUEST_LINE',
    transform:['none'], test:(r)=> !/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) \S+ HTTP\/\d\.\d$/.test(`${r.method} ${r.uri} HTTP/1.1`), score:5, msg:'Malformed request line' },
  { id:'942100', cat:'942', phase:2, name:'SQL Injection (libinjection)', var:'ARGS|REQUEST_BODY',
    transform:['lowercase','urlDecode'], rx:/('|--|;|\bunion\b|\bselect\b.+\bfrom\b|\bor\b\s+\d=\d|\bsleep\(|\bbenchmark\()/i, score:5, msg:'SQL injection pattern detected via libinjection-style match' },
  { id:'942190', cat:'942', phase:2, name:'Detects MSSQL code execution', var:'ARGS',
    transform:['lowercase'], rx:/(xp_cmdshell|sp_executesql)/i, score:5, msg:'MSSQL command execution attempt' },
  { id:'941100', cat:'941', phase:2, name:'XSS (libinjection)', var:'ARGS|REQUEST_BODY',
    transform:['lowercase','htmlDecode'], rx:/(<script|onerror\s*=|onload\s*=|javascript:|<svg.*onload)/i, score:5, msg:'XSS pattern detected via libinjection-style match' },
  { id:'930100', cat:'930', phase:2, name:'Path Traversal Attack', var:'REQUEST_URI|ARGS',
    transform:['urlDecode'], rx:/(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/)/i, score:5, msg:'Path traversal sequence detected' },
  { id:'932100', cat:'932', phase:2, name:'Unix Command Injection', var:'ARGS|REQUEST_BODY',
    transform:['lowercase'], rx:/(;|\|\||&&|\$\()\s*(cat|ls|wget|curl|nc|bash|sh|whoami|id)\b/i, score:5, msg:'OS command injection sequence detected' },
  { id:'933100', cat:'933', phase:2, name:'PHP Injection — Opening Tag', var:'ARGS|REQUEST_BODY',
    transform:['lowercase'], rx:/(<\?php|<\?=)/i, score:4, msg:'PHP opening tag found in user input' },
  { id:'933160', cat:'933', phase:2, name:'PHP Injection — High-Risk Function', var:'ARGS|REQUEST_BODY',
    transform:['lowercase'], rx:/(eval\(|base64_decode\(|assert\(|system\(|exec\(|passthru\()/i, score:5, msg:'Dangerous PHP function call pattern' },
  { id:'913100', cat:'913', phase:1, name:'Found Scanner UA', var:'REQUEST_HEADERS:User-Agent',
    transform:['lowercase'], custom:(r) => scanner.fingerprintUA(r.headers?.['user-agent']).is_scanner, score:5, msg:'Known security scanner User-Agent' },
  { id:'920420', cat:'920', phase:2, name:'Request content type not allowed', var:'REQUEST_HEADERS:Content-Type',
    transform:['lowercase'], custom:(r) => r.method==='POST' && r.headers?.['content-type'] && !/(urlencoded|multipart|json|xml)/i.test(r.headers['content-type']), score:3, msg:'Unusual Content-Type for POST request' },
]

function runTrace({ method='GET', uri='/', headers={}, body='' }) {
  const phases = { 1: [], 2: [] }
  const matched = []
  let totalScore = 0

  for (const rule of TRACE_RULES) {
    if (!state.RULE_CATEGORIES[rule.cat] || !state.RULE_CATEGORIES[rule.cat].enabled) continue

    const haystack = `${uri}\n${JSON.stringify(headers)}\n${body}`
    let hit = false
    let matchedValue = null

    if (rule.custom) {
      hit = rule.custom({ method, uri, headers, body })
      matchedValue = hit ? (headers?.['user-agent'] || headers?.['content-type'] || '(custom check)') : null
    } else if (rule.rx) {
      const m = haystack.match(rule.rx)
      hit = !!m
      matchedValue = m ? m[0] : null
    }

    const phaseEntry = {
      id: rule.id, name: rule.name, var: rule.var, transform: rule.transform,
      matched: hit, matched_value: matchedValue, score: hit ? rule.score : 0, msg: rule.msg,
    }
    phases[rule.phase].push(phaseEntry)

    if (hit) {
      matched.push({ id: rule.id, msg: rule.msg, score: rule.score, cat: rule.cat })
      totalScore += rule.score
    }
  }

  const threshold = state.WAF.inbound_anomaly_threshold
  const blocked = totalScore >= threshold
  const verdict = state.WAF.engine === 'Off' ? 'PASS (engine off)'
    : blocked ? (state.WAF.engine === 'DetectionOnly' ? 'WOULD BLOCK' : 'BLOCK')
    : 'PASS'

  return {
    request: { method, uri, headers, body },
    normalization: {
      decoded_uri: decodeURIComponent(uri || ''),
      lowercase_body: (body || '').toLowerCase(),
    },
    phases,
    matched_rules: matched,
    total_score: totalScore,
    threshold,
    blocked,
    verdict,
    engine_mode: state.WAF.engine,
    scanner: scanner.fingerprintUA(headers?.['user-agent']),
  }
}

const RULE_DOCS = {
  '942100': { purpose:'Detects classic SQL injection syntax (quotes, UNION SELECT, OR 1=1, time-based blind SQLi).', examples:["' OR 1=1--","' UNION SELECT 1,2,3--","'; WAITFOR DELAY '0:0:5'--"], false_positives:'Search fields containing apostrophes (e.g. names like O\'Brien) can trigger this.', cve_refs:['CVE-2021-3514 (related WAF bypass research)'] },
  '941100': { purpose:'Detects Cross-Site Scripting payloads including script tags, event handler injection, and javascript: URIs.', examples:['<script>alert(1)</script>','<img src=x onerror=alert(1)>','javascript:alert(1)'], false_positives:'Rich text editor content (CKEditor/TinyMCE) submitted as raw HTML.', cve_refs:[] },
  '930100': { purpose:'Detects directory/path traversal sequences attempting to access files outside the webroot.', examples:['../../etc/passwd','..%2f..%2fetc%2fpasswd'], false_positives:'File paths with literal ".." in filenames (rare).', cve_refs:[] },
  '932100': { purpose:'Detects Unix shell command injection via command separators and common binaries.', examples:['; cat /etc/passwd','| whoami','&& curl evil.com'], false_positives:'Form fields that legitimately contain shell-like syntax (rare, mostly dev tools).', cve_refs:[] },
  '933100': { purpose:'Detects PHP opening tags injected into user input — a precursor to PHP code injection.', examples:['<?php system($_GET[1]); ?>'], false_positives:'None common — PHP tags in user input are almost always malicious.', cve_refs:[] },
  '913100': { purpose:'Identifies known security scanner User-Agent strings (sqlmap, nikto, nmap, etc).', examples:['User-Agent: sqlmap/1.7.2'], false_positives:'Internal security testing tools using these UAs against your own staging server.', cve_refs:[] },
}

module.exports = { TRACE_RULES, runTrace, RULE_DOCS }
