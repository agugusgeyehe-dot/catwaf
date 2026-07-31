---
id: terminology
title: WAF terms explained plainly
keywords: [what is, waf, crs, owasp, coraza, anomaly, rule, definition, glossary, mean, meaning, term, acronym]
questions:
  - What is a WAF?
  - What is OWASP CRS?
  - What is Coraza?
  - What does anomaly score mean?
  - What is a rule category?
related: [getting-started, paranoia-levels, blocked-requests]
actions: []
---

A quick glossary for terms this dashboard uses without explaining.

**WAF (Web Application Firewall)** — sits in front of your website and inspects each request for attack patterns before your app ever sees it. That's what CatWAF is.

**Coraza** — the actual inspection engine CatWAF is built on. It's a native Go WAF engine (not a wrapper around the older ModSecurity/libmodsecurity) that reads the same rule format.

**OWASP CRS (Core Rule Set)** — the actual library of attack-detection rules Coraza runs. Maintained by the OWASP Foundation, covers SQL injection, XSS, command injection, and more. CatWAF doesn't write its own rules — it configures how strictly the CRS runs.

**Paranoia level** — how strict the CRS is, 1 (lenient) to 4 (strict). See "Paranoia levels 1 to 4."

**Anomaly score** — most rules don't block on their own; they add points to a running total for the request. Once the total crosses a threshold, the request is blocked. See "Reading blocked requests and attack logs."

**Rule category / rule ID** — CRS rules are grouped by attack type, and the ID's first three digits tell you which (942 = SQL injection, 941 = XSS, and so on).

**False positive** — a real, legitimate visitor blocked by mistake because their request happened to match an attack pattern. See "When legitimate visitors get blocked."

**Detection Only** — a mode that logs what would have been blocked without actually blocking it. Useful for testing; not protection on its own.

**Caddy** — the web server CatWAF runs on top of. It's what actually receives every request, runs it through Coraza, and forwards clean traffic to your app.
