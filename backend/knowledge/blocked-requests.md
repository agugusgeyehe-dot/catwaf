---
id: blocked-requests
title: Reading blocked requests and attack logs
keywords: [log, blocked, request, why, attack, rule, event, traffic, history, audit, anomaly, score, 403]
questions:
  - Why was this request blocked?
  - How do I see what was blocked?
  - What do the rule IDs mean?
  - What is an anomaly score?
related: [false-positives, dashboard, paranoia-levels]
actions: [ip.block, ip.allow]
---

Every blocked request is recorded with the client IP, the method and path, the rule that
matched, and an anomaly score.

## Rule IDs

OWASP rule IDs are grouped by attack class, and the first three digits tell you the
category:

| Prefix | Category |
|---|---|
| 930 | Local file inclusion / path traversal |
| 931 | Remote file inclusion |
| 932 | Remote command execution |
| 933 | PHP injection |
| 941 | Cross-site scripting (XSS) |
| 942 | SQL injection |
| 949 | Anomaly score threshold reached |

## Anomaly scoring

Most rules don't block on their own — they add to a running score for the request. When
the total crosses the threshold, rule 949 fires and the request is blocked. This is why a
blocked request often lists several rule IDs: no single one was conclusive, but together
they crossed the line.

A request blocked by 949 with several low-confidence matches is more likely to be a false
positive than one blocked by a single high-confidence SQL injection rule.

## Deciding what to do

- **Obvious attack** (`UNION SELECT`, `../../etc/passwd`, a scanner user-agent) — nothing
  to do. It worked.
- **Recognisable customer traffic** — that's a false positive; see *When legitimate
  visitors get blocked*.
- **Sustained attacks from one address** — block the IP so it stops consuming resources.
