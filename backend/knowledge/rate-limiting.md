---
id: rate-limiting
title: Rate limiting and brute-force protection
keywords: [rate limit, throttle, dos, ddos, flood, brute force, too many requests, 429, spam, hammering, scraping]
questions:
  - How do I stop brute force attacks?
  - What is rate limiting?
  - Someone is hammering my site
  - How do I limit requests per IP?
related: [ip-blocklist, geo-blocking, security-score]
actions: [rate_limit.enable, ip.block]
---

Rate limiting caps how many requests a single IP can make in a given window. Past the
cap, further requests are refused until the window resets.

## What it stops

- **Brute-force login attempts** — the single most valuable use. Password guessing needs
  thousands of tries; rate limiting makes that take years instead of minutes.
- **Content scraping** at speed.
- **Crude floods** from a single source.

## What it doesn't stop

A **distributed** attack from thousands of addresses defeats per-IP limits by design —
each individual address stays under the cap. That needs upstream protection; connecting
Cloudflare is the practical answer for most sites.

## Choosing a limit

Set it well above what a real person browsing quickly would generate, but well below what
a script can. A few hundred requests per minute per IP is generous for a normal website
and still cuts brute-forcing dead.

Watch out for shared addresses: an office, school or mobile carrier can put hundreds of
legitimate users behind one IP. If you serve those, set the limit higher and rely on the
WAF rules for the rest.
