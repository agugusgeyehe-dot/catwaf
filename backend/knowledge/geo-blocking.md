---
id: geo-blocking
title: Blocking visitors by country
keywords: [geo, country, region, china, russia, block country, nation, location, geographic, worldwide]
questions:
  - How do I block a country?
  - Block all IPs from China
  - Can I stop traffic from Russia?
  - How do I block a whole region?
  - Make my firewall block traffic coming from a country
  - Block all traffic from Brazil
related: [ip-blocklist, rate-limiting]
actions: [geo.block]
---

Geo blocking refuses every request from a country you select, before the WAF rules even
run. It's a blunt instrument, and that's exactly why it's useful: if you run a local
business that only serves one country, blocking the rest removes most automated attack
traffic in one step.

## When it makes sense

- Your customers are all in one country or region.
- You're seeing sustained attack traffic from somewhere you don't do business with.
- You want to cut background scanner noise so real incidents stand out.

## When it doesn't

- **You have international customers.** Blocking a country blocks your customers there,
  with no warning and no way for them to tell you.
- **You expect it to stop a determined attacker.** It won't — a VPN or a proxy in an
  allowed country defeats it in seconds. Treat it as noise reduction, not defence.
- **You rely on it instead of the WAF.** Geo blocking doesn't inspect anything. An attack
  from an allowed country passes straight through to the rules.

## Notes

Country detection is IP-based and imperfect. Travellers, VPN users and some mobile
networks can be misidentified. If a specific person is wrongly blocked, allow their IP
individually rather than unblocking the whole country.
