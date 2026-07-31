---
id: user-agents
title: Blocking bots and scanners by user agent
keywords: [user agent, bot, scanner, crawler, sqlmap, nikto, nmap, useragent, ua, spider, block bot, scraper]
questions:
  - How do I block bots?
  - Can I block sqlmap?
  - How do I stop scrapers?
  - Block a user agent
related: [rate-limiting, ip-blocklist]
actions: [ua.block]
---

CatWAF can refuse requests whose `User-Agent` header matches a list you control. It ships
blocking the obvious security scanners — sqlmap, nikto, nmap, masscan, dirbuster, hydra
and similar.

## What this is good for

Cutting noise. Automated scanners announce themselves by default, and blocking them stops
their traffic before the rules run. Your logs get quieter and real incidents become easier
to spot.

## What this is not

**A security control.** A user agent is a header the client chooses — an attacker changes
it with one flag. Anyone competent is not going to be stopped by this, and the tools
listed above all support custom agents.

Treat it as a noise filter that happens to catch lazy attackers, and rely on the WAF rules
for actual protection.

## Careful with scrapers

Blocking a scraper by user agent works only while it's honest about who it is. The ones
worth blocking usually aren't. Rate limiting is the more effective tool against scraping,
since it works regardless of what the client claims to be.

Also make sure you're not blocking something you want: search engine crawlers, uptime
monitors, and preview-link fetchers from chat apps all identify by user agent.
