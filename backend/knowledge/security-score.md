---
id: security-score
title: Understanding your security score
keywords: [score, grade, rating, improve, recommendation, posture, percentage, letter, better, raise, low]
questions:
  - What does my security score mean?
  - How do I improve my score?
  - Why is my grade so low?
  - How do I get an A?
related: [getting-started, paranoia-levels, cloudflare]
actions: [engine.enable, rate_limit.enable, paranoia.set]
---

The security score is a weighted checklist of things CatWAF can actually verify about
your setup. It is computed from your real configuration — not an estimate, and not a
number that moves on its own.

Each check is **pass**, **warning**, **fail**, or **unknown**. Unknown checks (things
CatWAF genuinely can't verify) are excluded from the maths entirely rather than counted
against you.

## Raising it

Work down the recommendations on the Security page in order — they're sorted by impact.
The usual big movers:

- **Engine is On** (not Detection Only or Off). Largest single factor.
- **An admin account with a real password.**
- **Rate limiting enabled** — cheap to turn on, stops brute-force and scraping.
- **Cloudflare connected and the origin locked** so traffic can't bypass the firewall.
- **Paranoia level above 1**, once you've confirmed level 1 produces no false positives.

## What the score isn't

It measures **configuration**, not whether you've been attacked or whether your
application code is safe. A perfect score on a site running vulnerable software is still
a vulnerable site. Treat it as "have I turned on what's available", not "am I safe".
