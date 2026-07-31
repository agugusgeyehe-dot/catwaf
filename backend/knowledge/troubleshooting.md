---
id: troubleshooting
title: Troubleshooting — site down, Caddy not running, nothing working
keywords: [broken, down, not working, error, 502, 503, caddy, coraza, wont start, fix, diagnostics, crash, offline]
questions:
  - My site is down after installing CatWAF
  - Caddy is not running
  - I am getting a 502 error
  - Coraza module not found
  - Nothing is being blocked
related: [getting-started, dashboard, engine-modes]
actions: []
---

Start with the **Diagnostics** page — it checks each part of the chain and tells you which
one is failing.

## My site is down / 502

Caddy is running but can't reach your application. CatWAF sits in front of your app; if
the app itself is stopped, Caddy has nothing to forward to. Check your app is running and
listening on the port Caddy is proxying to.

## Caddy is not running

Nothing is being served at all. Start it, then check the Caddy log for a config error —
a malformed Caddyfile is the usual cause after a hand edit.

## Coraza module not found

Caddy is running, but without the WAF module compiled in — so traffic passes through
completely unfiltered. This is the dangerous failure mode, because the site looks fine
while being unprotected.

Caddy needs a build that includes `github.com/corazawaf/coraza-caddy/v2`. Reinstalling
CatWAF's dependencies fetches a suitable build automatically.

## Nothing is being blocked

Work through in order:

1. Is the engine **On** (not Detection Only)?
2. Is Coraza actually loaded? (Diagnostics)
3. Is traffic reaching Caddy at all, or going straight to your app? (Origin Exposure
   Scanner)

The third is the most common answer on a site that was already live before CatWAF.
