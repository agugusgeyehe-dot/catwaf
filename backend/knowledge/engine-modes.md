---
id: engine-modes
title: Engine modes — On, Detection Only, and Off
keywords: [engine, mode, on, off, detection, monitor, enable, disable, turn on, active, protection]
questions:
  - What does Detection Only mean?
  - How do I turn protection on?
  - Should I use detection only or blocking?
  - Is the firewall running?
related: [getting-started, false-positives, paranoia-levels]
actions: [engine.enable]
---

The engine has three modes.

## On
Attacks are **blocked**. The visitor gets a 403 and your app never sees the request.
This is the mode you want in production.

## Detection Only
Attacks are **logged but allowed through**. Nothing is blocked. Useful for a week or two
after a big change, when you want to see what *would* have been blocked without risking
real customers. It is not protection — a site left in Detection Only is unprotected.

## Off
Nothing is inspected or logged.

## Which should I use?

Start in **Detection Only** if you have unusual traffic and are nervous about false
positives. Watch the blocked-request log for a few days. If nothing legitimate is being
flagged, switch to **On**.

If you're already live and unsure, **On** is the right default — the OWASP rules at
paranoia level 1 are conservative and rarely catch normal traffic.

Switching modes takes effect immediately; CatWAF rewrites the Caddy config and reloads it
for you.
