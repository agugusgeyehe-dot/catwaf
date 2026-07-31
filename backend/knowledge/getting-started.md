---
id: getting-started
title: Getting started with CatWAF
keywords: [start, setup, begin, first, new, install, what is, how does, overview, protect, site]
questions:
  - What is CatWAF and how does it work?
  - How do I get started?
  - Is my site protected?
  - What should I do first?
related: [engine-modes, security-score, paranoia-levels]
actions: [engine.enable]
---

CatWAF sits in front of your website. Every request passes through Coraza — a web
application firewall running the OWASP Core Rule Set — before it reaches your app.
Requests that match an attack pattern are blocked and logged; everything else passes
through untouched.

## Is it actually protecting me?

Three things have to be true:

1. **The engine is On.** Check the Dashboard. `Detection Only` logs attacks but blocks
   nothing; `Off` does neither.
2. **Caddy is running** with the Coraza module loaded. The Diagnostics page checks this.
3. **Your traffic actually routes through it.** If visitors can reach your server
   directly, bypassing Caddy, the firewall never sees them. The Origin Exposure Scanner
   checks for this.

## A sensible first hour

- Turn the engine **On**.
- Leave paranoia at **level 1** to start. Raise it later once you know your normal
  traffic doesn't trip it.
- Look at your **Security Score** and work down the recommendations.
- Set up **Alerts** so you hear about attacks without watching a dashboard.

Everything CatWAF shows you reflects your real system. If something isn't configured
yet, it says so rather than showing sample data.
