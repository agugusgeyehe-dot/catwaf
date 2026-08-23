---
id: domain-https-setup
title: Setting up your domain and HTTPS
keywords: [domain, https, ssl, tls, certificate, dns, subdomain, catwaf.domain, api.domain, setup wizard, https setup]
questions:
  - How do I set up my domain?
  - How do I get HTTPS working?
  - What DNS records do I need?
  - Why does the dashboard need two subdomains?
related: [getting-started, cloudflare]
actions: []
---

`catwaf --setup` asks for your domain once and configures both HTTPS endpoints for you — there's no certificate step to do by hand.

## The two subdomains

- **`catwaf.yourdomain.com`** — the dashboard you log into.
- **`api.catwaf.yourdomain.com`** — the API the dashboard talks to.

Splitting them keeps the admin API off a fixed, guessable address on your main domain — it's part of why the API isn't reachable at any predictable path even once you're on that subdomain (see the README's Security section).

## What you need to do

Point both as A (or AAAA, or CNAME) records at your server, before or right after running setup:

```
catwaf.yourdomain.com      →  your server's IP
api.catwaf.yourdomain.com  →  your server's IP
```

Caddy requests certificates for both automatically the first time it starts with those records in place — there's no manual certbot step, no renewal to remember. If a certificate fails to issue, it's almost always because the DNS record isn't pointing at the server yet, or hasn't propagated.

## Running without a domain

Leave the domain blank during setup to run locally at `http://localhost:8000` (whatever `PORT` is set to) instead — the backend serves the dashboard and API itself on one port, no Caddy fronting needed, no certificate involved. You can always re-run `catwaf --setup` later once you have a domain ready.

## Changing your domain later

Update `DOMAIN` in `.env` and re-run `catwaf --setup` — it'll pick up the new value and regenerate what's needed.
