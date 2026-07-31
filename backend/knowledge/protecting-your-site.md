---
id: protecting-your-site
title: Actually protecting your website (adding it to the Caddyfile)
keywords: [protect, reverse proxy, caddyfile, add site, real site, my website, my app, connect app, point at, in front of]
questions:
  - How do I actually protect my website with CatWAF?
  - How do I add my site to the Caddyfile?
  - My changes aren't blocking anything on my real site
  - How does CatWAF connect to my app?
related: [getting-started, troubleshooting, origin-exposure]
actions: []
---

CatWAF's dashboard doesn't inspect traffic itself — Caddy does, with the Coraza module doing the actual inspection. The dashboard's job is to keep the WAF part of your Caddyfile in sync with whatever you configure here. For your app to actually be protected, Caddy needs a site block pointing at it.

## The one-time setup

Your Caddyfile lives wherever `CADDYFILE_PATH` points (`catwaf --setup` creates one for you and shows the path). Add a block for your real app, if it isn't there already:

```caddyfile
yourdomain.com {
    reverse_proxy localhost:3001
}
```

Replace `localhost:3001` with wherever your app actually runs, and `yourdomain.com` with the real address visitors use.

## Then apply any WAF setting once

The first time you change something in the dashboard — turn the engine on, adjust paranoia, block an IP — CatWAF looks for a marked block in that site and inserts one if it isn't there yet:

```caddyfile
yourdomain.com {
    reverse_proxy localhost:3001

    # @@CATWAF_WAF_START@@
    coraza_waf { ...generated from your settings... }
    order coraza_waf first
    # @@CATWAF_WAF_END@@
}
```

Everything between those two marker lines is regenerated automatically every time you change a setting — there's nothing to hand-edit there. Everything **outside** the markers (your `reverse_proxy` line, TLS settings, anything else in the block) is yours; CatWAF never touches it.

## If nothing seems to be getting blocked

The most common cause is that your real site's traffic still isn't routing through this Caddy instance at all — check the Origin Exposure Scanner. The Caddyfile can be perfectly configured and still protect nothing if visitors can reach your app directly.
