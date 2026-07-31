---
id: origin-exposure
title: Origin exposure — can attackers bypass your firewall?
keywords: [origin, exposure, bypass, direct, real ip, leak, scanner, reachable, skip, around, direct access]
questions:
  - Can people bypass CatWAF?
  - What is origin exposure?
  - Is my real server IP exposed?
  - How do I check if my firewall can be skipped?
related: [cloudflare, getting-started]
actions: []
---

A firewall only protects traffic that passes through it. If your server is reachable
directly — by IP, or through a stale DNS record — an attacker can skip CatWAF entirely
and talk to your app unfiltered.

This is the single most common way a correctly-configured WAF ends up providing no
protection at all.

## How origins leak

- **Old DNS records.** An `A` record for `direct.example.com` or `mail.example.com`
  pointing at the same server.
- **Certificate transparency logs.** Every certificate you've issued is public, along
  with its hostnames.
- **Email headers.** Mail sent from the same server exposes its address.
- **The address was public before** you put Cloudflare in front of it. It's archived.

## Fixing it

1. Run the **Origin Exposure Scanner**. It checks whether your server answers directly.
2. If it does, **lock the origin** so it only accepts connections from Cloudflare (see
   *Connecting Cloudflare*).
3. Remove or proxy any DNS records pointing straight at the server.
4. If the address is already widely known, changing it is the only complete fix — lock the
   origin first regardless.

Rotating a leaked IP without locking the origin just starts the clock again.
