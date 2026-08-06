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

1. Turn on **Reject unknown Host/SNI** under *Access control*. This is the direct fix,
   and it works whether or not you use Cloudflare: CatWAF refuses any request whose
   `Host` header isn't one of your hostnames, instead of letting it fall through to a
   site block by accident. An attacker connecting to your bare IP has no hostname to
   send, so there is nothing for them to reach.

       catwaf settings access reject_unknown_host=true known_hosts=example.com

   List every hostname the server should answer for in `known_hosts` first — anything
   missing from that list gets refused once the switch is on. `CATWAF_EXTRA_HOSTS` in
   `.env` adds to it too.

2. Run the **Origin Exposure Scanner**. It checks whether your server still answers
   directly, which is how you confirm step 1 actually took effect rather than assuming it.
3. If you're behind Cloudflare, **lock the origin** so it only accepts connections from
   Cloudflare's ranges as well (see *Connecting Cloudflare*). Step 1 and step 3 fail in
   different ways, so having both is not redundant.
4. Remove or proxy any DNS records pointing straight at the server.
5. If the address is already widely known, changing it is the only complete fix — do
   steps 1 to 3 first regardless.

Rotating a leaked IP without closing the origin just starts the clock again.

## Why this used to be harder

Until recently CatWAF could explain this problem but had no switch to close it — the
advice was entirely about DNS and Cloudflare. **Reject unknown Host/SNI** is the
mechanical fix, and the security score now checks for it directly.
