---
id: cloudflare
title: Connecting Cloudflare
keywords: [cloudflare, cdn, proxy, dns, ssl, tls, origin, lock, wizard, orange cloud, certificate]
questions:
  - How do I set up Cloudflare?
  - What does locking the origin do?
  - Should I use Cloudflare with CatWAF?
  - How do I hide my server IP?
related: [origin-exposure, rate-limiting, security-score]
actions: []
---

Cloudflare sits in front of CatWAF, which sits in front of your app. It absorbs
distributed attacks that per-IP rate limiting can't handle, and hides your server's real
address.

The wizard walks through it:

1. **Connect your account** with an API token.
2. **Verify your zone** — confirms CatWAF can see your domain's DNS.
3. **Enable proxying** (the orange cloud) so traffic actually routes through Cloudflare.
4. **Enforce strict SSL** so the Cloudflare-to-your-server hop is encrypted *and*
   certificate-verified.
5. **Lock the origin** — a firewall rule so your server only accepts connections from
   Cloudflare's addresses.

## Why locking the origin matters

Without it, Cloudflare is a suggestion. Anyone who learns your server's real IP can
connect to it directly and skip Cloudflare, your rate limits, and CatWAF entirely. Old
DNS records, certificate transparency logs and email headers all leak origin addresses
routinely.

Locking the origin is what turns "traffic usually goes through Cloudflare" into "traffic
can only go through Cloudflare". Do this step — the rest is much less valuable without it.

## SSL mode

Use **Full (Strict)**. `Flexible` leaves the Cloudflare-to-origin hop unencrypted, and
`Full` (without Strict) accepts any certificate, including an attacker's.
