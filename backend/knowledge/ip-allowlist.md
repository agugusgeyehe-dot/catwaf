---
id: ip-allowlist
title: Allowing an IP through the firewall
keywords: [allow, whitelist, allowlist, unblock, exempt, trusted, bypass, skip, let through, office]
questions:
  - How do I whitelist an IP?
  - Allow my office IP
  - How do I unblock an address?
  - Unblock 198.51.100.4
  - Allow 203.0.113.9 for an hour
  - Can I exempt myself from the firewall?
related: [false-positives, ip-blocklist]
actions: [ip.allow, ip.unblock]
---

Allowing an IP lets it skip the WAF rules entirely. It is the fastest way to unblock a
real customer who's hitting a false positive.

## Use it for

- A customer or colleague caught by a false positive, while you investigate the cause.
- Your own office or home address, so your testing never trips a rule.
- A monitoring service or payment webhook that legitimately sends odd-looking requests.

## Always set a time limit

An allowlist entry is a hole in your firewall. A 60-minute exception to unblock a
customer is sensible; the same entry still sitting there in eight months is a liability —
addresses get reassigned, offices move, laptops get stolen.

CatWAF defaults allowlist entries to one hour for exactly this reason. Extend it
deliberately if you genuinely need to.

## Understand what you're turning off

An allowlisted address bypasses **all** rule checks. If that machine is compromised, or
the address is reassigned, attacks from it reach your app unfiltered. Never allowlist a
range you don't control — and never allowlist a whole country or a large CIDR block as a
shortcut.

## Unblocking

If an address is on the blocklist and shouldn't be, remove it from the blocklist rather
than adding it to the allowlist. Removing the block restores normal filtered access;
allowlisting removes filtering altogether.
