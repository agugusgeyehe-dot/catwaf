---
id: ip-blocklist
title: Blocking a specific IP address
keywords: [block ip, blacklist, ban, deny, attacker, address, cidr, range, stop, blocklist]
questions:
  - How do I block an IP address?
  - Block 203.0.113.9
  - How do I ban an attacker?
  - Can I block a whole IP range?
related: [ip-allowlist, geo-blocking, blocked-requests]
actions: [ip.block]
---

Blocking an IP refuses every request from it immediately, before any rule runs.

You can block a single address (`203.0.113.9`) or a whole range in CIDR notation
(`203.0.113.0/24` covers 256 addresses).

## When to block

- One address is generating sustained attack traffic in your logs.
- A scanner is hammering your site and the rules are catching it, but you'd rather it
  stopped consuming resources entirely.

## Set an expiry

Attack traffic usually comes from short-lived, rented addresses. A block you set today
may be punishing an innocent person on the same address next month. Giving blocks a time
limit keeps the list from silently accumulating stale entries forever.

## You cannot block yourself

CatWAF refuses to blacklist a range covering your own address, because doing so would
lock you out of the panel you'd need in order to undo it. If you get that error, narrow
the range — you've almost certainly typed something broader than you meant.

## Blocking a range is a big hammer

A `/16` covers 65,536 addresses and will include people who have nothing to do with the
attack. Prefer the narrowest range that actually stops the problem.
