---
id: false-positives
title: When legitimate visitors get blocked
keywords: [false positive, blocked, customer, checkout, legitimate, real user, 403, forbidden, cant access, mistake, wrongly]
questions:
  - Why are real customers getting blocked?
  - My checkout page is being blocked
  - A legitimate user got a 403
  - How do I unblock someone?
  - CatWAF is blocking my own site
related: [ip-allowlist, paranoia-levels, blocked-requests]
actions: [ip.allow, ip.unblock, paranoia.set]
---

A "false positive" is CatWAF blocking someone who wasn't attacking you. It usually means
an OWASP rule matched normal input that happens to look suspicious — a password with odd
punctuation, a rich-text comment, a long URL, or an upload.

## Fix it right now

**Allow the affected visitor's IP.** This is the fastest unblock and it only affects that
one address. Give it a time limit (an hour is plenty) so a temporary exception doesn't
quietly become permanent.

Find the IP in the blocked-request log, or ask the affected person to visit an
"what is my IP" site and tell you.

## Then find the cause

1. Open the blocked-request log and find their request. It names the rule that fired.
2. If a whole category is misfiring on normal traffic, your paranoia level is probably
   too high. Drop it one level and see if the problem stops.
3. If it's one specific page (a comment form, an admin editor), that page is the thing
   to look at — rich text and file uploads are the usual culprits.

## When it's one endpoint, not one visitor

Some endpoints will never stop tripping the rules: a webhook receiver taking raw JSON
from a payment provider, an upload handler, a rich-text editor's save. Allowing every
caller's IP doesn't work when the callers are someone else's servers.

Exempt the path instead of weakening protection everywhere:

    catwaf settings access waf_bypass_paths=/webhooks/stripe,/admin/editor/save

Under *Access control* in the dashboard, this is **Paths exempt from WAF inspection**.
Requests to those paths skip inspection; everything else is unaffected.

Keep the list short and specific. Each entry is a hole in your own firewall, so exempt
`/webhooks/stripe`, never `/webhooks` and certainly never `/`. Everything else CatWAF
does — rate limiting, the IP lists, geo blocking, bans — still applies to an exempt path;
only CRS inspection is skipped.

This is the right answer to "a CRS rule keeps flagging this one endpoint". Dropping the
paranoia level sitewide to fix one URL is not.

## What not to do

Don't turn the engine off to fix one blocked customer. That removes protection from the
entire site to solve a problem affecting one address. Allow their IP, or exempt the one
path, instead.
