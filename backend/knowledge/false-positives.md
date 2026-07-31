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

## What not to do

Don't turn the engine off to fix one blocked customer. That removes protection from the
entire site to solve a problem affecting one address. Allow their IP instead.
