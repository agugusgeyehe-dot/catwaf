---
id: dashboard
title: Reading the dashboard
keywords: [dashboard, home, overview, stats, graph, chart, traffic, numbers, empty, zero, no data, live]
questions:
  - What am I looking at on the dashboard?
  - Why is my dashboard empty?
  - Why does it show zero requests?
  - Where is my traffic data?
related: [blocked-requests, getting-started, troubleshooting]
actions: []
---

The dashboard summarises real traffic through your firewall: total requests, how many
were blocked, the attack types seen, and the most active source addresses.

## Why it might be empty

An empty dashboard on a new install is normal and correct. CatWAF only shows traffic it
has genuinely inspected — it never generates sample data to make the page look busy.

You'll see zeros when:

- **No traffic has arrived yet.** A brand-new install on a quiet site legitimately has
  nothing to show.
- **Traffic isn't routing through Caddy.** If visitors reach your app directly, CatWAF
  never sees those requests. This is the common cause on an existing site — check the
  Origin Exposure Scanner.
- **Coraza's audit log isn't being written.** Check Diagnostics; if the Coraza module
  isn't loaded, requests pass through unfiltered and unlogged.

## What to watch

The ratio matters more than the totals. A steady trickle of blocked scanner traffic is
normal background noise on any public site. A sudden spike from one address or one attack
type is worth investigating — and worth setting up Alerts for, so you don't have to
watch.
