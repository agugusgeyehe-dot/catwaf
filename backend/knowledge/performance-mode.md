---
id: performance-mode
title: Performance mode and WAF overhead
keywords: [performance, speed, slow, latency, overhead, cpu, resource, fast, optimise, sampling, impact]
questions:
  - Does CatWAF slow down my site?
  - What is performance mode?
  - How do I reduce CPU usage?
  - Is the firewall making my site slow?
related: [paranoia-levels, engine-modes]
actions: []
---

Inspecting every request costs something. For most sites the overhead is a few
milliseconds and invisible next to normal application and network time.

## What actually costs

- **Paranoia level.** Higher levels run more rules against more of the request. This is
  the biggest single factor.
- **Request body inspection.** Scanning large uploads costs far more than scanning a URL.
- **Traffic volume**, obviously.

## Performance mode

Performance mode trades some inspection depth for lower overhead — useful on a small
server, or when the WAF is measurably competing with your application for CPU.

## Before you turn it on

Confirm the firewall is actually the problem. A slow site is far more often slow
application code, a slow database query, or an undersized server. Turning off protection
to fix a problem it isn't causing leaves you slower *and* less protected.

If you do need to reduce load, the cheaper first moves are lowering the paranoia level by
one, or capping the maximum request body size that gets inspected — both are more
targeted than a blanket reduction.
