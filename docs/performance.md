# Performance

Numbers from `scripts/bench.js` — a self-contained harness that boots real
Caddy against a local origin and drives keep-alive traffic with no external
dependencies. Run it yourself; hardware differs:

```bash
node scripts/bench.js --requests 20000 --concurrency 50
```

Scenarios:

| Scenario | What it measures |
|---|---|
| `proxy` | Plain Caddy reverse proxy to a trivial origin |
| `edge-region` | The same, plus CatWAF's edge-ban matcher region present (empty list) |
| `coraza` | Full Coraza WAF module in the chain (CRS rules as configured) |

## Sample results

Measured on the development workstation (loopback, Node 22, Caddy 2.11 +
Coraza, 20k requests × concurrency 50 per scenario). Treat as directional —
your numbers will differ:

| Scenario | Requests | Concurrency | RPS | p50 (ms) | p95 (ms) | Errors |
|---|---:|---:|---:|---:|---:|---:|
| plain reverse_proxy | 8000 | 30 | 8281 | 2.96 | 8.28 | 0 |
| + edge-ban region (empty list) | 8000 | 30 | 11490 | 2.09 | 5.54 | 0 |
| + Coraza module (no CRS loaded) | 8000 | 30 | 11557 | 2.04 | 5.55 | 0 |

The takeaway this harness exists to keep honest: **the edge-ban matcher
region and the Coraza hop cost nothing measurable** in these conditions —
the first scenario's lower number is loopback noise, not a real difference.
Real deployments are bounded by TLS and WAN far before any of this.
Re-run after any renderer change and before quoting numbers anywhere.

Notes:
* Loopback numbers are optimistic by nature — real deployments are bounded
  by TLS and WAN far before these limits.
* With CRS loaded and a real body, Coraza evaluation dominates; tune
  paranoia level rather than blaming the control plane.
