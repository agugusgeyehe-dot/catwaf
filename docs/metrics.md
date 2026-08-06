# Metrics

CatWAF exposes a Prometheus-compatible scrape endpoint. It is off by default.

```
catwaf settings metrics enabled=true token=<a long random string>
```

Or **System → Telemetry** in the dashboard, which carries the metrics settings
alongside it.

- [Enabling it safely](#enabling-it-safely)
- [What is exported](#what-is-exported)
- [Worth alerting on](#worth-alerting-on)
- [Scrape configuration](#scrape-configuration)

---

## Enabling it safely

The endpoint describes your security posture: engine mode, paranoia level, how
many addresses are banned and by what, which optional features are on. That is
exactly the reconnaissance an attacker wants, so it is guarded twice and both
guards are on by default:

| Setting | Default | What it does |
|---|---|---|
| `require_token` | `true` | Demands `Authorization: Bearer <token>` |
| `allow_cidrs` | `127.0.0.1/32`, `::1/128` | Refuses scrapes from anywhere else |
| `token` | _(unset)_ | Write-only; set it, and it is never printed back |
| `path` | `/metrics` | Move it if you like |
| `include_geo` | `false` | Adds a per-country series — see below |

`include_geo` is off because a per-country blocked-request series has a
cardinality of up to ~250 and is genuinely useful to some people and pure noise
to others. Turn it on deliberately.

The endpoint is mounted outside the rotating admin path, because a scraper
needs a fixed URL. It carries its own authentication rather than borrowing the
dashboard's session.

---

## What is exported

Every metric is prefixed with `metrics.prefix` (default `catwaf`). All are
gauges — CatWAF reports current state rather than monotonic counters, so a
restart does not produce a counter reset your dashboards have to reason about.

### Build and process

| Metric | Labels | Meaning |
|---|---|---|
| `catwaf_build_info` | `version`, `engine`, `edition`, `node` | Always `1`; the labels carry the information |
| `catwaf_up` | — | Always `1` when scraped |
| `catwaf_uptime_seconds` | — | Seconds since the API process started |

### WAF configuration

Exported as gauges specifically so you can alert on a *setting* changing, not
just on traffic.

| Metric | Meaning |
|---|---|
| `catwaf_waf_engine_enabled` | `1` when blocking, `0` in detection-only or off |
| `catwaf_waf_paranoia_level` | Current CRS blocking paranoia level, 1–4 |
| `catwaf_waf_anomaly_threshold` | Inbound anomaly score threshold |
| `catwaf_rate_limit_enabled` | `1` when rate limiting is on |

### Traffic

| Metric | Labels | Meaning |
|---|---|---|
| `catwaf_requests_total` | `window` = `1h`, `24h` | Requests in the log |
| `catwaf_blocked_total` | `window` = `1h`, `24h` | Blocked requests |
| `catwaf_blocked_by_category` | `category` | Blocked in 24h by CRS attack category |
| `catwaf_blocked_by_severity` | `severity` | Blocked in 24h by severity |
| `catwaf_blocked_by_country` | `country` | Only when `include_geo` is on |

Despite the `_total` suffix these are windowed gauges, not counters — the name
is kept for familiarity. Do not wrap them in `rate()`.

### Protection layer

| Metric | Labels | Meaning |
|---|---|---|
| `catwaf_active_bans` | `source` (plus `source="all"`) | Currently banned addresses, by the feature that banned them |
| `catwaf_list_entries` | `list` | Sizes of the IP blocklist, allowlist, geo rules, custom rules and disabled rules |

### Configuration health

These two are the reason to scrape CatWAF even if you already graph your web
server:

| Metric | Meaning |
|---|---|
| `catwaf_config_skipped_directives` | Settings that are switched **on** but could not be rendered — a missing Caddy module or unmet prerequisite |
| `catwaf_caddy_reload_pending` | `1` when a reload is queued but has not run |

A non-zero `catwaf_config_skipped_directives` means you believe a protection is
active and it is not. Alert on it.

### Scheduled jobs

| Metric | Labels | Meaning |
|---|---|---|
| `catwaf_job_last_run_timestamp_seconds` | `job` | Unix time of the last completion |
| `catwaf_job_last_run_success` | `job` | `1` if the last run succeeded |

A job that has never run has no series at all, which is deliberate: absence is
a different condition from failure, and `absent()` can alert on it.

---

## Worth alerting on

```yaml
groups:
  - name: catwaf
    rules:
      # A protection you think is on, that is not.
      - alert: CatWAFSettingNotInEffect
        expr: catwaf_config_skipped_directives > 0
        for: 15m
        annotations:
          summary: A CatWAF setting is enabled but was not rendered into the config
          description: Run `catwaf doctor` — usually a missing optional Caddy module.

      # The firewall silently stopped firewalling.
      - alert: CatWAFNotBlocking
        expr: catwaf_waf_engine_enabled == 0
        for: 5m
        annotations:
          summary: CatWAF is not blocking attacks

      # A scheduled job stopped working — list refreshes, backups, cert checks.
      - alert: CatWAFJobFailing
        expr: catwaf_job_last_run_success == 0
        for: 30m
        annotations:
          summary: "CatWAF job {{ $labels.job }} last run failed"

      # A job that should be running has not reported in.
      - alert: CatWAFJobStalled
        expr: time() - catwaf_job_last_run_timestamp_seconds > 86400
        annotations:
          summary: "CatWAF job {{ $labels.job }} has not completed in 24h"

      # Backups are configured but nothing is landing.
      - alert: CatWAFBackupsStale
        expr: time() - catwaf_job_last_run_timestamp_seconds{job="backups.run"} > 172800
        annotations:
          summary: No CatWAF backup has completed in two days

      # A sudden mass ban is either an attack or a false-positive rule.
      - alert: CatWAFBanSurge
        expr: catwaf_active_bans{source="bad_behavior"} > 100
        for: 10m
        annotations:
          summary: Behavioural banning has banned an unusual number of addresses
          description: Either you are under attack, or a legitimate client is tripping the threshold.
```

---

## Scrape configuration

```yaml
scrape_configs:
  - job_name: catwaf
    metrics_path: /metrics
    scheme: https
    static_configs:
      - targets: ['catwaf.example.com']
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/catwaf-token
```

Add the scraper's address to `allow_cidrs` — it is not enough to hold the
token:

```
catwaf settings metrics allow_cidrs=127.0.0.1/32,::1/128,10.0.0.5/32
```

A scrape from an address outside `allow_cidrs` is refused even with a correct
token, and a scrape with no token is refused even from an allowed address. If
you want only one of the two guards, turn the other off explicitly rather than
leaving it in place and wondering why the scrape 401s.

---

## See also

- [Settings reference](settings.md#metrics) — every field
- [Protection layer](protection.md) — what the ban and skip metrics are counting
- [CLI reference](cli.md#catwaf-jobs) — inspecting the jobs these metrics track
