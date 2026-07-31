# CatWAF CLI reference

Every command supports `catwaf help <command>`. Commands that change
configuration back up the Caddyfile, validate the result, and roll back
automatically if Caddy rejects it.

## Editions

Every command documented here works in **both CatWAF Lite and CatWAF Full**,
with one exception: [`catwaf docker`](#catwaf-docker) requires Full, because
Lite does not install the Docker stack.

Run a Full-only command on Lite and it explains what is missing, names the fix
(`catwaf setup --full`), and exits `5`. It does not print a stack trace, and it
does not silently succeed.

```
$ catwaf docker up
This command requires CatWAF Full — Docker stack management is not installed in Lite.
Run `catwaf setup --full` to add it. Your WAF configuration, rules, event history
and admin accounts are preserved.
$ echo $?
5
```

### `catwaf edition`
```
catwaf edition
```
Prints `lite` or `full`. Reads `CATWAF_EDITION` from `.env`; if that is absent
(an installation predating the edition model), the edition is inferred from
whether a built dashboard is present.

### `catwaf version`
```
catwaf version
```
Prints the version, e.g. `1.0.1`. Matches `package.json`, the `/api/health`
response and the Docker image labels.

### `catwaf status`
```
catwaf status
```
Version, edition, protection state, Caddy and Coraza status, API server,
dashboard, CatAI and GeoIP availability, active rule count, load and uptime,
security score and recent activity.

On Lite, Full-only components are reported as `NOT INSTALLED (Lite)` rather
than as failures — a Lite box without an API server is correct, not degraded.

## Setup

### `catwaf setup`
```
catwaf setup                      # interactive: choose an edition
catwaf setup --lite               # WAF + CLI only
catwaf setup --full               # adds API, dashboard, CatAI
catwaf setup --custom             # interactive component selection
```

| Option | Meaning |
|---|---|
| `--lite` | Caddy + Coraza + CRS, CLI, event database. No frontend dependencies. |
| `--full` | Everything in Lite plus the HTTP API, dashboard and CatAI. |
| `--domain <domain>` | Base domain. Omit to run locally. |
| `--admin-user <name>` | Admin account to create. |
| `--admin-pass <pass>` | Admin password. Prefer `CATWAF_ADMIN_PASSWORD`. |
| `--yes` | Never prompt. Suppresses prompts only — validation still runs. |
| `--no-ai` | Skip CatAI even in Full. |
| `--rebuild` | Rebuild the dashboard even if `frontend/dist` exists. |
| `--force` | Overwrite existing domain settings. |
| `--minimal` | Legacy spelling of `--lite`. Accepted; prints a note. |
| `--standard` | Legacy spelling of `--full`. Accepted; prints a note. |

Re-running with a different edition converts in place and preserves your WAF
configuration, database, event history, rules, domain settings and admin
accounts.

Prefer `CATWAF_ADMIN_PASSWORD` over `--admin-pass`: a flag is visible in your
shell history and in `ps` output.

```bash
CATWAF_ADMIN_PASSWORD='...' catwaf setup --lite \
  --admin-user admin --domain example.com --yes
```

## Investigate

### `catwaf audit`
```
catwaf audit [--last 24h] [--attack SQLi] [--severity critical] [--limit 10] [--json]
```
Totals, block rate, top attack types, top CRS rules, severity distribution,
anomaly-score statistics and recent blocked requests for a time window.

Windows: `30m`, `6h`, `24h`, `7d`, `4w`. `--json` output is stable and
machine-readable.

### `catwaf explain`
```
catwaf explain <event-id>
catwaf explain --last [--json]
```
For one event: classification, matched CRS rules with descriptions, paranoia
level, anomaly score vs threshold, severity, the request component that
actually matched, why it was blocked, and remediation — including the exact
command to disable only the decisive rule.

Bodies, cookies and `Authorization` headers are never stored and cannot be
shown. Sensitive-looking query parameters are redacted.

### `catwaf simulate`
```
catwaf simulate --url '<url>' [--json]
catwaf simulate --request <file> [--json]
```
Runs a request through a throwaway Caddy + Coraza instance using your current
configuration, against a local sink. **Your real upstream is never contacted.**

`--url` supplies the method, path, query and headers only — CatWAF does not
fetch the URL (that would be an SSRF primitive). Only `http` and `https` are
accepted.

`--request` takes a raw HTTP request file:
```
POST /login HTTP/1.1
Host: example.com
Content-Type: application/json

{"user":"x"}
```
Sensitive headers are stripped before simulation.

### `catwaf replay`
```
catwaf replay <event-id> [--json]
```
Rebuilds a stored attack from sanitized fields and replays it against the
sandbox — never production. Reports whether it is still blocked, which rules
changed, and warns loudly on a regression (previously blocked, now allowed).

## Tune

### `catwaf paranoia`
```
catwaf paranoia          # show levels and the active one
catwaf paranoia <1-4> [--yes]
```
| Level | Name | Behaviour |
|---|---|---|
| 1 | Balanced | Clear attacks, very few false positives (default) |
| 2 | Elevated | Adds usually-malicious patterns |
| 3 | Aggressive | Adds heuristics; expect to tune |
| 4 | Maximum | Blocks nearly anything unusual |

Sets the real CRS `tx.blocking_paranoia_level` in your Caddyfile. Raising to
3 or 4 prompts for confirmation. Detection level is raised to match when
needed (CRS requires detection >= blocking).

### `catwaf mode`
```
catwaf mode [normal|lockdown|learning|maintenance] [--yes]
```
| Mode | Engine | PL | Threshold | Audit | Blocks |
|---|---|---|---|---|---|
| normal | On | 1 | 5 | on | yes |
| lockdown | On | 4 | 3 | on | yes, aggressively |
| learning | DetectionOnly | 3 | 5 | on | **no** |
| maintenance | On | 1 | 5 | off | yes |

`learning` leaves your site unprotected while active and requires
confirmation. `maintenance` reduces logging but does **not** weaken
protection.

CatWAF detects drift: if settings change after a mode is applied, `catwaf
mode` says so rather than reporting a mode that is no longer accurate.

### `catwaf rules`
```
catwaf rules list [--category <c>] [--disabled|--enabled] [--limit n] [--json]
catwaf rules search <query>
catwaf rules show <rule-id>
catwaf rules enable <rule-id>
catwaf rules disable <rule-id>
```
Disabling writes a real `SecRuleRemoveById` directive. Rule IDs are validated
as 3-7 digits; anything else is rejected.

Rule metadata comes from local CRS `.conf` files when they can be found
(`CATWAF_CRS_PATH`, the Go module cache, or common system paths). When they
cannot, CatWAF falls back to rules observed in real traffic and says so
rather than inventing descriptions.

## Operate

### `catwaf health`
```
catwaf health [--json]
catwaf health --watch [--interval 5]
```
Runtime health of CatWAF, Caddy, Coraza, CRS, the database and schema, the
Caddyfile and its validity, WAF interception, audit log, event ingestion, the
dashboard build and the Caddy admin API.

Exit codes: `0` healthy, `1` degraded, `2` unhealthy.

### `catwaf security-test`
```
catwaf security-test [--json]
```
Assesses CatWAF's own deployment posture: bind addresses, admin-API exposure,
Docker socket and privileged containers, secret strength and file
permissions, CORS, security headers, proxy trust, WAF interception and bypass
risk, disabled rules and rate limiting.

Exit codes: `0` clean, `1` at least one high finding, `2` at least one
critical. Passing does not mean the protected application is secure.

### `catwaf diff`
```
catwaf diff [--config] [--rules] [--json]
```
What changed since the most recent snapshot: WAF settings, paranoia level,
enabled/disabled rules and categories, and the operating mode. Secrets are
never printed.

### `catwaf config` snapshots
```
catwaf config snapshot [--label <text>]
catwaf config snapshots
catwaf config show <id>
catwaf config diff <id> [--against <id>]
catwaf config restore <id> [--yes]
```
Restore is validated before activation and rolls back automatically on
failure. A safety snapshot of the current state is taken before every
restore. Secrets are redacted in `show` and `diff` output.

## Docker

### `catwaf docker`

**Requires CatWAF Full.**

Manages the stack defined in `docker-compose.yml` — the backend API, Caddy with
Coraza, and the local test app.

```
catwaf docker up          # start in the background (--build to rebuild first)
catwaf docker down        # stop and remove containers
catwaf docker restart     # restart every service
catwaf docker status      # show each service and its state
catwaf docker ps          # alias of status
catwaf docker logs        # recent logs (--follow / -f to stream)
catwaf docker build       # rebuild images
```

| Option | Applies to | Meaning |
|---|---|---|
| `--build` | `up` | Rebuild images before starting. |
| `--follow`, `-f` | `logs` | Stream instead of printing a snapshot. |

Subcommands are matched against a fixed allowlist and the argument vector is
built from constants — no shell is used, and nothing you type is interpolated
into a command. An unrecognised subcommand is rejected before anything runs.

Works with either the `docker compose` plugin or a standalone `docker-compose`
binary; if neither is present it says which is missing and exits `3`.

```
$ catwaf docker frobnicate
Unknown docker subcommand: "frobnicate"
Valid subcommands: up, down, restart, status, ps, logs, build
$ echo $?
2
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Runtime failure |
| 2 | Invalid or missing arguments |
| 3 | A required dependency is not installed (Docker, Caddy) |
| 4 | Permission denied |
| 5 | This command requires an edition that is not installed |

`catwaf health` and `catwaf security-test` predate this table and keep their own
documented meanings, which callers depend on:

| Code | Meaning for `health` / `security-test` |
|---|---|
| 0 | Healthy / no significant findings |
| 1 | Degraded, or a high severity finding |
| 2 | Unhealthy, or a critical finding |

Stack traces are never shown to normal users. Set `CATWAF_DEBUG=1` to print
them when diagnosing a CLI error.
