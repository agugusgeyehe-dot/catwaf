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

## Protect

### `catwaf start`

The "put my website behind CatWAF" command. Starts the service, then puts the
WAF in the request path of every discovered application and **proves** it.

```
catwaf start                      # start, discover, protect, verify
catwaf start --no-auto            # start the service only
catwaf start --no-verify          # apply routes without the live self-test
```

The resulting request path is:

```text
Internet → CatWAF (Caddy) → Coraza + OWASP CRS → your application
```

Steps 3 and 7 are the ones that make this real protection rather than a
generated file:

1. Start CatWAF (systemd where available, otherwise a background process).
2. Discover running web applications (see `catwaf auto` below).
3. **Work out how to actually reach the application**, and prove it with a
   TCP connection before writing any upstream. How depends on where CatWAF
   itself runs:

   | CatWAF runs | Upstream used | Notes |
   |---|---|---|
   | In Docker | `service:80` | Attaches its proxy to the app's network first; Docker DNS resolves the name. No host port needed, so there is no bypass path. |
   | On the host | `127.0.0.1:<hostPort>` | Used when the app publishes a port. |
   | On the host | `<container-ip>:80` | When the app is Docker-internal only. Container subnets on a normal bridge network are routable from the host. Re-resolved on every run, since container IPs change. |

   A host-native CatWAF must **never** be given a Docker DNS name like
   `nginx:80` — the host does not resolve Docker's embedded DNS. If the
   address cannot be connected to, CatWAF reports precisely why (network
   marked internal, non-routable driver, port not listening) instead of
   writing an upstream that would break the site.
4. Generate routes that run Coraza + CRS *before* the upstream, and prepare
   the Coraza audit log. Coraza opens that file when the config is
   *provisioned*, so validation fails outright if it is not openable. CatWAF
   creates it, preferring `/var/log/coraza/audit.json` and falling back to
   `<data dir>/logs/coraza-audit.json` when that is not writable — which is
   the normal case for an unprivileged host-native install. Set
   `CORAZA_AUDIT_LOG` to pin the location; an explicit path is never silently
   relocated.
5. Validate the whole configuration, back it up, apply it atomically.
6. Reload the proxy.
7. **Verify with real traffic**: send a benign request and a CRS test payload
   to CatWAF's own endpoint. The benign one must be served; the payload must
   be blocked.

A route is reported `protected` **only if step 7 passes**. If the upstream is
unreachable, the proxy is not listening, or a payload reaches the application,
CatWAF reports the route as **NOT protected** with the reason and exits
non-zero. A generated configuration is never treated as evidence of
protection.

Re-running is safe: it regenerates only CatWAF's own marked region, keeps
listen ports stable so published endpoints don't move, drops routes whose
containers disappeared, and leaves unrelated configuration untouched.

### `catwaf auto`
```
catwaf auto                       # discover, generate, validate, apply
catwaf auto --dry-run             # discover and show what would happen
catwaf auto --verbose             # also show routing caveats
catwaf auto --json                # machine-readable output
```

Detects Docker, enumerates running containers, and works out which ones are
web applications and what they run:

- **Web port** — from what the container is *running* (an nginx/Apache/Caddy
  process, or a Node/Python runtime), combined with exposed/published ports,
  common-port heuristics, and — for host-published ports only — a lightweight
  local HTTP probe. Three cases are kept distinct:

  | | Meaning | Routed as |
  |---|---|---|
  | **exposed** | the container declares the port; says nothing about reachability | — |
  | **published** | mapped to a host port (`ports: 8080:80`) — also a WAF bypass path | `service:port`, with a bypass warning |
  | **docker-internal** | listening on a Docker network, no host mapping | `service:port` |

  A container does **not** need a published host port to be treated as a web
  application. A Docker-internal service is in fact the safer deployment, and
  is routed by network alias once Caddy joins that network. Only a container
  with neither a host mapping nor a routable network (`host`/`none`
  networking) is genuinely unreachable and skipped.
- **PHP** — a multi-signal confidence score (image name, `php-fpm`/`php`
  process, filesystem probes for `index.php`/`composer.json`/`vendor/`,
  `X-Powered-By` header, response-body fingerprints, environment variables).
  Confidence ≥ 70 is high, 40–69 is "likely", below 40 isn't classified as PHP.
- **Split nginx/Apache + PHP-FPM** — when the web server and PHP run in
  separate containers, CatWAF correlates them by reading the web server's
  `fastcgi_pass` / `fcgi://` target and resolving it to a PHP-FPM container on
  a shared Docker network. If the config can't be read, it falls back to
  network topology, but only when exactly one PHP-FPM container is a
  candidate *and* another PHP signal corroborates it. A static nginx site
  with no FastCGI wiring stays classified as static. The PHP-FPM container is
  reported as part of the application but is never itself proxied — it speaks
  FastCGI, not HTTP.
- **Framework** — Laravel (`artisan`), WordPress (`wp-config.php` or
  `WORDPRESS_*` env vars), Drupal (`sites/default/settings.php`).
- **Runtime** — Node.js, Python, or a static file server, when not PHP.

For each web app found, it generates a Caddy site block that reverse-proxies
to the container (preferring its Docker network/compose-service name over an
IP, since IPs churn on restart) and wraps it in the same `coraza_waf`
protection as CatWAF's main WAF block. The result is validated with
`caddy validate` in a temp file **before** anything real is touched; on
success the previous Caddyfile is backed up and the new one is swapped in
atomically. On failure, nothing is written — the previous configuration is
left exactly as it was.

CatWAF never modifies, stops, or exposes a discovered container. If a
container already publishes its web port directly to the host, that path
still bypasses the WAF — `catwaf auto` flags this and lets you decide whether
to stop publishing it yourself.

If Docker isn't reachable (not installed, daemon down, or permission denied),
`catwaf auto` fails gracefully with a clear message and a non-zero exit code.

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

## Configure

Every switch the dashboard exposes is reachable from the CLI, from the same
schema, with the same validation and the same safety net: a change is written,
rendered into the Caddyfile, validated by Caddy, and only then applied. If the
result would not load, the previous configuration is kept.

### `catwaf settings`
```
catwaf settings                             # list every group
catwaf settings <group>                     # show one group's current values
catwaf settings <group> --verbose           # ...with help text for each field
catwaf settings <group> field=value ...     # change one or more fields
catwaf settings <group> --preview field=v   # show the Caddyfile diff, apply nothing
catwaf settings <group> --reset [--yes]     # restore this group's defaults
catwaf settings <group> --json              # machine-readable
```

Values are typed by the schema, and a value that does not fit its type is
refused rather than coerced — storing the string `"false"` for a switch is
worse than an error message:

| Type | Accepted |
|---|---|
| switch | `true` / `false`, `yes` / `no`, `on` / `off`, `1` / `0` |
| number | a whole number |
| list | comma- or space-separated, e.g. `allowed_methods=GET,POST,HEAD` |
| choice | one of the values the schema lists |
| text | anything, subject to the field's own validation |

Fields holding structured rows (redirect rules, error pages, community list
sources) are refused here and point you at the dashboard or a template — a
half-expressed row is not something the command line can safely write.

Secrets are write-only. They can be set from the CLI but are never printed
back; a group listing shows `(set)` or `(not set)` instead.

```
$ catwaf settings access reject_unknown_host=true known_hosts=example.com
✓ access updated: reject_unknown_host, known_hosts

$ catwaf settings challenge --preview mode=javascript
--- current Caddyfile
+++ proposed Caddyfile
@@ -14 +14 @@
 example.com {
+    forward_auth 127.0.0.1:8000 {
+        uri /api/enforce
...
Nothing was applied — drop --preview to make this change.
```

A setting that is switched on but could not be written — because the installed
Caddy build lacks the module it needs — is reported after the change rather
than silently doing nothing:

```
$ catwaf settings proxy cache_enabled=true
✓ proxy updated: cache_enabled
  ! Response caching is not in effect: the installed Caddy has no cache handler.
```

`catwaf doctor` reports the same thing, along with everything the installed
Caddy build can and cannot do.

### `catwaf bans`
```
catwaf bans [list]                          # every address currently refused
catwaf bans list --source bad_behavior      # only one source
catwaf bans list --include-expired
catwaf bans add <ip|cidr> [--minutes N] [--reason "..."]
catwaf bans lift <ip|cidr> [--source <s>]
catwaf bans clear [--yes]
```

This is the unified ban store. Behavioural banning, DNSBL hits, the challenge
gate, community lists, the threat feed and the shared threat network all write
here, so "why is this visitor blocked, and how do I let them back in" has one
answer rather than one per feature.

Omitting `--minutes` makes the ban permanent. CatWAF refuses a range covering
the address you are connected from — banning it would lock you out.

Your manual IP blocklist (`catwaf config`, and the dashboard's IP Blacklist) is
separate, permanent and operator-curated. Nothing here changes it, including
`clear`.

### `catwaf template`
```
catwaf template [list]
catwaf template show <id>
catwaf template save "<name>" [--description "..."] [--no-waf]
catwaf template apply <id> [--dry-run] [--yes]
catwaf template remove <id>
```

A template is a set of settings captured together. Applying one rewrites
several groups at once, so `apply` always prints the diff and asks before
doing anything — `--dry-run` prints the diff and stops.

```
$ catwaf template apply hardened-public-site --dry-run

"hardened-public-site" would change 9 setting(s)

  headers.preset
    "off" → "strict"
  access.enforce_method_allowlist
    false → true
  ...

Nothing was applied.
```

## Operate the protection layer

### `catwaf jobs`
```
catwaf jobs [list]                # every job, its interval and last run
catwaf jobs run <name>            # run one now, regardless of its schedule
```

One scheduler drives list refreshes, ban expiry, backups, certificate checks
and telemetry. A job whose feature is switched off is listed but never
scheduled, which makes this the answer to "is that actually running?".

### `catwaf cache`
```
catwaf cache [list]               # namespaces, entry counts and sizes
catwaf cache clear <namespace>    # "all" empties every namespace
catwaf cache refresh <namespace>  # rebuild one now
```

Every namespace is rebuildable, so clearing one is safe. The cost is that the
next request needing that data pays for the lookup again — for the DNS-based
checks that means a visible pause on the first request from an address.

### `catwaf backup`
```
catwaf backup [list]
catwaf backup now [--dry-run] [--destination <dir>]
catwaf backup verify [--destination <dir>]
```

Set a destination first:

```
catwaf settings backups destination=/var/backups/catwaf enabled=true
```

Backups are written to a temporary file and renamed, so an interrupted backup
never leaves a truncated file that looks complete. Retention counts JSON
manifests; each manifest's sibling `.db` is pruned with it so the two cannot
drift apart.

### `catwaf report`
```
catwaf report --from 2026-01-01 --to 2026-02-01 [--format csv]
catwaf report --format html --out /tmp/january.html
catwaf report --format json
```

| Format | Contents |
|---|---|
| `csv` | Summary totals, categories, severities, top addresses and countries (default) |
| `events-csv` | One row per logged request in the range |
| `html` | A printable report |
| `json` | The whole report as structured data |

Without `--out` the report goes to stdout, so it pipes.

### `catwaf 2fa`
```
catwaf 2fa [status] [--user <u>]
catwaf 2fa enroll --user <u>
catwaf 2fa confirm <code> --user <u>
catwaf 2fa disable --user <u> [--yes]
catwaf 2fa codes --user <u>
```

`--user` may be omitted when there is exactly one admin account.

Enrollment is two steps on purpose. `enroll` generates the secret and the
`otpauth://` URI; nothing is enforced until `confirm` proves the authenticator
app is working, because enrolling without that check is how people lock
themselves out.

`confirm` prints ten recovery codes once and never again — they are stored as
HMACs, so the output cannot be reproduced later. Each works exactly once.
`codes` issues a fresh set and invalidates the previous one.

The code used to confirm enrollment is spent by that confirmation: it cannot
then be used to log in for the rest of its 30-second window.

```
$ catwaf 2fa enroll --user admin

Two-factor enrollment — admin

  Secret                    IHE2XI5YL2L3ZSO6Z6QOBIZBUERJOB25
  Digits / period           6 / 30s

  Add this URI to your authenticator app:
  otpauth://totp/CatWAF%3Aadmin?secret=IHE2XI5YL2L3ZSO6Z6QOBIZBUERJOB25&issuer=CatWAF&...

  Nothing is enforced yet. Prove the app works first:
  catwaf 2fa confirm <code> --user admin
```

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
