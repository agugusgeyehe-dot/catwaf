# Security

CatWAF is a security product, so this document describes what it actually protects, what
it does not, and how it handles the sensitive material you give it. It avoids claims that
cannot be backed up.

## What CatWAF protects, and what it does not

CatWAF inspects HTTP requests to your site through Coraza running the OWASP Core Rule Set,
and blocks what matches. That is the whole of the protection it provides.

It does **not** make the application behind it secure. A WAF is a filter in front of your
code, not a substitute for fixing your code. `catwaf security-test` assesses *CatWAF's own*
deployment posture — bind addresses, secret strength, file permissions, proxy trust — and
says nothing about the application it is protecting.

## Reporting a vulnerability

Open a private security advisory on the repository, or email the maintainer listed in
`package.json`. Please include a description, affected version (`catwaf version`), and a
reproduction. Do not open a public issue for an unpatched vulnerability.

## Secrets

**Where secrets live.** All secrets are in `.env` in the installation directory. Nothing
sensitive is stored in the SQLite database except password hashes (bcrypt, cost 12).

| Secret | Purpose | Created by |
|---|---|---|
| `JWT_SECRET` | Signs dashboard session tokens | Generated at setup — 32 random bytes |
| Admin password hash | Dashboard login | bcrypt, cost 12, in the database |
| `CF_API_TOKEN` | Cloudflare API access (optional) | You supply it |

**Permissions.** `.env` is written mode `600` and owned by the service account. The
installer writes it under `umask 077`, so it is never briefly world-readable between
creation and `chmod`. CatWAF warns at startup if `.env` is group- or world-readable.

**What is never logged.** The request logger records method, path, status and duration
only. Request bodies, cookies and `Authorization` headers are never captured, so they
cannot appear in the database or in log files. Query parameters are redacted in
`catwaf explain` output. The Cloudflare token travels in a request body and is therefore
never logged.

**Admin passwords.** Setup reads the password from the `CATWAF_ADMIN_PASSWORD`
environment variable rather than a flag, because a flag would be visible in your shell
history and in `ps` output for the lifetime of the process. There are no default
accounts — until you create one, there is nothing to log into. Minimum length is 8
characters. Changing a password invalidates every existing session for that account.

## Network exposure

**Default bindings.** The API binds `127.0.0.1:8000`. It is meant to sit behind Caddy,
which terminates TLS and proxies to it. Do not bind it to `0.0.0.0` unless something else
is restricting access to it.

**Caddy's admin API (port 2019)** is how CatWAF reloads configuration in containers. In
`docker-compose.yml` it stays on the internal network and is deliberately **not**
published to the host. Exposing it is equivalent to handing over control of your reverse
proxy.

**No Docker socket.** CatWAF does not mount or use `/var/run/docker.sock`. Socket access
is effectively root on the host — the wrong trade for a security product. Caddy is
reloaded either through the local `caddy` binary or through Caddy's admin API.

## API security

Requests to `/api/*` must satisfy all of the following:

1. **A rotating path segment.** The real API lives under `/g/<segment>/api/...`, where the
   segment is an HMAC of the current 15-minute window. Requests to `/api/...` directly
   receive a decoy 404. This is obscurity, not a control — it raises the cost of
   untargeted scanning and nothing more. The controls below are what actually enforce
   access.
2. **A bearer token.** A signed JWT (HS256), re-validated against the live user store on
   every request, so a deleted account, a demoted admin, or a session predating a password
   reset loses access immediately rather than at token expiry. Tokens are accepted in the
   `Authorization` header only — never in a query string.
3. **A request signature.** HMAC over method, path, timestamp, nonce and body hash, with a
   2-minute clock-skew window and nonce replay rejection.
4. **A role.** Every state-changing endpoint requires the `admin` role.

Rate limits apply to both gated and ungated paths. Login attempts are limited per
IP-and-username **and** per account, so a client that controls its `X-Forwarded-For`
header (direct exposure without a reverse proxy) still faces a cumulative budget per
targeted username.

A note on trust boundaries: the enforcement and upload-scan hops derive the visitor's
address from `X-Real-IP` / `X-CatWAF-Client-IP`, which the generated Caddyfile always
overwrites with the real connection address before anything reaches the backend. If you
put your own proxy in front of CatWAF's API port, it must do the same — do not forward
client-supplied versions of those headers untouched.

How many forwarded hops CatWAF trusts is inferred unless you set `TRUST_PROXY_HOPS`
explicitly: 1 when DOMAIN or CATWAF_HTTPS indicates a proxied deployment, 0 otherwise.
On a direct deployment (dashboard on `localhost:8000`, a bare LAN port) forwarded
headers are ignored entirely — a client cannot forge its way past rate limiting or IP
checks by inventing them. If you front the API with your own proxy without setting
DOMAIN, set `TRUST_PROXY_HOPS=1`.

## Kernel-level drops (opt-in)

The nftables mirror runs only when BOTH the setting is enabled and
`CATWAF_KERNEL_BANS=1` is set in `.env`, and refuses to run in containers or
without root. CatWAF creates and fills exactly one table (`inet catwaf_edge`)
and deletes/recreates it atomically per refresh — it never touches any other
firewall rule. The forwarding rule that makes the kernel consult the set is
applied by you, as root, from `catwaf kernel-bans print-rules` output.

## Update check

`catwaf update`, the dashboard diagnostics and a daily background job perform
one HTTPS GET to `api.github.com/repos/agugusgeyehe-dot/catwaf/releases/latest`.
No telemetry, no identifiers beyond your IP as seen by GitHub, response cached
for 24h. Read-only: nothing is downloaded or installed. If the repository has
no releases yet the check reports that instead of an error.

## Backup encryption

With `backups.encrypt` enabled, manifests and database copies are written as
AES-256-CBC (PBKDF2, 200k iterations) via the system `openssl`. The passphrase
comes from `CATWAF_BACKUP_PASSPHRASE` in `.env` and is deliberately NOT stored
in the database — a backup decryptable by whatever it protects would not be a
backup. Lose the passphrase and the backups are gone; that is the deal.

## Concurrent configuration writers

The API server, the `catwaf` CLI and scheduled jobs can all change WAF configuration.
Every mutation path serializes through one lock file in the data directory
(`data/config.lock`), re-reads committed state before applying its change, and writes
the Caddyfile atomically. A crashed holder's lock is broken automatically; you should
never need to touch the file by hand.

## GeoIP data

CatWAF uses [`geoip-lite`](https://www.npmjs.com/package/geoip-lite), which bundles a
converted **MaxMind GeoLite2** database.

- **Licensing.** GeoLite2 data is distributed by MaxMind under the
  [Creative Commons Attribution-ShareAlike 4.0](https://creativecommons.org/licenses/by-sa/4.0/)
  license and MaxMind's
  [GeoLite2 End User License Agreement](https://www.maxmind.com/en/geolite2/eula).
  If you redistribute CatWAF or a product containing this data, those terms apply to you.
  This product includes GeoLite2 data created by MaxMind, available from
  [maxmind.com](https://www.maxmind.com).
- **Disk footprint.** Roughly 150 MB. On a Lite install it is the single largest component.
- **Accuracy.** City-level geolocation is approximate and should be treated as a hint, not
  as evidence. Do not make blocking decisions on it that you would not be comfortable
  defending.
- **Updates.** The bundled database ages. Refreshing it requires a MaxMind license key —
  see the `geoip-lite` documentation.
- **Private addresses are never geolocated.** RFC 1918 space, loopback, link-local, CGNAT,
  benchmarking, multicast and IPv6 ULA/link-local addresses are excluded, including when
  written as IPv4-mapped IPv6 (`::ffff:10.0.0.1`). An address that cannot be resolved is
  stored as `NULL` and does not appear on the Attack Map. CatWAF does not fabricate
  coordinates to fill in a map.

## Installer trust model

The installer is a shell script that runs as root. Understand what that means before
running it.

**Recommended — download, read, then run:**

```bash
curl -fsSLo setup.sh https://raw.githubusercontent.com/agugusgeyehe-dot/catwaf/main/setup.sh
less setup.sh
sudo bash setup.sh --lite
```

**The one-line form** (`curl … | sudo bash`) is supported but is not the recommendation.
Piping into a root shell means trusting, sight unseen: GitHub, the TLS chain, DNS
resolution at that moment, and every future change to that file. HTTPS authenticates the
transport — it says nothing about whether the content is what you expected. There is no
step at which you can inspect what is about to run as root.

What the installer itself does:

- runs with `set -euo pipefail`, quotes every variable, and never uses `eval`
- fetches the NodeSource and Ollama scripts **to a file** and executes them explicitly,
  rather than piping them into a shell, so a failed download cannot become a partial
  execution
- pins `--proto '=https' --tlsv1.2` on downloads
- writes secrets under `umask 077`
- creates a dedicated non-login `catwaf` system account and never runs the service as root
- refuses to overwrite a non-empty directory that is not a CatWAF checkout
- validates every argument — `--yes` suppresses prompts, never validation

It does not verify a signature or checksum on the Node and Ollama installers it fetches;
it inherits the trust model of those upstream projects.

## systemd hardening

The generated unit runs as the `catwaf` account with `NoNewPrivileges=true`,
`ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `RestrictSUIDSGID`,
`RestrictNamespaces`, `LockPersonality`, and write access limited to the data directory.

Interactive `catwaf setup` installs the same hardened unit when run as root — including
the dedicated service account and its `.env` ownership — so re-running setup can never
downgrade a hardened install to a root-running, unsandboxed one.

CatWAF Lite installs no API service at all. If you convert a Full install to Lite, the
existing unit is disabled and removed rather than left to fail on every boot.

## Docker

- No Docker socket is mounted.
- Caddy's admin API is not published to the host.
- Containers run with `no-new-privileges:true`.
- The test app in `docker-compose.yml` is intentionally vulnerable and has no `ports:`
  entry — it is reachable only through Caddy and Coraza. Do not expose it.
- `catwaf docker` validates subcommands against an allowlist and builds its argument
  vector from constants. It runs `docker compose`, which requires access to the Docker
  daemon; anyone who can run it can already control containers on that host.

## Updates

Re-run `setup.sh`, or `git pull && npm install && catwaf setup --<edition>`. Both are
idempotent and preserve your configuration, database, rules and accounts. Check
`CHANGELOG.md` before updating — security fixes are listed under a **Security** heading in
each release.

## Dependency posture

Advisories with a non-breaking fix are taken. Two in 1.0.2:

- **`js-yaml` quadratic CPU consumption in `!!omap` resolution** (GHSA-5p4m-2wfm-xmqj) —
  upgraded to 4.3.1. It was not reachable with hostile input: the only `yaml.load()` call
  is in `services/catai/retrieval.js`, parsing the frontmatter of the knowledge-base files
  shipped inside the repository. Patched anyway, because the fix cost nothing.
- **`nanoid`** (transitive, via the frontend build toolchain) — upgraded to 3.3.18.

After those, `npm audit` reports advisories in two remaining transitive dependencies.
Both were assessed for reachability rather than upgraded blindly, because in both cases
the available "fix" is worse than the finding:

- **`geoip-lite` → `rimraf`/`glob`/`minimatch`/`brace-expansion`, and `ip-address`.**
  These are reached only from `geoip-lite`'s `scripts/updatedb.js`, the database updater.
  CatWAF calls `geoip.lookup()` from `lib/geoip.js` and never invokes the updater. The
  advised fix (`npm audit fix --force`) downgrades `geoip-lite` to 1.2.2, which is older
  and not an improvement.
- **`react-router` open redirect and `deserializeErrors` constructor injection.**
  The dashboard is a pure client-side SPA with no server-side rendering or hydration, so
  `deserializeErrors` is never called. Every `navigate()` and `<Link to>` target in the
  codebase is a hardcoded constant, so there is no user-controlled navigation to redirect.
  No fixed 6.x release exists — the project is already on 6.30.4, the latest of that line —
  and the only remediation is a major upgrade to React Router 7, which is not appropriate
  in a patch release.

Both are re-checked each release, and were re-checked for 1.0.2. If either becomes
reachable, it will be fixed rather than re-documented.
