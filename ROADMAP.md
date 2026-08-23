# Roadmap

CatWAF already does a lot — the goal from here isn't to add more features, it's to make the ones that exist solid enough that someone can trust them on a real site. Roughly in order:

## Shipped in 1.0.2

- [x] **The configuration and protection layer** — roughly 300 settings across 40 groups behind one declarative schema, and a client-reputation layer that decides about a *client* before the rule engine inspects the *request*. All of it opt-in.
- [x] **Optional upload malware scanning** — a local ClamAV daemon, off by default, in the data path only for the upload paths you nominate.
- [x] **Release hardening** — sign-out actually ends the session, the dashboard works from an address other than the one it was set up on, and a stopped CatWAF API no longer takes every protected site down with it.
- [x] Fixed `guardedFetch` dropping the request body, which had silently emptied every outbound POST — including captcha verification, so an enabled challenge gate locked out legitimate visitors.

## Shipped in 1.0.1

- [x] **CatWAF Lite and Full** — a real, persisted, enforced edition model. Lite installs no frontend dependencies at all and runs no HTTP server; Full adds the API, dashboard and Attack Map. `catwaf setup --full` converts in place without losing configuration or data.
- [x] **`setup.sh`** — the installer the README had pointed at since the first public release but which was never committed. Distro detection, Lite/Full menu, non-root service account, hardened systemd unit, idempotent re-runs.
- [x] **`catwaf docker`** — allowlisted stack management, Full only.
- [x] **Attack Map** — real GeoIP-derived locations only; unresolvable sources are never plotted.
- [x] Version numbering normalised to a single public `1.x` line across every manifest, badge, spec and image label.
- [x] Full security review of every file; findings and their reachability analysis recorded in [SECURITY.md](SECURITY.md) and the changelog.
- [x] [SECURITY.md](SECURITY.md) — secret handling, exposure, installer trust model, GeoIP licensing.

## Shipped in 1.0.0

- [x] CatAI — a local assistant that answers from a real knowledge base and carries out changes safely (see [docs/catai.md](docs/catai.md))
- [x] Self-lockout guard on IP blocking — you can no longer blacklist your own address
- [x] Audited every documented endpoint and page against what actually ships; removed the claims that had drifted
- [x] Operator tooling: `explain`, `simulate`, `replay`, `rules`, `audit`, `mode`, `paranoia`, `health`, `security-test`, `diff`, `config` snapshots
- [x] Removed the Docker socket dependency entirely

## BunkerWeb parity — where this actually stands

Checked against BunkerWeb's feature list rather than guessed at. Most of the
gap someone would expect from the comparison is already closed:

- [x] **DNSBL** — `services/intel/dnsbl.js`, multi-zone, cached per address
      *and* per zone, fails open on timeout.
- [x] **Antibot** — cookie, JavaScript proof-of-work, CatWAF's own generated
      captcha, plus reCAPTCHA / hCaptcha / Turnstile / mCaptcha.
- [x] **Auto-ban on bad status codes** — `services/behavior.js`, counted off
      the request log rather than on the request path, with escalation for
      repeat offenders.
- [x] **Upload malware scanning** — optional ClamAV module, off by default.
      The one feature that puts CatWAF in the data path, and only for the
      upload paths you nominate. See [docs/protection.md](docs/protection.md).

Deliberately not copied:

- **Per-site challenge selection.** CatWAF Free protects one site — an edition
  boundary `sites.capacity()` enforces, not an oversight. Per-site config only
  becomes meaningful if that boundary moves.
- **A code-executing plugin ecosystem.** Plugins stay data-only. Reviewing and
  being liable for arbitrary third-party code running inside a WAF is not a
  reasonable position for a solo maintainer. Integrations that are actually
  wanted (webhooks, chat notifications) belong in the backend, the same way
  upload scanning does.
- **Kubernetes / Helm / multi-DB.** Real engineering investments with no user
  asking for them yet. Revisit when someone hits the wall, not before.

## Outstanding

- [ ] Real screenshots/GIFs in the README — there are none right now, just the logo
- [ ] A short demo video
- [ ] **Extend test coverage to the route handlers.** What exists is deep on two subsystems
  and absent everywhere else — most of `backend/routes/` still has no automated test at
  all. Smoke tests hitting each router would catch the stale-reference class of bug
  automatically.
- [ ] Pass over every frontend page for consistent loading/error/empty states — some pages
  handle these better than others.
- [ ] `data/config_signature` and friends currently live in a generic key/value table —
  fine for now, but worth revisiting if the state surface keeps growing.
- [ ] A proper plugin/rule-pack system instead of hand-edited custom rules.
- [ ] Multi-node fleet management beyond the current view — nodes can now report a real
  heartbeat (`POST /api/nodes/:id/heartbeat`), so status reflects whether a node has
  actually checked in rather than a simulated flip, but there's still no real cross-node
  coordination (pushing config to a fleet, aggregating their stats, etc.)

## Explicitly not planned right now
Turning this into "the next Cloudflare." The plan is to keep it something one person can understand end to end, use daily, and be proud of — not to chase every feature a bigger product has. If that changes, it'll be because real usage made the case for it, not because a feature list said so.

Have an idea that's not here? Open an issue. The best additions to this list come from people actually using CatWAF and hitting a wall, not from guessing what might be useful.

## Shipped, pre-1.0 (internal `3.x-dev` line)

Numbered against an internal `3.x-dev` line that was never published — see
`CHANGELOG.md`'s pre-release history for the same convention. Kept here for provenance,
not because any of it is still outstanding.

- [x] Split `server.js` into `routes/` + `services/` (v3.0)
- [x] Fix the bugs that split turned up (see `CHANGELOG.md`)
- [x] Repo polish: README, docs, LICENSE, CONTRIBUTING, this file
- [x] Centralized logging + error handling (v3.1-dev)
- [x] Security score page (v3.1-dev)
- [x] Dockerfile + docker-compose for a one-command local stack (v3.1-dev)
- [x] OpenAPI/Swagger docs for the core endpoints (v3.1-dev)
- [x] Switch `services/caddy.js`'s reload mechanism from `docker exec` to Caddy's HTTP Admin API — the Docker socket mount is gone from `docker-compose.yml` entirely, and `caddy.js` contains no Docker calls (asserted by a test). See `docs/docker.md`.
- [x] Real user/credential management — `catwaf user list|add|remove|passwd|role` plus `/api/users` endpoints, with server-side authorization, bcrypt hashing, and last-admin protection.
- [x] A real test suite — `test/security.test.js` and `test/catai.test.js` now cover the request-signing scheme end to end and the whole deterministic half of CatAI, with no network or Ollama required.
- [x] A frontend smoke test — `test/frontend-smoke.test.js` drives a real browser through login, the dashboard, and ten routes, and asserts server-side authorization. It immediately caught a CSP bug that made the backend-served dashboard unusable.
- [x] Replace the synthetic traffic generator (`services/traffic.js`) with real request logging, so the dashboard, TUI, and threat-hunting search reflect actual traffic instead of simulated data. `services/requestLog.js` ingests Coraza's own real audit log (`services/caddy.js` now writes `SecAuditLog`) into a real `request_log` table; `services/traffic.js`, `/api/stats`, `/api/traffic/*`, `/api/rules/heatmap`, and every TUI screen that used to show demo numbers now read from it. A fresh install with no real traffic yet honestly shows zeros, not a populated demo feed. Request body / cookie capture still isn't wired in (Coraza's audit log needs its `B` part enabled for that, which means logging real request bodies — a retention/PII question worth deciding deliberately rather than defaulting on).
- [x] Real IP reputation data — `services/ipIntel.js` checks Tor exit nodes and cloud-provider ranges for real with no API key needed (both are freely published), and calls the real AbuseIPDB/ipinfo.io APIs when `ABUSEIPDB_API_KEY`/`IPINFO_API_KEY` are configured. Without a key configured, those specific fields are honestly `null` rather than estimated — there's no free public source for abuse scoring or full geolocation, so this couldn't be made real without *some* external service, paid or not. GreyNoise integration would follow the same pattern but isn't built yet.
