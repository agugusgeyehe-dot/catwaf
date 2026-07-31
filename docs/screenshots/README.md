# Screenshots and demo assets

**Nothing in this directory is generated or faked.** These are the captures the
README wants, with exact steps to produce each one from a real running CatWAF.
Until a file exists here, the README simply does not show it.

## How to get a real system to capture

```bash
# terminal 1 - the local-only vulnerable test app
TEST_APP_PORT=9080 TEST_APP_HOST=127.0.0.1 node test/testapp/server.js

# terminal 2 - Caddy + Coraza in front of it, with CatWAF's WAF block applied
catwaf setup --full --admin-user admin --yes   # CATWAF_ADMIN_PASSWORD=...
catwaf start
caddy run --config ./Caddyfile

# terminal 3 - generate real traffic
curl "http://127.0.0.1:8081/"                              # allowed
curl "http://127.0.0.1:8081/?id=1+UNION+SELECT+1,2,3--"    # blocked
curl -A "sqlmap/1.0" "http://127.0.0.1:8081/"              # blocked
```

Events appear in the dashboard within ~5 seconds (the audit-log ingest interval).

## Still to capture

| File | What it should show |
|---|---|
| `dashboard.png` | Dashboard after the traffic above — real request counts, real blocked count, paranoia level, recent events |
| `waf-status.png` | Engine Mode page showing Blocking / Detection Only / Off |
| `blocked-request.png` | A single blocked event expanded: rule ID, severity, attack type, reason |
| `logs.png` | The events list with a mix of allowed and blocked traffic |
| `configuration.png` | Paranoia Levels page with the active level highlighted |
| `cli-setup.png` | A terminal running `catwaf setup --full` through to completion |
| `doctor.png` | A terminal running `catwaf doctor` |

## Demo GIF (`demo.gif`)

15-30 seconds, no fake traffic. Suggested beats:

1. `catwaf setup --lite ...` completing (~4s)
2. `catwaf doctor` showing green (~3s)
3. `catwaf start` (~2s)
4. `curl` of a normal request returning 200 (~2s)
5. `curl` of the SQL-injection pattern returning 403 (~3s)
6. Cut to the dashboard showing that exact event appear (~5s)

Record with `asciinema` for the terminal portion, or any screen recorder for the
combined terminal + browser cut. Keep it under 5 MB so GitHub renders it inline.

## Rules for anything added here

- Real screenshots of a real running instance only.
- No mocked data, no edited numbers, no composites.
- If a panel is empty because nothing has happened yet, show it empty - that is
  what a new install actually looks like.
