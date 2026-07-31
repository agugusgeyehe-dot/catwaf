# Docker

The Docker stack is part of **CatWAF Full**. CatWAF Lite does not install it, and
`catwaf docker` refuses to run there.

## Managing the stack with `catwaf docker`

```bash
catwaf docker up            # build if needed and start in the background
catwaf docker up --build    # force an image rebuild first
catwaf docker status        # each service and its state
catwaf docker logs -f       # stream logs from every service
catwaf docker restart
catwaf docker down          # stop and remove containers
catwaf docker build         # rebuild images without starting
```

These wrap `docker compose` against this repository's `docker-compose.yml`. The
subcommand is checked against a fixed allowlist and the argument vector is built
from constants, so nothing you type reaches a command line and no shell is
involved. Either the `docker compose` plugin or a standalone `docker-compose`
binary works; if neither is installed the command says which is missing and
exits `3`.

Running `docker compose` directly does exactly the same thing — `catwaf docker`
is a convenience, not a requirement.

> `catwaf docker` needs access to the Docker daemon. Anyone who can run it can
> already control containers on that host; it grants nothing new.

## Architecture

Three containers, matching how CatWAF already works outside Docker (see
[reverse-proxy.md](reverse-proxy.md) and [architecture.md](architecture.md)):

```
                     ┌─────────────────────────┐
   :80  ─────────────▶   caddy (dashboard +    │────▶ :8000  backend (API,
                     │   reverse proxy + WAF)  │              SQLite state)
   :8081 (protected) │                         │
   ───────────────────▶  demo-app (your real   │
                     │    application goes     │
                     └─── here instead) ────────┘
```

- **`backend`** — the Node API (`Dockerfile` at the repo root). Owns the
  SQLite database (`catwaf-data` volume) and writes WAF config changes into
  the shared Caddyfile.
- **`caddy`** (`docker/Caddy.Dockerfile`) — a Caddy binary built with the
  [Coraza module](https://github.com/corazawaf/coraza-caddy) baked in via
  `xcaddy`, serving the built dashboard SPA and running the actual WAF site
  block. Shares the `caddy-config` volume with `backend` so both containers
  see the same live Caddyfile.
- **`demo-app`** — a placeholder (stock `nginx:alpine`) so `docker compose
  up` gives you something to protect immediately, and so the README's curl
  checks have a target. Swap it for your real application — see below.

## Pointing this at your real application

Edit `docker/Caddyfile`'s second site block:

```caddyfile
:8081 {
    reverse_proxy demo-app:80
}
```

Two options:

- **Your app also runs in this compose file** — add it as another service,
  then change `demo-app:80` to `your-service-name:port`.
- **Your app runs elsewhere** (already deployed, a different host) — point
  at wherever it's actually reachable from the `caddy` container, e.g.
  `reverse_proxy host.docker.internal:3001` (Docker Desktop) or a real
  hostname/IP reachable from inside the container network.

After changing it, `docker compose restart caddy` (the file lives on the
shared `caddy-config` volume, so `backend`'s later WAF changes keep applying
to whichever site block CatWAF's own managed configuration block is already
in — same mechanism as the non-Docker setup, see
[reverse-proxy.md](reverse-proxy.md)).

## No Docker socket required

Earlier versions of CatWAF mounted the host's Docker socket
(`/var/run/docker.sock`) into the `backend` container so it could run
`docker exec catwaf-caddy caddy reload ...`. **That is gone.**

Docker socket access is effectively root-equivalent access to the host:
anything that can execute commands inside the backend container could, via
that socket, control every other container and in practice the host itself.
For a security product that was the wrong trade to ask anyone to make.

CatWAF now reloads Caddy over **Caddy's own HTTP admin API**:

- `caddy` listens on `0.0.0.0:2019` inside the compose network
  (see `docker/Caddyfile`).
- Port 2019 is deliberately **not** in the `caddy` service's `ports:` list,
  so it is reachable only from sibling containers, never from the host or
  the internet.
- `backend` is pointed at it with `CADDY_ADMIN_URL: http://caddy:2019`.
- `backend/services/caddy.js` prefers a local `caddy reload` when the binary
  is present (the normal non-Docker case) and falls back to `POST /load` on
  the admin API (the container case). It contains no Docker calls at all.

Both containers also run with `no-new-privileges:true`.

If you expose the admin API more widely than the compose network, secure it
yourself — Caddy's admin API is unauthenticated by design and assumes a
trusted local interface.

## Data & config persistence

Two named volumes:

- `catwaf-data` → `/app/data` in `backend` — the SQLite database.
- `caddy-config` → `/etc/caddy` in both `backend` and `caddy` — the live
  Caddyfile and Coraza list directory. Seeded from `docker/Caddyfile` the
  first time the volume is created (standard Docker behavior — an empty
  named volume mounted over a directory that has content in the image gets
  populated from that image directory once), and left alone after that, so
  your edits and CatWAF's applied WAF changes persist across
  `docker compose restart` / `down` / `up`.

To reset back to the baked-in default Caddyfile: `docker compose down -v`
(removes the volumes entirely, including your database — back it up first
via the dashboard's Snapshots feature if you want to keep your WAF config).

## Building without Compose

```bash
docker build -t catwaf-backend .
docker build -t catwaf-caddy -f docker/Caddy.Dockerfile .
```

Useful if you're integrating these images into an existing orchestration
setup rather than using this repo's compose file directly.
