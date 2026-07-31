# docker/Caddy.Dockerfile — builds a Caddy binary with the Coraza WAF module
# baked in, and serves the frontend's static build alongside it.
#
# Three responsibilities live in this one container, matching how the app
# already works outside Docker (see docs/reverse-proxy.md):
#   1. Serve the dashboard's built static files (the SPA)
#   2. Reverse-proxy /api to the backend container
#   3. Run the actual WAF site block(s) that protect your real application
#
# Why Caddy needs its own build stage: CatWAF is built specifically on
# Coraza (github.com/corazawaf/coraza-caddy), a native Go WAF module — not
# ModSecurity — and that module isn't part of Caddy's default build. It has
# non-Docker equivalent of this same step.

# ── Stage 1: build the frontend ──────────────────────────────────────────
FROM node:22-slim AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend ./
RUN npm run build
# Output: /app/frontend/dist

# ── Stage 2: build Caddy with the Coraza module ──────────────────────────
# caddy:builder is the official image for exactly this — it has Go and
# xcaddy preinstalled, so this stage is just "run the one command from
FROM caddy:2-builder AS caddy-build
RUN xcaddy build --with github.com/corazawaf/coraza-caddy/v2

# ── Stage 3: final runtime image ─────────────────────────────────────────
FROM caddy:2-alpine
COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy
COPY --from=frontend-build /app/frontend/dist /srv/dashboard
COPY docker/Caddyfile /etc/caddy/Caddyfile

# CORAZA_LIST_DIR in .env.example — a place for IP/UA lists Coraza reads
# directly (separate from the WAF directives block CatWAF's backend writes
# into the Caddyfile itself).
RUN mkdir -p /etc/coraza/lists

EXPOSE 80 443 8081

# Confirm the module actually made it into the binary at build time, not
# you to run by hand.
RUN caddy list-modules | grep -q http.handlers.waf
