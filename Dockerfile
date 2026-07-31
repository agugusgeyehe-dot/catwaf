# Dockerfile — CatWAF backend API.
#
# Node 22+ is required (not just recommended) because the backend uses the
# built-in `node:sqlite` module (see backend/services/db.js) — there's no
# separate database server to run, but this does mean the base image can't
# be downgraded to save size the way a lot of "just needs Express" Dockerfiles
# do.

FROM node:22-slim AS base
WORKDIR /app

LABEL org.opencontainers.image.title="CatWAF" \
      org.opencontainers.image.description="Web application firewall built on Caddy + Coraza + OWASP CRS" \
      org.opencontainers.image.version="1.0.1" \
      org.opencontainers.image.source="https://github.com/agugusgeyehe-dot/catwaf" \
      org.opencontainers.image.licenses="LicenseRef-PolyForm-Internal-Use-1.0.0"

# This image is the API server only. Caddy (with Coraza) and the built
# dashboard live in docker/Caddy.Dockerfile, so:
#   CATWAF_SKIP_CADDY_DOWNLOAD  stops postinstall fetching a Caddy binary that
#                               would never be executed here.
#   CATWAF_EDITION=full         this container provides the HTTP API. frontend/
#                               is deliberately not copied, and postinstall
#                               detects that and skips the dashboard install.
ENV CATWAF_SKIP_CADDY_DOWNLOAD=1 \
    CATWAF_EDITION=full

# Install backend dependencies first, separately from copying the rest of
# the source — Docker layer caching means `docker build` skips this step
# entirely on rebuilds where only application code changed, not package.json.
COPY package.json package-lock.json* ./
COPY scripts ./scripts
COPY backend/services/env.js ./backend/services/env.js
RUN npm install --omit=dev --omit=optional && npm cache clean --force

# Now the actual application code.
COPY backend ./backend

# Where the SQLite file and Caddy sync data live — created automatically at
# runtime if missing (see services/db.js), declared here so `docker volume`
# users have an obvious mount point without reading the source.
RUN mkdir -p /app/data
VOLUME ["/app/data"]

ENV NODE_ENV=production
ENV PORT=8000
EXPOSE 8000

# --experimental-sqlite is required until node:sqlite graduates out of
# experimental status — same flag package.json's own "dev:backend" script
# uses locally, kept consistent here.
CMD ["node", "--experimental-sqlite", "backend/server.js"]
