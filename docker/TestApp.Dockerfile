# docker/TestApp.Dockerfile — the INTENTIONALLY VULNERABLE local-only test app.
#
# Exists solely to prove the WAF in front of it actually blocks traffic. It is
# the origin behind CatWAF's protected site: public traffic reaches it on :80
# through Caddy + Coraza, never directly.
#
# docker-compose.yml publishes it on 127.0.0.1:8082 ONLY — that is the origin
# port, addressable from the host so you can inspect it and demonstrate the
# difference between going through the WAF and going around it. A request that
# arrives on 8082 is NOT inspected.
#
# Never widen that bind past loopback, and never deploy this anywhere
# reachable from a network you do not control.

FROM node:22-alpine

WORKDIR /app
COPY test/testapp/server.js ./server.js

# The internal application port. Unchanged by the :8082 origin convention:
# Caddy dials this over the compose network (`reverse_proxy test-app:8080`),
# and only the host mapping in docker-compose.yml says 8082.
ENV TEST_APP_PORT=8080
# 0.0.0.0 is required for the sibling Caddy container to reach it across the
# compose network. Safe here ONLY because the service's single host mapping in
# docker-compose.yml binds 127.0.0.1.
ENV TEST_APP_HOST=0.0.0.0

USER node
EXPOSE 8080
CMD ["node", "server.js"]
