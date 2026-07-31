# docker/TestApp.Dockerfile — the INTENTIONALLY VULNERABLE local-only test app.
#
# Exists solely to prove the WAF in front of it actually blocks traffic.
# docker-compose.yml gives this service NO published ports, so it is reachable
# only from inside the compose network, via Caddy + Coraza.
#
# Do not publish this container. Do not deploy it anywhere reachable.

FROM node:22-alpine

WORKDIR /app
COPY test/testapp/server.js ./server.js

ENV TEST_APP_PORT=8080
# 0.0.0.0 is required for the sibling Caddy container to reach it across the
# compose network. Safe here ONLY because the service publishes no ports.
ENV TEST_APP_HOST=0.0.0.0

USER node
EXPOSE 8080
CMD ["node", "server.js"]
