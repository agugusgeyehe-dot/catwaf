#!/usr/bin/env bash
# verify-live.sh — prove CatWAF is actually in the request path for a live
# Docker fixture. Web-server agnostic: it works for the nginx fixture, the
# Apache fixture, and anything added later, because it asks CatWAF which
# endpoint belongs to which container rather than assuming.
#
# Run AFTER `catwaf auto` (or `catwaf start`).
#
#   ./test/fixtures/verify-live.sh <compose-project> <compose-service> <container-name>
#
#   nginx  fixture:  ./test/fixtures/verify-live.sh fake-web  nginx  freshmart_nginx
#   Apache fixture:  ./test/fixtures/verify-live.sh booknook  apache booknook_apache
#
# This does not trust CatWAF's own report. It sends real traffic through the
# protected endpoint and inspects the APPLICATION'S OWN access log to confirm
# a blocked request never reached it.
#
#   1. benign request   -> must be 200 and served by the app
#   2. CRS SQLi payload -> must be blocked
#   3. CRS XSS payload  -> must be blocked
#   4. the app's access log must NOT contain the blocked requests
#   5. benign request again -> must still be 200
#   6. show the WAF log entries
#
# The payloads are the standard inert OWASP CRS detection signatures used
# throughout this repo's tests, sent only to the local fixture.

set -euo pipefail

PROJECT="${1:?usage: verify-live.sh <compose-project> <compose-service> <container-name>}"
SERVICE="${2:?missing compose service}"
CONTAINER="${3:?missing container name}"

# Override to run against a checkout rather than an installed CLI:
#   CATWAF="node bin/catwaf.js" ./test/fixtures/verify-live.sh ...
CATWAF="${CATWAF:-catwaf}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
dim()   { printf '\033[2m%s\033[0m\n' "$*"; }

fail_count=0
check() {
  if [ "$2" = "true" ]; then green "  ok   $1"; else red "  FAIL $1 ${3:-}"; fail_count=$((fail_count + 1)); fi
}

if ! command -v jq >/dev/null 2>&1; then
  red "jq is required to read CatWAF's JSON output. Install jq and re-run."
  exit 2
fi

echo "== locating the protected endpoint for '${CONTAINER}' =="
AUTO_JSON="$($CATWAF auto --json --no-verify 2>/dev/null || true)"
PORT="$(printf '%s' "$AUTO_JSON" | jq -r --arg c "$CONTAINER" '.routes[]? | select(.containerName==$c) | .listenPort' | head -1)"
UPSTREAM="$(printf '%s' "$AUTO_JSON" | jq -r --arg c "$CONTAINER" '.routes[]? | select(.containerName==$c) | .upstream' | head -1)"
SERVER="$(printf '%s' "$AUTO_JSON" | jq -r --arg c "$CONTAINER" '.containers[]? | select(.containerName==$c) | .webServer' | head -1)"
RUNTIME="$(printf '%s' "$AUTO_JSON" | jq -r --arg c "$CONTAINER" '.containers[]? | select(.containerName==$c) | .runtime' | head -1)"

if [ -z "$PORT" ] || [ "$PORT" = "null" ]; then
  red "CatWAF reports no protected route for ${CONTAINER}. Run \`catwaf auto\` first."
  printf '%s\n' "$AUTO_JSON" | head -40
  exit 1
fi
dim "  web server         : ${SERVER:-unknown}"
dim "  runtime            : ${RUNTIME:-unknown}"
dim "  protected endpoint : http://127.0.0.1:${PORT}"
dim "  upstream           : ${UPSTREAM}"

MARK="catwaf-live-$(date +%s)-$$"

echo
echo "== 1. benign request through CatWAF =="
BODY_FILE="$(mktemp)"
CODE="$(curl -s -o "$BODY_FILE" -w '%{http_code}' "http://127.0.0.1:${PORT}/?probe=${MARK}-benign" || echo 000)"
BODY="$(cat "$BODY_FILE")"; rm -f "$BODY_FILE"
check "benign request returns 200" "$([ "$CODE" = "200" ] && echo true || echo false)" "(got $CODE)"
check "response came from the application" \
  "$(printf '%s' "$BODY" | grep -qiE 'freshmart|booknook' && echo true || echo false)"
check "PHP executed (not served as source)" \
  "$(printf '%s' "$BODY" | grep -q '<?php' && echo false || echo true)"

echo
echo "== 2. OWASP CRS payloads through CatWAF =="
SQLI="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/?probe=${MARK}-sqli&id=1+UNION+SELECT+1,2,3--" || echo 000)"
check "SQLi payload is blocked (403)" "$([ "$SQLI" = "403" ] && echo true || echo false)" "(got $SQLI)"

XSS_FILE="$(mktemp)"
XSS="$(curl -s -o "$XSS_FILE" -w '%{http_code}' "http://127.0.0.1:${PORT}/?probe=${MARK}-xss&q=%3Cscript%3Ealert(1)%3C/script%3E" || echo 000)"
XSS_BODY="$(cat "$XSS_FILE")"; rm -f "$XSS_FILE"
check "XSS payload is blocked (403)" "$([ "$XSS" = "403" ] && echo true || echo false)" "(got $XSS)"
check "XSS payload was never reflected" \
  "$(printf '%s' "$XSS_BODY" | grep -q '<script>alert(1)</script>' && echo false || echo true)"

echo
echo "== 3. the application never received the blocked requests =="
sleep 1
APP_LOG="$(docker compose -p "$PROJECT" logs --no-log-prefix "$SERVICE" 2>/dev/null \
  || docker logs "$CONTAINER" 2>&1 || true)"
check "app log shows the benign request" \
  "$(printf '%s' "$APP_LOG" | grep -q "${MARK}-benign" && echo true || echo false)"
check "app log does NOT show the SQLi request" \
  "$(printf '%s' "$APP_LOG" | grep -q "${MARK}-sqli" && echo false || echo true)"
check "app log does NOT show the XSS request" \
  "$(printf '%s' "$APP_LOG" | grep -q "${MARK}-xss" && echo false || echo true)"

echo
echo "== 4. normal traffic still works after the blocks =="
AFTER="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" || echo 000)"
check "benign request still returns 200" "$([ "$AFTER" = "200" ] && echo true || echo false)" "(got $AFTER)"

echo
echo "== 5. rerunning catwaf auto keeps the same endpoint =="
$CATWAF auto >/dev/null 2>&1 || true
PORT2="$($CATWAF auto --json --no-verify 2>/dev/null | jq -r --arg c "$CONTAINER" '.routes[]? | select(.containerName==$c) | .listenPort' | head -1)"
check "endpoint did not move" "$([ "$PORT2" = "$PORT" ] && echo true || echo false)" "(was $PORT, now $PORT2)"

echo
echo "== 6. CatWAF / Coraza log entries =="
$CATWAF audit --last 30m --limit 5 2>/dev/null | sed -n '1,20p' || dim "  (catwaf audit unavailable)"

echo
if [ "$fail_count" -eq 0 ]; then
  green "PROTECTED: traffic traverses CatWAF, attacks are blocked before ${CONTAINER}."
  exit 0
fi
red "NOT PROTECTED: $fail_count check(s) failed. See above."
exit 1
