#!/usr/bin/env bash
# End-to-end demo of the back-channel logout flow against the running stack
# (docker compose up, or the local processes).  Requires: curl, jq.
#
#   IDP_URL=http://localhost:9000 PORTAL1_URL=http://localhost:8001 \
#   PORTAL2_URL=http://localhost:8002 ./scripts/demo.sh
set -euo pipefail

IDP_URL="${IDP_URL:-http://localhost:9000}"
PORTAL1_URL="${PORTAL1_URL:-http://localhost:8001}"
PORTAL2_URL="${PORTAL2_URL:-http://localhost:8002}"

step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
json_post() { curl -sS -X POST "$1" -H 'content-type: application/json' -d "$2"; }

step "1. alice logs in (no delay) via portal1"
CODE=$(json_post "$IDP_URL/authorize" '{"sub":"alice","delay_seconds":0}' | jq -r .code)
LOGIN=$(json_post "$PORTAL1_URL/login" "{\"code\":\"$CODE\"}")
echo "$LOGIN" | jq .
ALICE_SESSION=$(jq -r .session_id <<<"$LOGIN")

step "2. the session is visible from BOTH portal replicas (shared SQLite state)"
echo "portal1 /me:"; curl -sS "$PORTAL1_URL/me" -H "Authorization: Bearer $ALICE_SESSION" | jq .
echo "portal2 /me:"; curl -sS "$PORTAL2_URL/me" -H "Authorization: Bearer $ALICE_SESSION" | jq .

step "3. alice is removed from the identity source -> logout JWT pushed to both replicas"
json_post "$IDP_URL/logout" '{"sub":"alice"}' | jq '{claims, deliveries}'

step "4. the old session is revoked on both replicas"
curl -sS -o /dev/null -w 'portal1 /me -> %{http_code}\n' "$PORTAL1_URL/me" -H "Authorization: Bearer $ALICE_SESSION"
curl -sS -o /dev/null -w 'portal2 /me -> %{http_code}\n' "$PORTAL2_URL/me" -H "Authorization: Bearer $ALICE_SESSION"

step "5. bob's login response is LATE (8s); logout lands while the exchange is in flight"
CODE=$(json_post "$IDP_URL/authorize" '{"sub":"bob","delay_seconds":8}' | jq -r .code)
BOB_RESULT=$(mktemp)
( json_post "$PORTAL1_URL/login" "{\"code\":\"$CODE\"}" >"$BOB_RESULT" ) &
LOGIN_PID=$!
sleep 2
LOGOUT=$(json_post "$IDP_URL/logout" '{"sub":"bob"}')
jq .claims <<<"$LOGOUT"
BOB_LOGOUT_TOKEN=$(jq -r .logout_token <<<"$LOGOUT")
echo "waiting for the late login response..."
wait "$LOGIN_PID"
echo "late login response (must be a 409 rejection, no session created):"
jq . <"$BOB_RESULT"
rm -f "$BOB_RESULT"

step "6. bob logs in again AFTER the logout (fresh iat) -> allowed"
CODE=$(json_post "$IDP_URL/authorize" '{"sub":"bob","delay_seconds":0}' | jq -r .code)
LOGIN=$(json_post "$PORTAL2_URL/login" "{\"code\":\"$CODE\"}")
echo "$LOGIN" | jq .
BOB_SESSION=$(jq -r .session_id <<<"$LOGIN")
curl -sS "$PORTAL1_URL/me" -H "Authorization: Bearer $BOB_SESSION" | jq .

step "7. duplicate logout notification (same jti) is a no-op and does not widen revocation"
json_post "$PORTAL1_URL/backchannel-logout" "{\"logout_token\":\"$BOB_LOGOUT_TOKEN\"}" | jq .
echo "bob's newer session still valid:"
curl -sS -o /dev/null -w 'portal1 /me -> %{http_code}\n' "$PORTAL1_URL/me" -H "Authorization: Bearer $BOB_SESSION"

step "8. out-of-order logout (iat 60s in the past, still valid) must not lower the persisted cutoff"
echo "cutoffs before:"; curl -sS "$PORTAL1_URL/debug/state" | jq .logout_cutoffs
json_post "$IDP_URL/logout" '{"sub":"bob","iat_offset_seconds":-60}' | jq '{claims, deliveries: (.deliveries | map_values(.response))}'
echo "cutoffs after (unchanged):"; curl -sS "$PORTAL1_URL/debug/state" | jq .logout_cutoffs
echo "bob's session still valid:"
curl -sS -o /dev/null -w 'portal1 /me -> %{http_code}\n' "$PORTAL1_URL/me" -H "Authorization: Bearer $BOB_SESSION"

step "demo finished"
