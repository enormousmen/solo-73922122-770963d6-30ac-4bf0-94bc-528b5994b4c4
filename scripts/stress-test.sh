#!/usr/bin/env bash
# Stress test: concurrent logins (some delayed) + concurrent logouts across
# both portal replicas must be equivalent to some serial execution.
# Invariant checked afterwards: no active session has id_token_iat <= the
# persisted logout cutoff of its sub or sid.
set -uo pipefail

IDP_URL="${IDP_URL:-http://127.0.0.1:9000}"
PORTALS=("http://127.0.0.1:8001" "http://127.0.0.1:8002")
N="${N:-12}"
TMP=$(mktemp -d)

login_flow() {  # $1=user index
    local i="$1" user="stress-$1" delay code portal resp
    delay=$(( (i % 3) * 2 ))   # 0, 2 or 4 seconds of simulated IdP latency
    code=$(curl -sS -X POST "$IDP_URL/authorize" -H 'content-type: application/json' \
           -d "{\"sub\":\"$user\",\"delay_seconds\":$delay}" | jq -r .code)
    portal="${PORTALS[$((i % 2))]}"
    resp=$(curl -sS -X POST "$portal/login" -H 'content-type: application/json' -d "{\"code\":\"$code\"}")
    echo "$resp" > "$TMP/login-$i.json"
}

logout_flow() {  # $1=user index
    local i="$1" user="stress-$1"
    sleep $(( (i % 5) ))       # scatter the logout times across the login window
    curl -sS -X POST "$IDP_URL/logout" -H 'content-type: application/json' \
         -d "{\"sub\":\"$user\"}" > "$TMP/logout-$i.json"
}

for i in $(seq 1 "$N"); do login_flow "$i" & done
for i in $(seq 1 "$N"); do logout_flow "$i" & done
wait

echo "login outcomes:"
for i in $(seq 1 "$N"); do
    jq -rc "if .session_id then \"stress-$i: session created (iat=\(.id_token_iat))\" else \"stress-$i: rejected -> \(.detail)\" end" "$TMP/login-$i.json"
done

echo
echo "checking invariant on both replicas..."
FAIL=0
for portal in "${PORTALS[@]}"; do
    state=$(curl -sS "$portal/debug/state")
    bad=$(jq -r '
        (.logout_cutoffs | map({key: .target_value, value: .max_logout_iat}) | from_entries) as $c
        | [.active_sessions[] | select(.id_token_iat <= ($c[.sub] // -1) or .id_token_iat <= ($c[.sid] // -1))]
        | length' <<<"$state")
    echo "$portal: sessions with id_token_iat <= cutoff -> $bad"
    [ "$bad" = "0" ] || FAIL=1
done
rm -rf "$TMP"
if [ "$FAIL" = "0" ]; then echo "INVARIANT HOLDS: no session survives that is covered by a logout cutoff"; else echo "INVARIANT VIOLATED"; exit 1; fi
