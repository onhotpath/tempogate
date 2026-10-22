#!/usr/bin/env bash
# Static safety checks for the DEV-ONLY docker-compose example. The bundled
# mock IdP hands any identity to whoever reaches it, so the stack must never
# be reachable from the network and must never boot on baked-in secrets.
#
#   test/deploy/compose-lint.sh          # or: make compose-lint
#
# Asserts, without starting any container:
#   1. each compose file opens with a DEV ONLY banner;
#   2. `docker compose config` fails when any required secret is unset, and no
#      secret-named variable carries a non-empty `:-` fallback (an empty one,
#      as for the optional KEYS_ENCRYPTION_KEY, just leaves it unset);
#   3. every resolved secret comes from the environment, not a literal;
#   4. every published port binds 127.0.0.1;
#   5. under the host-network overlay, every listener the overlay can pin is
#      on loopback and no two services claim the same port.
#
# Needs docker (compose v2) and jq.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIR="$ROOT/examples/docker-compose"
BASE="$DIR/docker-compose.yml"
HOSTNET="$DIR/docker-compose.host-network.yml"

# Secrets the example must refuse to start without.
SECRET_VARS=(TEMPOGATE_SESSION_SIGNING_KEY TEMPORAL_UI_CLIENT_SECRET TEMPOGATE_DEVICE_UI_CLIENT_SECRET POSTGRES_PASSWORD)
# Secret-named env keys whose literal value is fine: the mock IdP never checks
# the upstream client secret.
LITERAL_OK='^OIDC_GOOGLE_CLIENT_SECRET$'
SENTINEL="lint-sentinel"

fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }
# report fails once per non-empty line of $1.
report() {
  local line
  while IFS= read -r line; do [ -z "$line" ] || bad "$line"; done <<<"$1"
}

# compose runs `docker compose` with a scrubbed environment (no .env file, no
# inherited vars) plus whatever VAR=value pairs are passed before `--`.
compose() {
  local envs=()
  while [ "$1" != "--" ]; do envs+=("$1"); shift; done
  shift
  env -i PATH="$PATH" HOME="$HOME" ${DOCKER_HOST:+DOCKER_HOST="$DOCKER_HOST"} "${envs[@]}" \
    docker compose --project-directory "$DIR" --env-file /dev/null "$@"
}

full_env=()
for v in "${SECRET_VARS[@]}"; do full_env+=("$v=$SENTINEL-$v"); done

echo "==> 1. DEV ONLY banner"
for f in "$BASE" "$HOSTNET"; do
  head -n 5 "$f" | grep -q 'DEV ONLY' || bad "$(basename "$f"): no 'DEV ONLY' banner in its first 5 lines"
done

echo "==> 2. required secrets"
if out="$(compose -- -f "$BASE" config --quiet 2>&1)"; then
  bad "docker compose config succeeded with no secrets set"
elif ! grep -q 'required variable' <<<"$out"; then
  bad "docker compose config failed, but not on a required variable: $out"
fi
for v in "${SECRET_VARS[@]}"; do
  partial=()
  for kv in "${full_env[@]}"; do [ "${kv%%=*}" = "$v" ] || partial+=("$kv"); done
  if compose "${partial[@]}" -- -f "$BASE" config --quiet >/dev/null 2>&1; then
    bad "docker compose config succeeded with $v unset"
  fi
done
if defaults="$(grep -nE '\$\{[A-Z0-9_]*(SECRET|KEY|PASSWORD|PWD|TOKEN)[A-Z0-9_]*:?-[^}]' "$BASE" "$HOSTNET")"; then
  bad "secret-named variables with a non-empty fallback default:"$'\n'"$defaults"
fi

base_json="$(compose "${full_env[@]}" -- -f "$BASE" config --format json)"
hostnet_json="$(compose "${full_env[@]}" -- -f "$BASE" -f "$HOSTNET" config --format json)"

echo "==> 3. no literal secrets"
report "$(for json in "$base_json" "$hostnet_json"; do
  jq -r --arg ok "$LITERAL_OK" --arg s "$SENTINEL" '
    .services | to_entries[] | .key as $svc
    | (.value.environment // {}) | to_entries[]
    | select(.key | test("(SECRETS?|SIGNING_KEY|PASSWORD|PWD|TOKEN)$"))
    | select(.key | test($ok) | not)
    | select((.value // "") | contains($s) | not)
    | "\($svc).\(.key) is a literal, not taken from the environment"' <<<"$json"
done | sort -u)"

echo "==> 4. published ports bind 127.0.0.1"
report "$(for json in "$base_json" "$hostnet_json"; do
  jq -r '
    .services | to_entries[] | .key as $svc
    | (.value.ports // [])[]
    | select(.host_ip != "127.0.0.1")
    | "\($svc) publishes \(.published) on \(.host_ip // "0.0.0.0")"' <<<"$json"
done | sort -u)"

echo "==> 5. host-network overlay: loopback listeners, no port collisions"
# Every listener each service opens in the host's network namespace, as
# "service host:port". Temporal's internal ports are the auto-setup image's
# fixed defaults; tempogate's admin listener defaults to 127.0.0.1:8081.
listeners="$(jq -r '
  .services as $s
  | def env($svc; $k; $d): ($s[$svc].environment[$k] // $d);
    "mockoidc \(env("mockoidc"; "MOCK_LISTEN"; ":8080"))",
    "tempogate \(env("tempogate"; "HTTP_LISTENER"; "127.0.0.1:8000"))",
    "tempogate \(env("tempogate"; "ADMIN_LISTENER"; "127.0.0.1:8081"))",
    "temporal-ui *:\(env("temporal-ui"; "TEMPORAL_UI_PORT"; "8080"))",
    (env("temporal"; "BIND_ON_IP"; "127.0.0.1") as $ip
      | (7233, 7234, 7235, 7236, 7239, 7243, 6933, 6934, 6935, 6936, 6939)
      | "temporal \($ip):\(.)"),
    "db \(if (($s.db.command // []) | join(" ") | test("listen_addresses=(127\\.0\\.0\\.1|localhost)$")) then "127.0.0.1" else "*" end):5432"
' <<<"$hostnet_json")"
dups="$(awk '{n=split($2, a, ":"); print a[n]}' <<<"$listeners" | sort | uniq -d)"
for p in $dups; do
  bad "host-network port $p is claimed by: $(awk -v p="$p" '{n=split($2, a, ":"); if (a[n]==p) print $1}' <<<"$listeners" | sort -u | tr '\n' ' ')"
done
# temporal-ui 2.32 has no bind-address knob, so it is exempt (and documented in
# the overlay); every other listener must be pinned to loopback.
while read -r svc addr; do
  [ "$svc" = "temporal-ui" ] && continue
  case "$addr" in
    127.0.0.1:*) ;;
    *) bad "host-network $svc listens on $addr, not 127.0.0.1" ;;
  esac
done <<<"$listeners"

if [ "$fail" -ne 0 ]; then
  echo "compose-lint: FAILED" >&2
  exit 1
fi
echo "compose-lint: PASS"
