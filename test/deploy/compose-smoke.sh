#!/usr/bin/env bash
# Smoke test for examples/docker-compose:
#   1. every compose file under examples/ (an overlay together with the
#      docker-compose.yml next to it) passes `docker compose config`;
#   2. the one-shot `tempogate-migrate` service exits 0. It runs with only
#      STATE_SQLITE_PATH (and an issuer) set, so it fails if a non-serve
#      subcommand ever requires server config again;
#   3. unless BOOT=0, the `tempogate` service then boots against the migrated
#      volume and the bundled mock IdP: /readyz answers 200 and the discovery
#      document advertises the example's issuer.
# The example has no secret defaults, so its secrets are generated with the
# example's own gen-env.sh into a temporary env file passed via --env-file
# (any .env in the example directory is ignored). The project, its volume and
# the env file are always removed on exit.
#
#   test/deploy/compose-smoke.sh         # or: make test-deploy-compose
#
# Env:
#   IMAGE       image to test (default tempogate:smoke)
#   SKIP_BUILD  set to 1 to use an already built IMAGE
#   PROJECT     compose project name (default tempogate-smoke)
#   BOOT        set to 0 to skip booting `tempogate serve` (step 3)
set -euo pipefail

IMAGE="${IMAGE:-tempogate:smoke}"
PROJECT="${PROJECT:-tempogate-smoke}"
BOOT="${BOOT:-1}"
TIMEOUT_SECONDS=120

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EXAMPLE_DIR="$ROOT/examples/docker-compose"
COMPOSE_FILE="$EXAMPLE_DIR/docker-compose.yml"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required but not on PATH" >&2; exit 1; }; }
need docker; need curl; need openssl

# Fresh random secrets, exactly as a user would create their .env.
env_file="$(mktemp)"
override="$(mktemp)"
trap 'rm -f "$env_file" "$override"' EXIT
"$EXAMPLE_DIR/gen-env.sh" >"$env_file"

echo "==> docker compose config: every compose file under examples/"
found=0
while IFS= read -r file; do
  found=1
  base="$(dirname "$file")/docker-compose.yml"
  files=(-f "$file")
  if [ "$file" != "$base" ]; then
    # An overlay is only meaningful on top of its directory's base file.
    files=(-f "$base" -f "$file")
  fi
  docker compose --env-file "$env_file" "${files[@]}" config --quiet
  echo "    ok ${file#"$ROOT"/}"
done < <(find "$ROOT/examples" -type f \( -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'compose*.yml' -o -name 'compose*.yaml' \) | sort)
if [ "$found" = 0 ]; then
  echo "FAIL: no compose files found under examples/" >&2
  exit 1
fi

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "==> building $IMAGE"
  DOCKER_BUILDKIT=1 docker build -t "$IMAGE" -f "$ROOT/Dockerfile" "$ROOT"
fi

# Run the example's service definitions unchanged except for the image, so
# the smoke test does not rebuild what was just built, and tempogate's
# published port, which is moved to an ephemeral loopback port so the test
# never collides with something already listening on 8000.
compose() { docker compose -p "$PROJECT" --env-file "$env_file" -f "$COMPOSE_FILE" -f "$override" "$@"; }
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "==> diagnostics" >&2
    compose ps -a >&2 || true
    compose logs --no-color --tail=50 tempogate-migrate tempogate mockoidc >&2 || true
  fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$env_file" "$override"
  exit "$status"
}
trap cleanup EXIT
cat >"$override" <<YAML
services:
  tempogate-migrate:
    image: $IMAGE
    pull_policy: never
  tempogate:
    image: $IMAGE
    pull_policy: never
    ports: !override
      - "127.0.0.1::8000"
YAML

echo "==> docker compose: tempogate-migrate must exit 0"
compose up --no-build --no-deps --abort-on-container-exit --exit-code-from tempogate-migrate \
  tempogate-migrate
echo "    ok"

if [ "$BOOT" != "1" ]; then
  echo "PASS: compose files render and tempogate-migrate exited 0 (BOOT=0: serve not booted)"
  exit 0
fi

echo "==> docker compose: tempogate must boot and become ready"
# mockoidc is built from the example's Dockerfile.mockoidc; tempogate uses
# IMAGE. depends_on re-runs the (idempotent) migration first.
compose build mockoidc
compose up --detach --no-build tempogate

addr="$(compose port tempogate 8000)"
base_url="http://$addr"
deadline=$((SECONDS + TIMEOUT_SECONDS))
until curl -fs -o /dev/null "$base_url/readyz"; do
  if [ "$(compose ps --status running --quiet tempogate)" = "" ]; then
    echo "FAIL: tempogate exited before becoming ready" >&2
    exit 1
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "FAIL: tempogate not ready on $base_url/readyz within ${TIMEOUT_SECONDS}s" >&2
    exit 1
  fi
  sleep 2
done
echo "    ok /readyz"

issuer="$(curl -fsS "$base_url/.well-known/openid-configuration" | sed -n 's/.*"issuer":"\([^"]*\)".*/\1/p')"
if [ "$issuer" != "http://tempogate:8000" ]; then
  echo "FAIL: discovery issuer '$issuer', want 'http://tempogate:8000'" >&2
  exit 1
fi
echo "    ok discovery issuer $issuer"

echo "PASS: compose files render, tempogate-migrate exited 0, tempogate booted and is ready"
