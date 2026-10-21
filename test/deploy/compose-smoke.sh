#!/usr/bin/env bash
# Smoke test for examples/docker-compose: the one-shot `tempogate-migrate`
# service must exit 0. It runs with only STATE_SQLITE_PATH (and an issuer)
# set, so it fails if a non-serve subcommand ever requires server config again.
# Only the migrate service is started; the project and its volume are always
# removed on exit.
#
#   test/deploy/compose-smoke.sh         # or: make test-deploy-compose
#
# Env:
#   IMAGE       image to test (default tempogate:smoke)
#   SKIP_BUILD  set to 1 to use an already built IMAGE
#   PROJECT     compose project name (default tempogate-smoke)
set -euo pipefail

IMAGE="${IMAGE:-tempogate:smoke}"
PROJECT="${PROJECT:-tempogate-smoke}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT/examples/docker-compose/docker-compose.yml"

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "==> building $IMAGE"
  DOCKER_BUILDKIT=1 docker build -t "$IMAGE" -f "$ROOT/Dockerfile" "$ROOT"
fi

# Run the example's service definition unchanged except for the image, so the
# smoke test does not rebuild what was just built.
override="$(mktemp)"
cleanup() {
  status=$?
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" -f "$override" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$override"
  exit "$status"
}
trap cleanup EXIT
cat >"$override" <<YAML
services:
  tempogate-migrate:
    image: $IMAGE
    pull_policy: never
YAML

echo "==> docker compose: tempogate-migrate must exit 0"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" -f "$override" up \
  --no-build --no-deps --abort-on-container-exit --exit-code-from tempogate-migrate \
  tempogate-migrate

echo "PASS: tempogate-migrate exited 0"
