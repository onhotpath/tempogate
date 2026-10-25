#!/usr/bin/env bash
# Download the newest stable chart release no newer than the candidate.
# Use the release asset, not a source checkout; failures must block CI.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
destination="${1:?usage: released-chart.sh DESTINATION}"
repository="${GITHUB_REPOSITORY:-onhotpath/tempogate}"
version=$(yq '.version' "$ROOT/charts/tempogate/Chart.yaml")
# Fetch all pages so a run of binary releases cannot hide the last chart.
tag=$(gh api --paginate --slurp "repos/$repository/releases?per_page=100" | jq -er --arg version "$version" '
  ($version | split("-")[0] | split(".") | map(tonumber)) as $candidate |
  [ .[][] | select(.draft == false and .prerelease == false) |
    select(.tag_name | test("^chart-v[0-9]+\\.[0-9]+\\.[0-9]+$")) |
    . + { semver: (.tag_name | ltrimstr("chart-v") | split(".") | map(tonumber)) } |
    select(.semver <= $candidate) ] | sort_by(.semver) | last | .tag_name // error("no published chart baseline")')
mkdir -p "$destination"
archive="tempogate-${tag#chart-v}.tgz"
gh release download "$tag" --repo "$repository" --pattern "$archive" --dir "$destination"
tar -xzf "$destination/$archive" -C "$destination"
echo "Upgrade baseline: $tag (image $(yq '.appVersion' "$destination/tempogate/Chart.yaml"))"
