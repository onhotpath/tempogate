#!/usr/bin/env bash
# Fails if a third-party build input is referenced by a mutable tag instead of
# an immutable digest:
#   - every `uses:` in .github/workflows and .github/actions must be a
#     40-char commit SHA followed by a `# vX.Y.Z` comment (what Renovate's
#     pinGitHubActionDigests writes);
#   - every Dockerfile base image (FROM, including one taken from an ARG
#     default) and `# syntax=` frontend must carry an `@sha256:` digest.
# Renovate keeps both the versions and the digests current; see renovate.json.
set -euo pipefail

cd "$(dirname "$0")/.."
status=0

mapfile -t workflows < <(find .github/workflows .github/actions -type f \( -name '*.yml' -o -name '*.yaml' \) | sort)
bad_uses=$(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:' "${workflows[@]}" \
  | grep -vE 'uses:[[:space:]]*["'\'']?(\./|[^@[:space:]]+@[0-9a-f]{40}["'\'']?[[:space:]]+#[[:space:]]*v[0-9])' || true)
if [ -n "$bad_uses" ]; then
  echo "check-pins: pin these actions to a full commit SHA with a '# vX.Y.Z' comment:"
  echo "$bad_uses"
  status=1
fi

mapfile -t dockerfiles < <(find . -path ./.git -prune -o -path ./.bin -prune -o -type f -name 'Dockerfile*' -print | sort)
bad_from=$(awk '
  FNR == 1 { delete args; delete stages }
  # A parser directive is honoured only on the first lines, before any other
  # comment or instruction.
  FNR == 1 && /^#[[:space:]]*syntax=/ {
    if ($0 !~ /@sha256:[0-9a-f]{64}/) print FILENAME ":" FNR ": " $0
  }
  toupper($1) == "ARG" && $2 ~ /=/ {
    split($2, kv, "="); args[kv[1]] = substr($2, length(kv[1]) + 2)
  }
  toupper($1) == "FROM" {
    i = 2
    while ($i ~ /^--/) i++
    image = $i
    if (toupper($(i + 1)) == "AS") stages[$(i + 2)] = 1
    for (name in args) {
      gsub("\\$\\{" name "\\}", args[name], image)
      gsub("\\$" name "$", args[name], image)
    }
    if (image == "scratch" || image in stages) next
    if (image !~ /@sha256:[0-9a-f]{64}$/) print FILENAME ":" FNR ": " $0 "  (resolves to " image ")"
  }
' "${dockerfiles[@]}")
if [ -n "$bad_from" ]; then
  echo "check-pins: pin these base images by digest (image:tag@sha256:...):"
  echo "$bad_from"
  status=1
fi

exit $status
