# Releasing tempogate

Every release produces **two artifacts** from one trigger:

1. A **multi-arch container image** → `ghcr.io/onhotpath/tempogate` (the full
   server: `serve`/`migrate`/`keys` + all modules), built by the `publish`
   job (Docker buildx + QEMU).
2. A **lean standalone CLI** (`login`/`token`/`version` only — no
   SQLite/OIDC/API code) as GitHub Release assets for `linux`/`darwin` ×
   `amd64`/`arm64` + `checksums.txt`, built by the `binaries` job
   (GoReleaser, `-tags lean`).

Both jobs live in [`.github/workflows/release.yml`](.github/workflows/release.yml)
and fire off the same trigger.

The **Helm chart** is a third artifact, versioned and released
independently of the binary — see [Helm chart releases](#helm-chart-releases).

## TL;DR

| Goal | Do this | You get |
| --- | --- | --- |
| **Full release** | `git tag vX.Y.Z && git push origin vX.Y.Z` | Images `:vX.Y.Z` `:X.Y` `:X` `:latest` · published GitHub Release with lean CLI binaries + `checksums.txt` · PR to update `Casks/tempogate.rb` (`brew install --cask tempogate` after merge and one-time cask trust) |
| **Release candidate** | `git tag vX.Y.Z-rc.N && git push origin vX.Y.Z-rc.N` | Image `:vX.Y.Z-rc.N` only · GitHub Release marked **pre-release** with the same binaries · Homebrew **not** touched |
| **Test / dev build** | Actions → **release** workflow → **Run workflow** → pick branch/SHA | Image `:sha-<short>` · snapshot binaries attached to the **workflow run** (no GitHub Release, ~14-day retention) · Homebrew **not** touched |

## Versioning rules

- Semantic versioning, `v`-prefixed tags: `vMAJOR.MINOR.PATCH`.
- A pre-release suffix (anything after `-`, e.g. `-rc.1`) makes it a
  **release candidate**: GoReleaser auto-marks the GitHub Release as a
  pre-release, the container build suppresses the `:X.Y` / `:X` / `:latest`
  aliases, and the Homebrew cask is **not** updated (`skip_upload: auto`).
- Never move or re-tag a published stable version. To fix a bad stable
  release, cut the next patch (`vX.Y.(Z+1)`).

## Before you tag

1. `main` is green: `make ci` passes (fmt/vet/imports + lint + tests) and the
   "Lean CLI build guard" is happy.
2. Release notes are auto-generated from commit subjects since the previous
   tag, so use Conventional Commits (`feat:`, `fix:`, …). `docs:`, `test:`,
   `chore:`, `ci:` and merge commits are filtered out of the notes.
3. Decide the version bump from the change set; tag the exact commit on `main`
   you want released.
4. **If the release adds or changes a user-facing feature, update
   [`examples/`](examples/) and [`docs/`](docs/) in the same train.** The
   docker-compose stack, the kind overlay, the getting-started walkthrough,
   and [`docs/configuration.md`](docs/configuration.md) are the front door —
   a new env var, client mode, endpoint, or workflow that ships unreflected
   there is a release regression. A purely internal change (refactor, perf,
   dependency bump) needs nothing here.

## Cutting it

```bash
git checkout main && git pull
git tag vX.Y.Z            # or vX.Y.Z-rc.N for a candidate
git push origin vX.Y.Z
```

Watch the **release** workflow: the `publish` job pushes the image tags; the
`binaries` job runs GoReleaser.
On a stable tag GoReleaser also opens a PR for the regenerated
`Casks/tempogate.rb` in the in-repo Homebrew tap.
Merge that PR to publish the cask on `main`.

For a **dev build**, don't tag — run the workflow manually and choose the
branch/SHA. You get a `:sha-<short>` image and the binaries as a downloadable
artifact on that workflow run.

## What ships where

- **Container image = full server.** Run `serve`, `migrate`, `keys` and the
  OIDC issuer from the image. These are server/admin operations and need the
  SQLite state store.
- **Downloaded CLI binary = lean client.** `login`, `token`, `version` only.
  It is intentionally ~5 MB smaller with no server/SQLite/OIDC-issuer code —
  smaller download, smaller attack surface, and it never opens a database
  just to mint a token. Don't expect `serve`/`migrate`/`keys` on it.

## Verify a release

```bash
# binaries
gh release download vX.Y.Z --repo onhotpath/tempogate --pattern checksums.txt \
  --pattern 'tempogate_*'
sha256sum -c --ignore-missing checksums.txt
./tempogate version --detailed          # tag / commit / buildDate populated

# container
docker pull ghcr.io/onhotpath/tempogate:vX.Y.Z

# homebrew (stable only): merge the cask PR, then verify the bump on main
brew update && brew upgrade --cask tempogate
```

## Homebrew tap

The cask lives in this repository under `Casks/tempogate.rb` (no separate tap
repo or extra token).
GoReleaser opens an update PR with the workflow's default `GITHUB_TOKEN`.
Users install after that PR is merged with:

```bash
brew tap onhotpath/tempogate https://github.com/onhotpath/tempogate
brew trust --cask onhotpath/tempogate/tempogate
brew install --cask tempogate
```

Homebrew 6 requires explicit trust for casks from non-official taps.
Trusting this cask once avoids granting trust to the entire in-repo tap.

While the repository is access-restricted, `brew` needs credentials to reach
the private release assets — set `HOMEBREW_GITHUB_API_TOKEN` (a token with
read access) or rely on a configured git credential helper. `gh release
download` works with your existing `gh auth` and needs no extra setup.

The cask update uses PR mode in [`.goreleaser.yaml`](.goreleaser.yaml)
because `main` requires changes through a PR.

## Rollback

- Bad **release candidate**: delete the GitHub pre-release and its tag, fix,
  re-tag a higher `-rc.N`.
- Bad **stable**: do not delete or move the tag. Cut `vX.Y.(Z+1)` with the
  fix; `:latest` and the cask move forward on the next stable release.

## Helm chart releases

The Helm chart in [`charts/tempogate/`](charts/tempogate/) is versioned and
released **independently of the binary**. A chart-only fix never bumps the
server image, and an image bump never republishes an unchanged chart. The
workflow is
[`.github/workflows/chart-release.yml`](.github/workflows/chart-release.yml).

| Goal | Do this | You get |
| --- | --- | --- |
| **Cut a chart release** | Bump `charts/tempogate/Chart.yaml` `version:` (semver) in a PR; merge to `main` | OCI artifact `oci://ghcr.io/onhotpath/charts/tempogate:X.Y.Z` · GitHub Release `chart-vX.Y.Z` with the `.tgz` attached · the `chart-vX.Y.Z` tag, created by the workflow |
| **Cut it explicitly** | `git tag chart-vX.Y.Z && git push origin chart-vX.Y.Z` — the tagged commit's `Chart.yaml` `version` must equal `X.Y.Z` | Same as above |

### Versioning rules

- `charts/tempogate/Chart.yaml` `version` is semver; the release tag is
  `chart-v<version>` — the `chart-` prefix keeps it distinct from the
  binary's `vX.Y.Z`.
- Bump `version` for **any** change to the chart or its templates. Bump
  `appVersion` (and normally `version` too) when the chart should default
  to a new server image tag.
- A published chart version is never re-pushed. A `Chart.yaml` change that
  doesn't move `version` is a no-op — the workflow skips when the
  `chart-v<version>` Release already exists. Fix a bad chart release by
  bumping to the next patch, exactly as for the binary.

### One-time registry setup

The first push creates `ghcr.io/onhotpath/charts/tempogate` as a **private**
package. For `helm install oci://ghcr.io/onhotpath/charts/tempogate` to work
**without authentication**, a maintainer must, once, set that package's
visibility to **public** in the org's GitHub Packages settings and link it
to this repository. Later versions inherit the setting.

### Why not `helm/chart-releaser-action`

That action has no OCI registry support — its own docs tell you to do the
OCI push yourself — and it names releases `<chart>-<version>` rather than
the `chart-vX.Y.Z` scheme used here. The native Helm OCI client is the
supported path for `oci://` registries, so the workflow `helm package`s
and `helm push`es directly, then attaches the `.tgz` to a `gh`-created
GitHub Release.

### Verify a chart release

```bash
# the published OCI artifact resolves and templates cleanly
helm template t oci://ghcr.io/onhotpath/charts/tempogate --version X.Y.Z >/dev/null

# the GitHub Release exists with the packaged chart attached
gh release view chart-vX.Y.Z --repo onhotpath/tempogate
```
