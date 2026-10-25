# Contributing to tempogate

Thanks for taking the time to contribute. This document covers the things you'll want to know before opening a pull request.

## Code of Conduct

Participation in this project is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting bugs

Open a GitHub issue with:

- The version (`tempogate version --detailed`).
- A minimal reproduction — config, command line, expected vs. observed.
- Logs at `LOG_LEVEL=debug` if possible.

For security vulnerabilities, **do not open a public issue.** Use [GitHub Security Advisories](https://github.com/onhotpath/tempogate/security/advisories/new) instead — see [SECURITY.md](SECURITY.md).

## Development setup

You need:

- Go (version pinned in [`go.mod`](go.mod) - currently 1.27.x)
- Docker (only if you want to test the container build)

Then:

```bash
git clone git@github.com:onhotpath/tempogate.git
cd tempogate
make tools     # one-time: installs gci + golangci-lint + govulncheck + actionlint into ./.bin
make test      # check + race + coverage
make start     # go run with build-info ldflags and no subcommand (prints help)
```

Changes to the Helm chart, the Dockerfile or the examples are also checked by the `deploy` workflow.
Its jobs run the same Make targets locally (they install pinned kind, kubeconform and yq into `./.bin`; helm and kubectl come from your PATH):

```bash
make lint-chart           # helm lint --strict + kubeconform -strict, no cluster
make test-chart           # static assertions on the rendered chart
make test-deploy-kind     # install, upgrade and helm test in a throwaway kind cluster
PATH="$PWD/.bin:$PATH" test/deploy/released-chart.sh /tmp/tempogate-baseline
BASELINE_CHART=/tmp/tempogate-baseline/tempogate make test-deploy-kind # released-chart upgrade
make test-deploy-compose  # docker compose config, then migrate and boot the compose example
```

CI downloads the newest stable chart release no newer than the candidate and installs it with its published default image.
It seeds an integration key, upgrades to the candidate chart and image, and verifies that signing keys, integration-key metadata, the SQLite PVC, and the session-signing Secret survive.
PostgreSQL upgrades run when the baseline chart supports PostgreSQL; fresh PostgreSQL install and rolling-update tests always run.
The baseline download requires an authenticated `gh` CLI and `jq`; cluster tests also use `curl`, `openssl`, and `python3`.
`helm test` checks health, database readiness, OIDC discovery, and nonempty JWKS, including issuer sub-paths.

### Bumping Go

The `go` directive in [`go.mod`](go.mod) is the single source of truth for the toolchain: CI and release read it via `setup-go`'s `go-version-file`.
Dockerfiles cannot read `go.mod`, so each one takes its builder from an `ARG GO_IMAGE=golang:X.Y.Z-alpine@sha256:...` default whose tag must match; `make check` fails if any drifts.
Renovate bumps the go directive and every `GO_IMAGE` tag and digest together in one "Go toolchain" PR.
To bump by hand, run `go mod edit -go=X.Y.Z`, set every `ARG GO_IMAGE=` to `golang:X.Y.Z-alpine@<digest>` (from `docker buildx imagetools inspect golang:X.Y.Z-alpine`), then `make ci`.

### Pinned build inputs

Every GitHub Action is pinned to a full commit SHA with a `# vX.Y.Z` comment, and every Dockerfile base image (and `# syntax=` frontend) to an `@sha256:` digest, keeping the tag for readability.
`make check-supply-chain` (part of `make ci`) runs actionlint on the workflows and fails on any unpinned reference.
Renovate keeps the SHAs and digests current; when adding an action or image by hand, resolve the SHA from the release tag (`gh api repos/<owner>/<repo>/git/ref/tags/<tag>`, dereferencing annotated tags) or the digest with `docker buildx imagetools inspect <image:tag>`.
Dev tool versions live in [`tools.mk`](tools.mk); golangci-lint and actionlint are downloaded prebuilt and verified against the SHA-256s pinned there, so bump a version together with its checksums (from the release's checksums file).

## Working on a change

1. **Open an issue first** for non-trivial work so we can align on direction.
2. **Branch from `main`.** Use a short, descriptive branch name.
3. **Test-driven development is the default.** Add a failing test before the production code, especially for new Huma operations, state-store methods, and OIDC flows.
4. **Run `make ci` locally** before pushing — it's exactly what GitHub Actions runs.
5. **Sign off your commits.** We use the [Developer Certificate of Origin](https://developercertificate.org/):

   ```bash
   git commit -s -m "your message"
   ```

   This appends a `Signed-off-by: Your Name <you@example.com>` trailer attesting that you have the right to submit the change under the project's license.

6. **Open a PR.** Fill in the template. Keep PRs focused — multiple unrelated changes should be multiple PRs.

## Coding conventions

- **Functional-options constructors.** Every `New(opts ...Option) *T`. No long positional arg lists.
- **Lean consumer-side interfaces.** Interfaces live in the package that *uses* them, ideally with one method. No central `interfaces/` registry.
- **Top-level imports only.** No inline imports inside functions.
- **Tests live in the same issue as the production code.** Don't split test PRs from feature PRs.
- **Comment the *why*, not the *what*.** Well-named identifiers carry the *what*.
- **Declare sensitive values.** Where code first holds a credential, an identity or raw client input, declare it: `redact.Declare(ctx, redact.Secret, token)` (or `redact.PII`, `redact.Identifier`) in a request, or on the process `*redact.Set` for configuration.
  Exported spans mask declared values in their error text, even text a library formatted.
  Span names and attributes are never masked, so keep them to constants and route templates.
- **Imports are grouped** standard / default / `prefix(github.com/onhotpath/tempogate)` — `make imports` does this for you.

## Releasing

The **binary + container image** are tag-driven and run via `release.yml`.
Maintainers cut `vX.Y.Z` tags; contributors don't need to.

The **Helm chart** is versioned and released independently of the binary
via `chart-release.yml`. Its version lives in
`charts/tempogate/Chart.yaml` (`version:`, semver) and its release tag is
`chart-vX.Y.Z` (the `chart-` prefix keeps it distinct from the binary's
`vX.Y.Z`). Bumping `version:` in a PR and merging to `main` cuts the
release; a maintainer can also push a `chart-vX.Y.Z` tag explicitly. Full
mechanics are in [RELEASING.md](RELEASING.md).
