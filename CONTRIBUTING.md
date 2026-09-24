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
make tools     # one-time: installs gci + golangci-lint into ./.bin
make test      # check + race + coverage
make start     # runs `tempogate serve` with build-info ldflags
```

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
