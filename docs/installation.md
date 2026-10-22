# Installation

This page shows every way to get tempogate: the container image, the Helm chart, the CLI binaries, and a build from source.
To see the full stack work first, use [docs/getting-started.md](getting-started.md).

## Container image

Images are published to `ghcr.io/onhotpath/tempogate` for `linux/amd64` and `linux/arm64`.

| Tag | Meaning |
| --- | --- |
| `:vX.Y.Z`, `:X.Y`, `:X`, `:latest` | Stable releases (pushed on `git tag vX.Y.Z`) |
| `:vX.Y.Z-rc.N` | Pre-releases (release candidates) |
| `:sha-<short>` | One-off builds dispatched manually from `main` or a `v*` tag, named after the built commit |

Every pushed image carries SLSA provenance and an SBOM attestation, and is signed with cosign (keyless).
[RELEASING.md](../RELEASING.md#verify-a-release) shows how to verify them.

Run a published image:

```bash
TEMPOGATE_IMAGE=${TEMPOGATE_IMAGE:-ghcr.io/onhotpath/tempogate:latest}
export OIDC_SESSION_SIGNING_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
export OIDC_CLIENTS='tempogate-device-ui:http://127.0.0.1/device/sso-callback'
export OIDC_CLIENT_SECRETS="tempogate-device-ui:$(openssl rand -hex 32)"
export OIDC_AUTHZ_RULES_0='email:alice@example.com=default:read'   # serve refuses to start without a rule
docker volume create tempogate-state
docker run --rm --mount source=tempogate-state,target=/var/lib/tempogate \
  "$TEMPOGATE_IMAGE" migrate
docker run --rm -d --name tempogate -p 127.0.0.1:8000:8000 \
  --mount source=tempogate-state,target=/var/lib/tempogate \
  -e OIDC_SESSION_SIGNING_KEY -e OIDC_CLIENTS -e OIDC_CLIENT_SECRETS -e OIDC_AUTHZ_RULES_0 \
  -e HTTP_LISTENER=0.0.0.0:8000 "$TEMPOGATE_IMAGE"
curl --retry 20 --retry-delay 1 --retry-all-errors -fsS http://127.0.0.1:8000/healthz
```

Keep the signing key and the state volume across restarts.
The generated client secret and the rule are only for this health check.
For a real sign-in, also set `OIDC_ISSUER`, the registered clients, the allowed domains, the [authorization rules](configuration.md#authorization) and the Google credentials.
Keep those secrets in a secret manager, not only in your shell, before you use this as a lasting deployment.
To stop the example, run `docker stop tempogate`.

## Helm chart

The chart in [`charts/tempogate/`](../charts/tempogate/README.md) deploys tempogate to Kubernetes.
It is published as an OCI artifact, so you do not need a clone of the repository:

```bash
helm install tempogate oci://ghcr.io/onhotpath/charts/tempogate --version 0.3.0
```

The chart has its own version, separate from the binary.
Find the latest version in the [chart releases](https://github.com/onhotpath/tempogate/releases?q=chart-v).
To try the chart on a local cluster, use [examples/kind/](../examples/kind/README.md).

## CLI binaries

Every stable release and release candidate also ships a **lean** `tempogate` CLI.
It contains only `login`, `token` and `version`, with none of the server, SQLite or OIDC-issuer code.
The binaries are GitHub Release assets for `linux` and `darwin` on `amd64` and `arm64`, with a `checksums.txt`.
Stable releases are published, and release candidates are marked pre-release.
Manual dispatch builds attach the binaries to the workflow run only.

### macOS (Homebrew)

The Homebrew tap is in this repository:

```bash
brew tap onhotpath/tempogate https://github.com/onhotpath/tempogate
brew trust --cask onhotpath/tempogate/tempogate
brew install --cask tempogate
```

Homebrew 6 requires trust for casks from taps that are not official.
The `brew trust` step trusts only the tempogate cask, and you do it once.

The macOS binary is not signed or notarized by Apple, because the project has no paid Apple Developer account.
So that Gatekeeper does not block it, the cask removes the `com.apple.quarantine` attribute after install.
As a result, Gatekeeper never checks the binary.
Instead, you rely on the sha256 check of the release archive that Homebrew does (the cask pins it), and on the cosign-signed `checksums.txt` on the GitHub Release ([verify it](../RELEASING.md#verify-a-release)).
If that is not sufficient for your machines, download the archive and verify the signature yourself, or build from source.

### Release download

This example is for Linux on x86_64.
Change the pattern for your OS and architecture:

```bash
gh release download vX.Y.Z --repo onhotpath/tempogate \
  --pattern 'tempogate_*_linux_x86_64.tar.gz' --pattern checksums.txt
sha256sum -c --ignore-missing checksums.txt
tar -xzf tempogate_*_linux_x86_64.tar.gz
./tempogate version --detailed
```

## Build from source

Go 1.27 or later is necessary.

```bash
git clone git@github.com:onhotpath/tempogate.git
cd tempogate
make build
export STATE_SQLITE_PATH="$PWD/state.db"
export OIDC_SESSION_SIGNING_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
export OIDC_CLIENTS='tempogate-device-ui:http://127.0.0.1/device/sso-callback'
export OIDC_CLIENT_SECRETS="tempogate-device-ui:$(openssl rand -hex 32)"
export OIDC_AUTHZ_RULES_0='email:alice@example.com=default:read'   # serve refuses to start without a rule
./.bin/tempogate migrate
./.bin/tempogate serve            # listens on 127.0.0.1:8000
```

To build the container image locally:

```bash
docker build -t tempogate:dev .
TEMPOGATE_IMAGE=tempogate:dev    # then run the container example above
```

To cut a release, see [RELEASING.md](../RELEASING.md).

## See also

- [docs/configuration.md](configuration.md) - every setting
- [examples/google-oauth-setup.md](../examples/google-oauth-setup.md) - create the upstream Google OAuth client
- [charts/tempogate/README.md](../charts/tempogate/README.md) - Helm values and Secret wiring
