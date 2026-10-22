# syntax=docker/dockerfile:1.24@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

ARG GO_IMAGE=golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS builder

ARG TARGETOS
ARG TARGETARCH
ARG GIT_TAG=v0.0.0-dev
ARG GIT_COMMIT=unknown
ARG VERSION=dev
ARG BUILD_DATE=unknown

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ENV CGO_ENABLED=0
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags "-s -w \
        -X 'github.com/onhotpath/tempogate/buildinfo.version=${VERSION}' \
        -X 'github.com/onhotpath/tempogate/buildinfo.gitTag=${GIT_TAG}' \
        -X 'github.com/onhotpath/tempogate/buildinfo.gitCommit=${GIT_COMMIT}' \
        -X 'github.com/onhotpath/tempogate/buildinfo.buildDate=${BUILD_DATE}'" \
      -o /out/tempogate .
RUN mkdir -p /out/state

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=builder /out/tempogate /tempogate
# Owner-only: it holds the signing keys and session state, and a Docker
# volume mounted here is seeded with this mode. (--chmod, because COPY
# creates the destination directory itself rather than copying its mode.)
COPY --chown=nonroot:nonroot --chmod=0700 --from=builder /out/state /var/lib/tempogate

USER nonroot:nonroot
ENTRYPOINT ["/tempogate"]
CMD ["serve"]
