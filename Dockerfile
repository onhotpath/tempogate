# syntax=docker/dockerfile:1.24

ARG GO_VERSION=1.27.1

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

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

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/tempogate /tempogate
COPY --chown=nonroot:nonroot --from=builder /out/state /var/lib/tempogate

USER nonroot:nonroot
ENTRYPOINT ["/tempogate"]
CMD ["serve"]
