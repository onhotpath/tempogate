# Build context is the repo root so the mock shares the module (and its jwx
# pin) with tempogate. Built only by the e2e test via testcontainers.
# syntax=docker/dockerfile:1.24
ARG GO_IMAGE=golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd

FROM ${GO_IMAGE} AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ENV CGO_ENABLED=0
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -o /out/mockgoogle ./test/e2e/mockgoogle

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=builder /out/mockgoogle /mockgoogle
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/mockgoogle"]
