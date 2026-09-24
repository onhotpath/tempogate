# Build context is the repo root so the mock shares the module (and its jwx
# pin) with tempogate. Built only by the e2e test via testcontainers.
# syntax=docker/dockerfile:1.24
ARG GO_VERSION=1.27.1

FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ENV CGO_ENABLED=0
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -o /out/mockgoogle ./test/e2e/mockgoogle

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/mockgoogle /mockgoogle
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/mockgoogle"]
