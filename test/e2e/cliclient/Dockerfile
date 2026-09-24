# The engineer-laptop stand-in for the CLI loopback e2e: a single container
# that runs headless Chrome AND the tempogate binary, so the loopback server
# `tempogate login` binds on 127.0.0.1 and the browser that drives the consent
# redirect share one network namespace — exactly the property a real laptop
# has, and the one a separate browser container could not satisfy (it cannot
# reach another container's loopback).
#
# Build context is the repo root so the binary shares the module (and its jwx
# pin) with tempogate. Built only by the e2e test via testcontainers.
# syntax=docker/dockerfile:1.24
ARG GO_VERSION=1.27.1
ARG HEADLESS_SHELL_IMAGE=chromedp/headless-shell:131.0.6778.86

FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ENV CGO_ENABLED=0
# The cliclient stands in for a developer laptop, which only ever runs the
# CLI subcommands (login/token/version). The lean build drops the SQLite +
# OIDC + admin subtree along with the server-bound subcommands, so the
# binary's fx graph no longer requires OIDC__SESSION_SIGNING_KEY (or any of
# the other server env vars) at startup — exactly what a CLI-only client is
# expected to need on a real laptop. See app/modules_lean.go.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -tags lean -trimpath -o /out/tempogate .

FROM ${HEADLESS_SHELL_IMAGE}
# The static tempogate binary (CGO off) runs on the headless-shell Debian base.
COPY --from=builder /out/tempogate /usr/local/bin/tempogate
# `tempogate login`'s default opener shells out to xdg-open. In this headless
# container there is no desktop browser; the shim instead hands the authorize
# URL to the test (which then drives it with chromedp) and returns success so
# the login keeps waiting for the loopback callback.
COPY --chmod=0755 test/e2e/cliclient/xdg-open /usr/local/bin/xdg-open
# headless-shell's ENTRYPOINT is the chrome binary; the test passes the same
# --remote-debugging Cmd the standalone chrome container uses, so Chrome runs
# as PID 1 and `tempogate` is started via `docker exec`.
