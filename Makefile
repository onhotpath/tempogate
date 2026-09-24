SHELL := /bin/bash

PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
BIN_DIR     := $(PROJECT_DIR)/.bin
BIN         := $(BIN_DIR)/tempogate
PKG         := github.com/onhotpath/tempogate
BUILDINFO   := $(PKG)/buildinfo

# Pin tool versions so CI and local installs agree. Bump deliberately.
GCI_VERSION           ?= v0.14.0
GOLANGCI_LINT_VERSION ?= v2.13.2

GIT_TAG    ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0-dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X '$(BUILDINFO).version=$(VERSION)' \
	-X '$(BUILDINFO).gitTag=$(GIT_TAG)' \
	-X '$(BUILDINFO).gitCommit=$(GIT_COMMIT)' \
	-X '$(BUILDINFO).buildDate=$(BUILD_DATE)'

.PHONY: start build build-cli fmt vet lint imports imports-check check tidy test test-run test-e2e test-e2e-images test-e2e-go ci gen-oas clean help tools \
        gci golangci-lint

start: ## Run the binary directly with build-info ldflags injected
	go run -ldflags "$(LDFLAGS)" .

build: ## Build distroless-bound binary into $(BIN_DIR)
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) .

build-cli: ## Build the lean CLI (-tags lean: login/token/version only, no server subtree)
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -tags lean -ldflags "$(LDFLAGS)" -o $(BIN)-cli .

fmt: ## go fmt
	go fmt ./...

vet: ## go vet ./...
	go vet ./...

lint: golangci-lint ## golangci-lint run
	$(GOLANGCI_LINT) run ./...

imports: gci ## gci write with std/default/local groupings
	# gci also reads stdin; redirect from /dev/null so it never blocks
	# locally on a TTY nor logs a spurious EOF parse error under CI stdin.
	$(GCI) write --skip-generated -s standard -s default -s "prefix($(PKG))" . </dev/null

GO_SRC = $(shell find . -name '*.go' -not -path './.bin/*')

check: vet imports-check ## vet + assert gofmt/gci would not rewrite any .go file
	@bad=$$(gofmt -l $(GO_SRC)); \
	if [ -n "$$bad" ]; then \
		echo "check: these files are not gofmt-clean — run 'make fmt':"; \
		echo "$$bad"; \
		exit 1; \
	fi

imports-check: gci ## assert gci import grouping is already applied
	@d=$$($(GCI) diff --skip-generated -s standard -s default -s "prefix($(PKG))" . </dev/null); \
	if [ -n "$$d" ]; then \
		echo "check: import grouping is off — run 'make imports':"; \
		echo "$$d"; \
		exit 1; \
	fi

tidy: ## go mod tidy
	go mod tidy

test-run: ## run tests with race + coverage (no check chain — CI-friendly)
	go test -race -covermode=atomic -coverprofile=coverage.out ./...

test: check test-run ## check + test-run

# Container-backed acceptance proofs: the Web UI SSO flow and the
# `tempogate login` CLI loopback flow (temporalio/ui + temporal-frontend +
# mock Google + headless Chrome). Behind the `e2e` build tag and a dedicated CI job
# so `ci` stays fast; needs a working Docker daemon.
#
# The tempogate and mock-Google Dockerfiles use BuildKit-only syntax, but
# testcontainers builds via Docker's classic builder. So we pre-build both
# here with a BuildKit-capable `docker build` and hand the tags to the test
# via env; the test uses them as-is instead of building them itself.
E2E_TEMPOGATE_IMAGE  ?= tempogate:e2e
E2E_MOCKGOOGLE_IMAGE ?= tempogate-mockgoogle:e2e
E2E_CLICLIENT_IMAGE  ?= tempogate-cliclient:e2e

# Split so CI can build the images with a cross-run layer cache
# (docker/build-push-action + type=gha; see .github/workflows/e2e.yml) and
# then call test-e2e-go directly. Locally `make test-e2e` builds + runs as
# before — the local Docker daemon already caches layers across runs.
test-e2e-images: ## build the three e2e images with a BuildKit-capable docker build
	DOCKER_BUILDKIT=1 docker build -t $(E2E_TEMPOGATE_IMAGE) -f Dockerfile .
	DOCKER_BUILDKIT=1 docker build -t $(E2E_MOCKGOOGLE_IMAGE) -f test/e2e/mockgoogle/Dockerfile .
	DOCKER_BUILDKIT=1 docker build -t $(E2E_CLICLIENT_IMAGE) -f test/e2e/cliclient/Dockerfile .

test-e2e-go: ## run the e2e tests against pre-built E2E_* images
	E2E_TEMPOGATE_IMAGE=$(E2E_TEMPOGATE_IMAGE) E2E_MOCKGOOGLE_IMAGE=$(E2E_MOCKGOOGLE_IMAGE) \
	E2E_CLICLIENT_IMAGE=$(E2E_CLICLIENT_IMAGE) \
		go test -tags e2e -timeout 40m -count=1 ./test/e2e/...

test-e2e: test-e2e-images test-e2e-go ## build images + run the Web UI SSO + CLI loopback e2e tests

ci: check lint test-run ## fmt/vet/imports + lint + tests (used by GitHub Actions)
	@go tool cover -func=coverage.out | tail -1

gen-oas: build ## emit OpenAPI specs for both the public and admin surfaces
	$(BIN) gen-oas -f yaml > api/openapi.yaml
	$(BIN) gen-oas --admin -f yaml > api/openapi.admin.yaml

tools: gci golangci-lint ## install pinned dev tools into $(BIN_DIR)

clean:
	rm -rf $(BIN_DIR) coverage.out

help: ## list targets
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---------- tool installation ----------
#
# install-if-needed builds a tool into $(BIN_DIR) without polluting this
# module's go.mod. We use a throwaway temp module so `go build` resolves
# the requested version cleanly. Skipped if the target binary already exists.
#
# Args:
#   $(1) — make var name to set to the resolved binary path (eval'd)
#   $(2) — full Go import path of the tool's main package
#   $(3) — version (e.g. v1.2.3)
define install-if-needed
	@if [ ! -f "$(BIN_DIR)/$(notdir $(2))" ]; then \
		echo "Installing $(2)@$(3) -> $(BIN_DIR)/$(notdir $(2))" ;\
		set -e ;\
		mkdir -p $(BIN_DIR) ;\
		TMP_DIR=$$(mktemp -d) ;\
		cd $$TMP_DIR ;\
		go mod init tmp >/dev/null 2>&1 ;\
		go get $(2)@$(3) >/dev/null 2>&1 ;\
		go build -o $(BIN_DIR)/$(notdir $(2)) $(2) ;\
		cd - >/dev/null ;\
		rm -rf $$TMP_DIR ;\
	fi
	$(eval $(1) := $(BIN_DIR)/$(notdir $(2)))
endef

gci:
	$(call install-if-needed,GCI,github.com/daixiang0/gci,$(GCI_VERSION))

golangci-lint:
	$(call install-if-needed,GOLANGCI_LINT,github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
