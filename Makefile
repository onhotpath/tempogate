SHELL := /bin/bash

PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
BIN_DIR     := $(PROJECT_DIR)/.bin
BIN         := $(BIN_DIR)/tempogate
PKG         := github.com/onhotpath/tempogate
BUILDINFO   := $(PKG)/buildinfo

# Pinned tool versions (and release checksums) so CI and local installs agree.
include $(PROJECT_DIR)/tools.mk

GIT_TAG    ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0-dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X '$(BUILDINFO).version=$(VERSION)' \
	-X '$(BUILDINFO).gitTag=$(GIT_TAG)' \
	-X '$(BUILDINFO).gitCommit=$(GIT_COMMIT)' \
	-X '$(BUILDINFO).buildDate=$(BUILD_DATE)'

.PHONY: start build build-cli fmt vet lint imports imports-check check tidy test test-run test-e2e test-e2e-images test-e2e-go test-deploy test-deploy-kind test-deploy-compose ci vuln go-version-check check-supply-chain gen-oas clean help tools \
        gci golangci-lint govulncheck actionlint

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

check: vet imports-check go-version-check ## vet + assert gofmt/gci would not rewrite any .go file
	@bad=$$(gofmt -l $(GO_SRC)); \
	if [ -n "$$bad" ]; then \
		echo "check: these files are not gofmt-clean — run 'make fmt':"; \
		echo "$$bad"; \
		exit 1; \
	fi

# govulncheck exits non-zero only for vulnerabilities whose symbols our code
# can reach (stdlib included, so this also gates the Go toolchain version).
# Package- and module-level findings (imported or required but never called)
# are reported but do not fail the target.
vuln: govulncheck ## govulncheck ./... (fails on reachable vulnerabilities only)
	$(GOVULNCHECK) ./...

# go.mod's go directive is the single source of truth for the toolchain
# (CI and release read it via setup-go's go-version-file). Dockerfiles cannot
# read go.mod, so each takes its builder from an ARG GO_IMAGE default
# (golang:X.Y.Z-alpine@sha256:...) whose tag and digest Renovate updates
# together, grouped with the go directive (renovate.json); this catches drift
# and any golang image used without the ARG.
go-version-check: ## assert every Dockerfile ARG GO_IMAGE tag matches go.mod's go directive
	@want=$$(go list -m -f '{{.GoVersion}}'); \
	bad=$$(grep -rnE --include='Dockerfile*' --exclude-dir=.bin '^ARG GO_IMAGE=|^FROM .*golang:' . \
		| awk -v want="ARG GO_IMAGE=golang:$$want-alpine@sha256:" 'index($$0, want) == 0'); \
	if [ -z "$$want" ] || [ -n "$$bad" ]; then \
		echo "check: ARG GO_IMAGE must be golang:$$want-alpine@sha256:... to match go.mod's go directive:"; \
		echo "$$bad"; \
		exit 1; \
	fi

# Supply-chain guard: actionlint on every workflow, plus scripts/check-pins.sh
# (every action pinned to a commit SHA, every Dockerfile base image and
# syntax frontend pinned to a digest). Renovate keeps the pins current.
# scripts/check-ci-targets.sh keeps the workflow's split CI jobs running
# exactly ci's prerequisites.
check-supply-chain: actionlint ## actionlint + assert actions and base images are pinned by digest + CI runs exactly `make ci`
	$(ACTIONLINT)
	./scripts/check-pins.sh
	./scripts/check-ci-targets.sh

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

# The top-level e2e tests are independent (each starts its own network,
# volumes and containers) and call t.Parallel; E2E_PARALLEL caps how many run
# at once, since several start a postgres + Temporal stack and a 4-vCPU CI
# runner has to host them side by side. -v prints each test's duration.
E2E_PARALLEL ?= 3

test-e2e-go: ## run the e2e tests against pre-built E2E_* images
	E2E_TEMPOGATE_IMAGE=$(E2E_TEMPOGATE_IMAGE) E2E_MOCKGOOGLE_IMAGE=$(E2E_MOCKGOOGLE_IMAGE) \
	E2E_CLICLIENT_IMAGE=$(E2E_CLICLIENT_IMAGE) \
		go test -tags e2e -v -parallel $(E2E_PARALLEL) -timeout 40m -count=1 ./test/e2e/...

test-e2e: test-e2e-images test-e2e-go ## build images + run the Web UI SSO + CLI loopback e2e tests

# Deployment smoke tests: install the Helm chart into a throwaway kind
# cluster (migrate Job completes, pod becomes Ready) and run the
# docker-compose example's migrate service. Need docker; kind + helm +
# kubectl for the chart. Both build DEPLOY_IMAGE first unless SKIP_BUILD=1.
DEPLOY_IMAGE    ?= tempogate:smoke
KIND_CLUSTER    ?= tempogate-smoke
COMPOSE_PROJECT ?= tempogate-smoke

test-deploy-kind: ## helm template + install into a throwaway kind cluster
	IMAGE=$(DEPLOY_IMAGE) CLUSTER=$(KIND_CLUSTER) test/deploy/kind-smoke.sh

test-deploy-compose: ## docker-compose example: tempogate-migrate must exit 0
	IMAGE=$(DEPLOY_IMAGE) PROJECT=$(COMPOSE_PROJECT) test/deploy/compose-smoke.sh

test-deploy: test-deploy-kind test-deploy-compose ## both deployment smoke tests

ci: check lint vuln check-supply-chain test-run ## fmt/vet/imports + lint + govulncheck + supply-chain pins + tests (used by GitHub Actions)
	@go tool cover -func=coverage.out | tail -1

gen-oas: build ## emit OpenAPI specs for both the public and admin surfaces
	$(BIN) gen-oas -f yaml > api/openapi.yaml
	$(BIN) gen-oas --admin -f yaml > api/openapi.admin.yaml

tools: gci golangci-lint govulncheck actionlint ## install pinned dev tools into $(BIN_DIR)

clean:
	rm -rf $(BIN_DIR) coverage.out

help: ## list targets
	@awk 'BEGIN {FS = ":.*##"; printf "Targets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---------- tool installation ----------
#
# install-if-needed builds a tool into $(BIN_DIR) without polluting this
# module's go.mod. We use a throwaway temp module so `go build` resolves
# the requested version cleanly. Skipped if the target binary already exists.
# The tool is built with this module's toolchain (go.mod), not whatever the
# temp dir would default to: analyzers such as govulncheck type-check our
# sources and the stdlib, and fail if they were built with an older Go.
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
		export GOTOOLCHAIN=$$(go env GOVERSION) ;\
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

# install-release-if-needed downloads a prebuilt tool from its GitHub release
# and verifies the archive against the SHA-256 pinned in tools.mk (see
# scripts/install-release-tool.sh). Used where a release binary works on this
# module's Go and building from source is slow (golangci-lint: ~60s cold).
# Skipped if the target binary already exists.
#
# Args:
#   $(1) - make var name to set to the resolved binary path (eval'd)
#   $(2) - binary name in $(BIN_DIR)
#   $(3) - release archive URL
#   $(4) - expected SHA-256 of the archive
#   $(5) - path of the binary inside the archive
define install-release-if-needed
	@if [ ! -f "$(BIN_DIR)/$(2)" ]; then \
		echo "Installing $(3) -> $(BIN_DIR)/$(2)" ;\
		$(PROJECT_DIR)/scripts/install-release-tool.sh "$(BIN_DIR)/$(2)" "$(3)" "$(4)" "$(5)" ;\
	fi
	$(eval $(1) := $(BIN_DIR)/$(2))
endef

TOOLS_PLATFORM = $(shell go env GOOS)_$(shell go env GOARCH)
GOLANGCI_LINT_ARCHIVE = golangci-lint-$(GOLANGCI_LINT_VERSION:v%=%)-$(subst _,-,$(TOOLS_PLATFORM))
ACTIONLINT_ARCHIVE    = actionlint_$(ACTIONLINT_VERSION:v%=%)_$(TOOLS_PLATFORM)

gci:
	$(call install-if-needed,GCI,github.com/daixiang0/gci,$(GCI_VERSION))

golangci-lint:
	$(call install-release-if-needed,GOLANGCI_LINT,golangci-lint,https://github.com/golangci/golangci-lint/releases/download/$(GOLANGCI_LINT_VERSION)/$(GOLANGCI_LINT_ARCHIVE).tar.gz,$(GOLANGCI_LINT_SHA256_$(TOOLS_PLATFORM)),$(GOLANGCI_LINT_ARCHIVE)/golangci-lint)

govulncheck:
	$(call install-if-needed,GOVULNCHECK,golang.org/x/vuln/cmd/govulncheck,$(GOVULNCHECK_VERSION))

actionlint:
	$(call install-release-if-needed,ACTIONLINT,actionlint,https://github.com/rhysd/actionlint/releases/download/$(ACTIONLINT_VERSION)/$(ACTIONLINT_ARCHIVE).tar.gz,$(ACTIONLINT_SHA256_$(TOOLS_PLATFORM)),actionlint)
