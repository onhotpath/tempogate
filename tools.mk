# Pinned dev tool versions, included by the Makefile. CI keys its .bin tools
# cache on this file (plus the Go version), so edit tool pins here and only
# here: other Makefile edits and dependency bumps then keep the cache warm.
#
# gci and govulncheck are built from source with this module's toolchain
# (see install-if-needed). golangci-lint and actionlint are downloaded as
# release archives and verified against the SHA-256s below, copied from each
# release's checksums file (golangci-lint-<v>-checksums.txt,
# actionlint_<v>_checksums.txt). Bump a version and its four checksums
# together; a stale checksum fails the install instead of running an
# unverified binary.
#
# golangci-lint refuses to analyse a module whose go directive is newer than
# the Go it was built with, so a Go minor bump (go 1.28) needs a golangci-lint
# release built with that Go as well.

GCI_VERSION           ?= v0.14.0
GOLANGCI_LINT_VERSION ?= v2.14.0
GOVULNCHECK_VERSION   ?= v1.9.0
ACTIONLINT_VERSION    ?= v1.7.12
# Deployment test tools (lint-chart, test-chart, test-deploy-kind), built
# from source like gci.
KIND_VERSION          ?= v0.33.0
KUBECONFORM_VERSION   ?= v0.8.0
YQ_VERSION            ?= v4.54.1

GOLANGCI_LINT_SHA256_linux_amd64  := ab90aeb7b066f92a33415b638a50fe5344bbb75a0d32ad30cc248d88f81032ab
GOLANGCI_LINT_SHA256_linux_arm64  := ee7ec5f3453d15ddf106fae5a4d6c71737712348a979d1fe9cd52ec7ea299bae
GOLANGCI_LINT_SHA256_darwin_amd64 := a5667c1c3536be1740133213e1e822bfb8f0d98ea12903174d6d5f635e4ed68d
GOLANGCI_LINT_SHA256_darwin_arm64 := 5ef5f36a7147e91dc58ef9ef4d11bb7bad5ead0c76eb6c01327a73c641d1dcc3

ACTIONLINT_SHA256_linux_amd64  := 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
ACTIONLINT_SHA256_linux_arm64  := 325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6
ACTIONLINT_SHA256_darwin_amd64 := 5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644
ACTIONLINT_SHA256_darwin_arm64 := aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f
