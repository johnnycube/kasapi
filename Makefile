# Task-runner contract (https://fleetlint.org/baseline/#task-runner-contract). `make check` is the definition of green.
SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.ONESHELL:
.DEFAULT_GOAL := check-fast
MAIN_BRANCH ?= main
# Total statement coverage the cover target enforces; the suite is at 98.9%.
COVER_MIN   ?= 95
PKGS        := ./...
LICENSES    ?= MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC
# Each pin carries a `# renovate:` comment so Renovate bumps it (customManagers in renovate.json5).
# renovate: datasource=go depName=github.com/golangci/golangci-lint/v2
GOLANGCI_VERSION    ?= v2.14.0
# renovate: datasource=go depName=golang.org/x/vuln
GOVULNCHECK_VERSION ?= v1.9.0
# renovate: datasource=go depName=github.com/google/go-licenses/v2
GO_LICENSES_VERSION ?= v2.0.1
# renovate: datasource=go depName=github.com/fleetlint/fleetlint
FLEETLINT_VERSION   ?= v0.4.0
# Tools are built with this module's toolchain: golangci-lint refuses code that targets a newer Go than it was built with.
TOOLCHAIN   := $(shell go env GOVERSION)

.PHONY: help tools fmt lint vet test cover audit bench build dist check-fast check release tidy clean

help: ## list targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*##' '{printf "  %-12s %s\n", $$1, $$2}'

tools: ## install the pinned Go tools the gates use (gitleaks and syft come from their own installers)
	GOTOOLCHAIN=$(TOOLCHAIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	GOTOOLCHAIN=$(TOOLCHAIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	GOTOOLCHAIN=$(TOOLCHAIN) go install github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION)
	go install github.com/fleetlint/fleetlint/cmd/fleetlint@$(FLEETLINT_VERSION)

fmt: ## format in place
	golangci-lint fmt

lint: ## format check + linters + vet, warnings as errors
	golangci-lint fmt --diff
	golangci-lint run
	go vet $(PKGS)

vet: ## go vet only
	go vet $(PKGS)

test: ## all tests with the race detector, shuffled
	go test -race -shuffle=on -count=1 $(PKGS)

cover: ## tests with coverage; fail if the total is below COVER_MIN
	go test -count=1 -coverprofile=cover.out $(PKGS)
	total=$$(go tool cover -func=cover.out | awk '/^total:/ {sub("%", "", $$3); print $$3}')
	echo "coverage $$total% (minimum $(COVER_MIN)%)"
	if [ "$${total%.*}" -lt $(COVER_MIN) ]; then echo "coverage below $(COVER_MIN)%"; exit 1; fi

audit: ## vulnerabilities, licenses, tidy module graph, secrets
	govulncheck $(PKGS)
	go-licenses check $(PKGS) --allowed_licenses=$(LICENSES)
	go mod tidy -diff
	gitleaks git --no-banner --redact .

bench: ## benchmarks (not part of check)
	go test -run='^$$' -bench=. -benchmem $(PKGS)

build: ## build kascli
	CGO_ENABLED=0 go build -trimpath -o kascli ./cmd/kascli

dist: ## release artifacts into dist/ (the release workflow runs goreleaser itself)
	goreleaser release --snapshot --clean

check-fast: ## before every commit (< 30 s)
	golangci-lint fmt --diff
	golangci-lint run --new-from-rev=origin/$(MAIN_BRANCH) || golangci-lint run
	go test -short $(PKGS)

check: lint test cover audit build ## definition of green (< 10 min)
	fleetlint check --fail-on error

release: ## refuse dirty/non-main -> check -> signed tag V (its CHANGELOG.md section must exist); pushing the tag runs the release workflow
	@test -n "$(V)" || { echo "usage: make release V=vX.Y.Z"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "dirty tree"; exit 1; }
	@test "$$(git branch --show-current)" = "$(MAIN_BRANCH)" || { echo "not on $(MAIN_BRANCH)"; exit 1; }
	@grep -q "^## $(V) " CHANGELOG.md || { echo "CHANGELOG.md has no '## $(V) ' section"; exit 1; }
	$(MAKE) check
	git tag -s "$(V)" -m "$(V)"
	@echo "tagged $(V) — push with: git push origin $(V)"

tidy: ## go mod tidy
	go mod tidy

clean: ## remove build and coverage output
	rm -rf kascli cover.out dist
