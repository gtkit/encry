MODULE := github.com/gtkit/encry
EXAMPLE_PREFIX := $(MODULE)/examples/
PROD_PACKAGES = $(shell go list ./... | grep -v '^$(EXAMPLE_PREFIX)')
EXAMPLE_PACKAGES = $(shell go list ./... | grep '^$(EXAMPLE_PREFIX)')
PROD_DIRS = $(shell go list -f '{{.Dir}}' ./... | grep -v '/examples/')
EXAMPLE_DIRS = $(shell go list -f '{{.Dir}}' ./... | grep '/examples/')
PROD_LINT_TARGETS = $(shell go list -f '{{.Dir}}' ./... | grep -v '/examples/' | sed 's|^$(CURDIR)|.|')
EXAMPLE_LINT_TARGETS = $(shell go list -f '{{.Dir}}' ./... | grep '/examples/' | sed 's|^$(CURDIR)|.|')

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


##@ Development

.PHONY: test
TEST_ARGS ?= -v
TEST_TARGETS ?= ./...
test: ## Test all Go packages, including examples.
	@ echo ▶️ go test $(TEST_ARGS) $(TEST_TARGETS)
	go test $(TEST_ARGS) $(TEST_TARGETS)
	@ echo ✅ success!

.PHONY: test-prod
test-prod: ## Test production packages only; excludes examples/.
	@ echo ▶️ go test $(TEST_ARGS) $(PROD_PACKAGES)
	go test $(TEST_ARGS) $(PROD_PACKAGES)
	@ echo ✅ success!

.PHONY: test-examples
test-examples: ## Test example packages only.
	@ echo ▶️ go test $(TEST_ARGS) $(EXAMPLE_PACKAGES)
	go test $(TEST_ARGS) $(EXAMPLE_PACKAGES)
	@ echo ✅ success!

.PHONY: build-examples
build-examples: ## Build example packages only.
	@ echo ▶️ go build $(EXAMPLE_PACKAGES)
	go build $(EXAMPLE_PACKAGES)
	@ echo ✅ success!

.PHONY: verify-prod
verify-prod: ## Run production-only test, race, and vet checks.
	@ echo ▶️ go test $(TEST_ARGS) $(PROD_PACKAGES)
	go test $(TEST_ARGS) $(PROD_PACKAGES)
	@ echo ▶️ go test -race $(PROD_PACKAGES)
	go test -race $(PROD_PACKAGES)
	@ echo ▶️ go vet $(PROD_PACKAGES)
	go vet $(PROD_PACKAGES)
	@ echo ✅ success!

.PHONY: lint
LINT_TARGETS ?= ./...
lint: ## Lint all Go packages, including examples.
	@ echo "▶️ golangci-lint run --allow-serial-runners $(LINT_TARGETS)"
	golangci-lint run --allow-serial-runners $(LINT_TARGETS)
	@ echo "✅ golangci-lint run"

.PHONY: lint-prod
lint-prod: ## Lint production packages only; excludes examples/.
	@ echo "▶️ golangci-lint run --allow-serial-runners $(PROD_LINT_TARGETS)"
	golangci-lint run --allow-serial-runners $(PROD_LINT_TARGETS)
	@ echo "✅ golangci-lint run"

.PHONY: lint-examples
lint-examples: ## Lint example packages only.
	@ echo "▶️ golangci-lint run --allow-serial-runners $(EXAMPLE_LINT_TARGETS)"
	golangci-lint run --allow-serial-runners $(EXAMPLE_LINT_TARGETS)
	@ echo "✅ golangci-lint run"


.PHONY: check-secure
check-secure:
	govulncheck ./...
	gosec ./...

.PHONY: check-secure-prod
check-secure-prod: ## Run security scanners on production packages only.
	@ echo ▶️ govulncheck $(PROD_PACKAGES)
	govulncheck $(PROD_PACKAGES)
	@ echo ▶️ gosec $(PROD_DIRS)
	gosec $(PROD_DIRS)
	@ echo ✅ success!

## 推送标签到远程仓库时，通常不需要指定分支
tag:
	@current=$$(grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' version.go | head -n1 | tr -d 'v'); \
	if [ -z "$$current" ]; then echo "version not found in version.go"; exit 1; fi; \
	maj=$$(echo $$current | cut -d. -f1); \
	min=$$(echo $$current | cut -d. -f2); \
	patch=$$(echo $$current | cut -d. -f3); \
	newpatch=$$(expr $$patch + 1); \
	new="v$$maj.$$min.$$newpatch"; \
	printf "Bump: v%s -> %s\n" "$$current" "$$new"; \
	sed -E -i.bak 's/(const Version = ")([^"]+)(")/\1'"$$new"'\3/' version.go; \
	git add version.go; \
	git commit -m "chore(release): $$new"; \
	printf "Release: %s\n" "$$new"; \
	git push gtkit HEAD; \
	git tag -a "$$new" -m "release $$new"; \
	printf "Tag: %s\n" "$$new"; \
	git push gtkit "$$new"; \
	printf "Done\n"
	rm -f version.go.bak

gittag:
	git tag --sort=-version:refname | head -1
