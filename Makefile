GO ?= go
GOLANGCI_LINT ?= golangci-lint
PROTOC ?= protoc
PROTOC_GEN_GO ?= $(shell $(GO) env GOPATH)/bin/protoc-gen-go
SWAG ?= $(GO) tool swag
MIGRATE ?= migrate
QUIVER_DATABASE_DSN ?=
OPENAPI_DIR ?= api/openapi
OPENAPI_FILE ?= $(OPENAPI_DIR)/quiver.v1.yaml

.PHONY: fmt lint test test-unit test-integration test-race coverage proto proto-check swagger swagger-check openapi openapi-check migrate-up docker-up docker-down demo verify-demo

fmt:
	$(GO) fmt ./...

lint:
	$(GOLANGCI_LINT) run ./...

test: test-unit

test-unit:
	$(GO) test ./...

test-integration:
	$(GO) test -tags=integration ./...

test-race:
	$(GO) test -race ./internal/...

coverage:
	$(GO) test -coverprofile=coverage.out ./internal/...

proto:
	$(PROTOC) \
		--proto_path=api/proto \
		--plugin=protoc-gen-go=$(PROTOC_GEN_GO) \
		--go_out=. \
		--go_opt=module=github.com/adnope/quiver \
		api/proto/flow/v1/common.proto \
		api/proto/flow/v1/raw_flow_event.proto \
		api/proto/flow/v1/dead_letter_event.proto

proto-check:
	./scripts/proto-check-stale.sh

swagger:
	@tmp_dir=$$(mktemp -d); \
	trap 'rm -rf "$$tmp_dir"' EXIT; \
	$(SWAG) init \
		--generalInfo cmd/quiver/main.go \
		--output "$$tmp_dir" \
		--outputTypes yaml \
		--parseDependency \
		--parseInternal \
		--quiet; \
	mkdir -p "$(OPENAPI_DIR)"; \
	cp "$$tmp_dir/swagger.yaml" "$(OPENAPI_FILE)"

swagger-check:
	@tmp_dir=$$(mktemp -d); \
	trap 'rm -rf "$$tmp_dir"' EXIT; \
	$(SWAG) init \
		--generalInfo cmd/quiver/main.go \
		--output "$$tmp_dir" \
		--outputTypes yaml \
		--parseDependency \
		--parseInternal \
		--quiet; \
	if ! cmp -s "$$tmp_dir/swagger.yaml" "$(OPENAPI_FILE)"; then \
		printf '%s\n' "Swagger spec is stale. Run make swagger."; \
		diff -u "$(OPENAPI_FILE)" "$$tmp_dir/swagger.yaml" || true; \
		exit 1; \
	fi

openapi: swagger

openapi-check: swagger-check

migrate-up:
	$(MIGRATE) \
		-path internal/storage/postgres/migrations \
		-database "$(QUIVER_DATABASE_DSN)" \
		up

docker-up:
	@printf '%s\n' "docker compose is not wired yet"; exit 2

docker-down:
	@printf '%s\n' "docker compose is not wired yet"; exit 2

demo:
	@printf '%s\n' "demo is not wired yet"; exit 2

verify-demo:
	@printf '%s\n' "demo verification is not wired yet"; exit 2
