GO ?= go
GOLANGCI_LINT ?= golangci-lint
PROTOC ?= protoc
PROTOC_GEN_GO ?= $(shell $(GO) env GOPATH)/bin/protoc-gen-go
MIGRATE ?= migrate
QUIVER_DATABASE_DSN ?=

.PHONY: fmt lint test test-unit test-integration test-race coverage proto swagger migrate-up docker-up docker-down demo verify-demo

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

swagger:
	@printf '%s\n' "swagger generation is not wired yet"; exit 2

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
