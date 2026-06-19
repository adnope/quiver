ifneq (,$(wildcard ./.env))
    include .env
    export
endif

GO ?= go
GOLANGCI_LINT ?= golangci-lint
PROTOC ?= protoc
PROTOC_GEN_GO ?= $(shell $(GO) env GOPATH)/bin/protoc-gen-go
SWAG ?= $(GO) tool swag
MIGRATE ?= migrate
QUIVER_DATABASE_DSN ?=
OPENAPI_DIR ?= api/openapi
OPENAPI_FILE ?= $(OPENAPI_DIR)/quiver.v1.yaml

.PHONY: build build-quiver build-client fmt lint test test-unit test-integration test-race coverage proto proto-check swagger swagger-check openapi openapi-check migrate-up docker-up docker-down demo verify-demo load-smoke

build: build-quiver build-client

build-quiver:
	$(GO) build -o bin/quiver cmd/quiver/main.go

build-client:
	$(GO) build -o bin/quiver-client cmd/quiver-client/main.go

fmt:
	$(GO) fmt ./...

lint:
	$(GOLANGCI_LINT) run cmd/... internal/...

test: test-unit

test-unit:
	$(GO) test ./...

test-integration:
	QUIVER_DATABASE_DSN="postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@localhost:$(POSTGRES_HOST_PORT)/$(POSTGRES_DB)?sslmode=$(POSTGRES_SSLMODE)" \
	QUIVER_KAFKA_BROKERS="localhost:$(KAFKA_HOST_PORT)" \
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
	docker compose up -d --build

docker-down:
	docker compose down -v

demo:
	$(GO) run tools/restgen/main.go -target http://localhost:$(QUIVER_HOST_PORT) -key $(REST_INGEST_DEMO_CLIENT_KEY) -count 10
	$(GO) run tools/zeekloggen/main.go -file /tmp/zeek/conn.log -mode append -count 10
	$(GO) run tools/netflowgen/main.go -target localhost:$(NETFLOW_PORT) -count 5 -seq 10

verify-demo:
	./scripts/verify-demo.sh

load-smoke:
	$(GO) run tools/loadsmoke/main.go -rest http://localhost:$(QUIVER_HOST_PORT) -udp localhost:$(NETFLOW_PORT) -duration 30
