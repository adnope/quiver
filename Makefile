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

.PHONY: build build-quiver build-client frontend-install frontend-typecheck frontend-test frontend-build fmt lint test test-unit test-up test-down test-integration test-all test-race coverage proto proto-check swagger swagger-check openapi openapi-check migrate-up dev-up dev-down dev-demo load-smoke dev-load-smoke verify-demo verify-vector-shipper

build: build-quiver build-client

build-quiver: frontend-build
	$(GO) build -o bin/quiver cmd/quiver/main.go

build-client:
	$(GO) build -o bin/quiver-client cmd/quiver-client/main.go

frontend-install:
	npm --prefix frontend ci

frontend-typecheck:
	npm --prefix frontend run typecheck

frontend-test:
	npm --prefix frontend run test

frontend-build: frontend-install
	npm --prefix frontend run build
	rm -rf internal/web/dist
	mkdir -p internal/web/dist
	cp -R frontend/dist/. internal/web/dist/
	printf '%s\n' "placeholder for Go embed before frontend assets are built" > internal/web/dist/keep.txt

fmt:
	$(GO) fmt ./...

lint:
	$(GOLANGCI_LINT) run cmd/... internal/...

test: test-unit

test-unit:
	$(GO) test ./...

test-up:
	docker compose -f docker-compose.test.yml -p quiver-test up -d --build
	@for i in $$(seq 1 30); do \
		if docker exec quiver-test-timescaledb pg_isready -U postgres -d quiver >/dev/null 2>&1; then \
			echo "TimescaleDB test service is healthy!"; \
			break; \
		fi; \
		if [ "$$i" -eq 30 ]; then \
			echo "TimescaleDB test service did not become healthy."; \
			docker compose -f docker-compose.test.yml -p quiver-test logs timescaledb; \
			exit 1; \
		fi; \
		echo "Waiting for TimescaleDB test service..."; \
		sleep 2; \
	done
	@for i in $$(seq 1 30); do \
		if docker exec quiver-test-redpanda rpk cluster info --brokers=localhost:9092 >/dev/null 2>&1; then \
			echo "Redpanda test service is healthy!"; \
			break; \
		fi; \
		if [ "$$i" -eq 30 ]; then \
			echo "Redpanda test service did not become healthy."; \
			docker compose -f docker-compose.test.yml -p quiver-test logs kafka; \
			exit 1; \
		fi; \
		echo "Waiting for Redpanda test service..."; \
		sleep 2; \
	done

test-down:
	docker compose -f docker-compose.test.yml -p quiver-test down -v

test-integration:
	QUIVER_DATABASE_DSN="postgres://postgres:postgres@localhost:5434/quiver?sslmode=disable" \
	QUIVER_KAFKA_BROKERS="localhost:9096" \
	$(GO) test -tags=integration ./...

test-all: test-up test-unit test-integration test-down

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

dev-up:
	docker compose up -d --build --scale quiver=3

dev-down:
	docker compose down

dev-demo:
	$(GO) run tools/restgen/main.go -target http://localhost:$(QUIVER_HOST_PORT) -key $(REST_INGEST_DEMO_CLIENT_KEY) -count 10
	$(GO) run tools/zeekloggen/main.go -target http://localhost:$(QUIVER_HOST_PORT) -key $(ZEEK_SHIPPER_DEMO_KEY) -count 10
	$(GO) run tools/netflowgen/main.go -target localhost:$(NETFLOW_PORT) -count 5 -seq 10

verify-demo:
	./scripts/verify-demo.sh

verify-vector-shipper:
	./scripts/verify-vector-shipper.sh

load-smoke:
	$(GO) run tools/loadsmoke/main.go \
		-rest http://localhost:$(QUIVER_HOST_PORT) \
		-udp localhost:$(NETFLOW_PORT) \
		-db "$(QUIVER_DATABASE_DSN_HOST)" \
		-zeek-mode http \
		-admin-key "$(QUIVER_DEMO_ADMIN_API_KEY)" \
		-client-key "$(REST_INGEST_DEMO_CLIENT_KEY)" \
		-zeek-key "$(ZEEK_SHIPPER_DEMO_KEY)" \
		-duration 30

dev-load-smoke: load-smoke
