.PHONY: build run test test-unit test-integration lint fmt proto-gen templ-gen mocks-gen tidy

GOBIN := $(shell go env GOPATH)/bin

build:
	go build -o bin/server ./cmd/server

run: build
	./bin/server

test: test-unit test-integration

# Everything except test/integration - fast, no Docker required.
test-unit:
	go test $$(go list ./... | grep -v /test/integration) -race -cover

# Requires a Docker daemon: spins up real Postgres/Redis containers via
# testcontainers-go and applies the actual migrations/ directory.
test-integration:
	go test ./test/integration/... -v -timeout 300s

lint:
	$(GOBIN)/golangci-lint run ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

# Regenerates Go code from proto/*.proto into internal/transport/grpc/pb.
# Requires protoc, protoc-gen-go and protoc-gen-go-grpc on PATH.
proto-gen:
	protoc -I proto -I /usr/include \
		--go_out=internal/transport/grpc/pb --go_opt=paths=source_relative \
		--go-grpc_out=internal/transport/grpc/pb --go-grpc_opt=paths=source_relative \
		proto/sessionproxy/v1/admin.proto proto/sessionproxy/v1/import.proto
	mv internal/transport/grpc/pb/sessionproxy/v1/*.go internal/transport/grpc/pb/
	rm -rf internal/transport/grpc/pb/sessionproxy

# Regenerates Go code from internal/transport/webui/templates/*.templ.
# Requires the templ CLI (go install github.com/a-h/templ/cmd/templ).
templ-gen:
	$(GOBIN)/templ generate

# Regenerates gomock fakes for internal/domain's repository interfaces.
# Requires mockgen (go install go.uber.org/mock/mockgen).
mocks-gen:
	$(GOBIN)/mockgen -source=internal/domain/domain.go -destination=internal/domain/mocks/mocks.go -package=mocks
