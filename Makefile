BIN := bin/zruvix-cdn
VERSION := $(shell git describe --always --dirty 2>/dev/null || echo dev)

.PHONY: run build test lint hashpw deploy

run:
	go run ./cmd/cdn

build:
	mkdir -p bin
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/cdn

test:
	go test -race ./...

lint:
	go vet ./...
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipped"

hashpw:
	go run ./cmd/hashpw

deploy:
	./deploy/deploy.sh
