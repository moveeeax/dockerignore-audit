BIN := dist/dockerignore-audit
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet fmt lint clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/dockerignore-audit

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# self-audit: the tool checks its own build context
lint: build
	./$(BIN) -path .

clean:
	rm -rf dist
