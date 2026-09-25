BIN := dist/dockerignore-audit

.PHONY: build test vet fmt lint clean

build:
	go build -o $(BIN) ./cmd/dockerignore-audit

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
