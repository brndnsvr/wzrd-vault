VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
BINARY  := wzrd-vault

.PHONY: build install test lint clean coverage

build:
	go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY) .

install: build
	install -m 755 bin/$(BINARY) $(HOME)/.local/bin/$(BINARY)

test:
	go test ./... -race -count=1

coverage:
	go test ./... -race -count=1 -coverprofile=coverage.out
	go tool cover -func=coverage.out

lint:
	golangci-lint run

clean:
	rm -rf bin/ coverage.out
