.PHONY: build test race vet vuln fmt check clean

VERSION := $(or $(shell git describe --tags 2>/dev/null | sed 's/^v//'),dev)

build:
	go build -ldflags "-X github.com/sendscore/sendscore/cmd.version=$(VERSION)" -o bin/sendscore .

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

fmt:
	gofmt -w .

check: vet race vuln
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

clean:
	rm -rf bin/ coverage.out coverage.html
