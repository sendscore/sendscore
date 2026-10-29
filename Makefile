.PHONY: build test vet fmt check clean

VERSION := $(or $(shell git describe --tags 2>/dev/null | sed 's/^v//'),dev)

build:
	go build -ldflags "-X github.com/sendscore/sendscore/cmd.version=$(VERSION)" -o bin/sendscore .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

check: vet test
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

clean:
	rm -rf bin/ coverage.out coverage.html
