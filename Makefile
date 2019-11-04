export GO111MODULE=on

.PHONY: all build test clean distclean

build:
	go build -o spiffe-helper cmd/spiffe-helper/*.go

all: build test

vendor:
	go mod vendor

test:
	go test

clean:
	go clean

distclean:
	go clean -i
	rm -rf vendor dist

release:
	curl -sL https://git.io/goreleaser | bash || true
