.PHONY: build test vet clean dist docker

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -X main.version=$(VERSION)

build:
	mkdir -p bin
	go build -ldflags="$(LDFLAGS)" -o bin/omni-server ./cmd/omni-server
	go build -ldflags="$(LDFLAGS)" -o bin/omnid ./cmd/omnid

test:
	go test ./...

vet:
	go vet ./...

# Binaires statiques linux amd64 + arm64 dans dist/
dist:
	mkdir -p dist
	for arch in amd64 arm64; do \
		for cmd in omnid omni-server; do \
			CGO_ENABLED=0 GOOS=linux GOARCH=$$arch \
				go build -trimpath -ldflags="$(LDFLAGS)" \
				-o dist/$$cmd-linux-$$arch ./cmd/$$cmd || exit 1; \
		done; \
	done
	cd dist && sha256sum * > SHA256SUMS

docker:
	docker build --build-arg VERSION=$(VERSION) -t omniup-vpn:$(VERSION) .

clean:
	rm -rf bin dist
