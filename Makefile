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

# Binaires statiques dans dist/ : agent pour linux/macOS/windows,
# serveur pour linux.
dist:
	mkdir -p dist
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch \
			go build -trimpath -ldflags="$(LDFLAGS)" \
			-o dist/omni-server-linux-$$arch ./cmd/omni-server || exit 1; \
		for os in linux darwin; do \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
				go build -trimpath -ldflags="$(LDFLAGS)" \
				-o dist/omnid-$$os-$$arch ./cmd/omnid || exit 1; \
		done; \
	done
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		go build -trimpath -ldflags="$(LDFLAGS)" \
		-o dist/omnid-windows-amd64.exe ./cmd/omnid
	cd dist && sha256sum * > SHA256SUMS

docker:
	docker build --build-arg VERSION=$(VERSION) -t omniup-vpn:$(VERSION) .

clean:
	rm -rf bin dist
