.PHONY: build test vet clean dist docker packages gui

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

# Application de barre d'état (systray) — compilation native uniquement
# (utilise les API graphiques de l'OS ; non incluse dans « dist »).
gui:
	mkdir -p bin
	go build -ldflags="$(LDFLAGS)" -o bin/omnid-gui ./cmd/omnid-gui

# Paquets .deb et .rpm (agent + serveur) via nfpm. Nécessite « dist ».
# La version nfpm ne doit pas contenir de préfixe « v ».
packages: dist
	@command -v nfpm >/dev/null || { echo "nfpm requis : go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; exit 1; }
	VER=$$(echo "$(VERSION)" | sed 's/^v//'); \
	for arch in amd64 arm64; do \
		cp dist/omnid-linux-$$arch dist/omnid.pkgbin; \
		cp dist/omni-server-linux-$$arch dist/omni-server.pkgbin; \
		for pkg in omnid omni-server; do \
			for fmt in deb rpm; do \
				ARCH=$$arch VERSION=$$VER nfpm package \
					-f packaging/$$pkg.nfpm.yaml -p $$fmt -t dist/ || exit 1; \
			done; \
		done; \
	done
	@rm -f dist/omnid.pkgbin dist/omni-server.pkgbin
	@ls -1 dist/*.deb dist/*.rpm

clean:
	rm -rf bin dist
