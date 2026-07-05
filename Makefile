.PHONY: build test vet clean

build:
	mkdir -p bin
	go build -o bin/omni-server ./cmd/omni-server
	go build -o bin/omnid ./cmd/omnid

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin
