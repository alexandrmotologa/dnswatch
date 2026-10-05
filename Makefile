.PHONY: all build build-ui test lint clean run serve

BINARY_NAME=dnswatch

all: build

build-ui:
	cd ui && npm install && npm run build

build:
	go build -ldflags="-s -w" -o bin/$(BINARY_NAME) ./cmd/dnswatch

test:
	go test -v -race ./...

lint:
	go vet ./...

clean:
	rm -rf bin/ ui/dist

run:
	go run ./cmd/dnswatch $(DOMAIN)

serve:
	go run ./cmd/dnswatch serve --port 50080
