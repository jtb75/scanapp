# Makefile
BINARY_NAME=scanapp
VERSION=$(shell git describe --tags --always || echo "unknown")
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

all: linux-amd64

linux-amd64:
	@echo "Building for Linux amd64"
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/scanapp

clean:
	@echo "Cleaning up"
	rm bin/$(BINARY_NAME)-linux-amd64
