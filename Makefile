# Application name
APP_NAME := yourAppName

# The binary to build (just the basename).
BIN := $(APP_NAME)

# This version-strategy uses git tags to set the version string
VERSION := $(shell git describe --tags --always --dirty)

# These are the values we want to pass for Version and BuildTime
BUILD_FLAGS := -ldflags "-X main.Version=$(VERSION)"

.PHONY: linux-amd64 clean

# Build for Linux on amd64 architecture
linux-amd64:
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(BIN)-linux-amd64

clean:
	rm -f $(BIN)-linux-amd64
