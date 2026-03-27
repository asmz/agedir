MODULE := github.com/asmz/agedir
BINARY := agedir
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

PLATFORMS := \
	darwin/amd64 \
	darwin/arm64 \
	linux/amd64 \
	linux/arm64 \
	windows/amd64 \
	windows/arm64

BUILD_DIR := dist

.PHONY: all build test clean fmt vet lint cross-build help

all: build

## build: Build for the current platform
build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) .

## test: Run all tests
test:
	go test ./...

## fmt: Format code
fmt:
	go fmt ./...

## vet: Run go vet
vet:
	go vet ./...

## cross-build: Build for all supported platforms
cross-build: clean-dist
	@mkdir -p $(BUILD_DIR)
	@$(foreach platform,$(PLATFORMS), \
		$(eval GOOS=$(word 1,$(subst /, ,$(platform)))) \
		$(eval GOARCH=$(word 2,$(subst /, ,$(platform)))) \
		$(eval EXT=$(if $(filter windows,$(GOOS)),.exe,)) \
		echo "Building $(GOOS)/$(GOARCH)..." && \
		CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(LDFLAGS) \
			-o $(BUILD_DIR)/$(BINARY)-$(GOOS)-$(GOARCH)$(EXT) . ; \
	)
	@echo "Cross-build complete. Binaries in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/

## clean-dist: Remove dist directory
clean-dist:
	rm -rf $(BUILD_DIR)

## clean: Remove built binaries
clean: clean-dist
	rm -f $(BINARY)

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/^## //'
