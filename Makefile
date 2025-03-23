.PHONY: test test-integration test-coverage lint build clean

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOLINT=golangci-lint

# Binary name
BINARY_NAME=ncmec

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_TAG ?= $(shell git describe --tags --exact-match 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION_PKG := go.lumeweb.com/ncmec/build

# Linker flags
LDFLAGS += -X $(VERSION_PKG).Version=$(VERSION)
LDFLAGS += -X $(VERSION_PKG).GitCommit=$(GIT_COMMIT)
LDFLAGS += -X $(VERSION_PKG).GitTag=$(GIT_TAG)
LDFLAGS += -X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

all: test lint build

build:
	$(GOBUILD) -o $(BINARY_NAME) -ldflags '$(LDFLAGS)' -v

test:
	$(GOTEST) -v ./... -short -ldflags '$(LDFLAGS)'

test-integration:
	$(GOTEST) -v ./... -tags=integration -ldflags '$(LDFLAGS)'

test-coverage:
	$(GOTEST) -v ./... -short -coverprofile=coverage.out -ldflags '$(LDFLAGS)'
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

lint:
	$(GOLINT) run

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f coverage.out
	rm -f coverage.html

tidy:
	$(GOMOD) tidy

# Downloads dependencies
deps:
	$(GOMOD) download

# Install golangci-lint
install-lint:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v1.55.2