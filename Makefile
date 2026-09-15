APP_NAME := sbomber
GOCACHE ?= $(CURDIR)/.cache/go-build
CGO_ENABLED ?= 1

.PHONY: build run scan test vet lint fmt tidy ci

build:
	CGO_ENABLED=$(CGO_ENABLED) GOCACHE=$(GOCACHE) go build -o ./bin/$(APP_NAME) ./cmd/$(APP_NAME)

run:
	CGO_ENABLED=$(CGO_ENABLED) GOCACHE=$(GOCACHE) go run ./cmd/$(APP_NAME)

scan:
	CGO_ENABLED=$(CGO_ENABLED) GOCACHE=$(GOCACHE) go run ./cmd/$(APP_NAME) scan $(SCAN_ARGS) $(if $(SCAN_PATH),$(SCAN_PATH),..)

test:
	CGO_ENABLED=$(CGO_ENABLED) GOCACHE=$(GOCACHE) go test ./...

vet:
	CGO_ENABLED=$(CGO_ENABLED) GOCACHE=$(GOCACHE) go vet ./...

lint:
	CGO_ENABLED=$(CGO_ENABLED) GOCACHE=$(GOCACHE) golangci-lint run ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w ./cmd ./internal

tidy:
	CGO_ENABLED=$(CGO_ENABLED) go mod tidy

ci: fmt vet lint test
