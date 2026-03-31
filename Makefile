APP_NAME := sbomber
GOCACHE ?= $(CURDIR)/.cache/go-build

.PHONY: build run scan test vet fmt tidy ci

build:
	GOCACHE=$(GOCACHE) go build -o ./bin/$(APP_NAME) ./cmd/$(APP_NAME)

run:
	GOCACHE=$(GOCACHE) go run ./cmd/$(APP_NAME)

scan:
	GOCACHE=$(GOCACHE) go run ./cmd/$(APP_NAME) scan $(SCAN_ARGS) $(if $(SCAN_PATH),$(SCAN_PATH),..)

test:
	GOCACHE=$(GOCACHE) go test ./...

vet:
	GOCACHE=$(GOCACHE) go vet ./...

fmt:
	gofmt -w ./cmd ./internal

tidy:
	go mod tidy

ci: fmt vet test
