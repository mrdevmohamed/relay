.PHONY: build test test-race lint run clean worker-typecheck worker-test

GO ?= go
BIN ?= bin/relay-client
CLIENT_DIR ?= client

build:
	cd $(CLIENT_DIR) && $(GO) build -o ../$(BIN) ./cmd/relay-client

test:
	cd $(CLIENT_DIR) && $(GO) test ./...

test-race:
	cd $(CLIENT_DIR) && $(GO) test -race ./...

lint:
	cd $(CLIENT_DIR) && $(GO) vet ./... && gofmt -l .

run:
	cd $(CLIENT_DIR) && $(GO) run ./cmd/relay-client --config ./configs/client.example.yaml

clean:
	rm -rf bin $(CLIENT_DIR)/bin

worker-typecheck:
	cd worker && npm run typecheck

worker-test:
	cd worker && npm test
