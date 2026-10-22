GO ?= go
BIN := bin/doorkeep

.PHONY: build dev test e2e lint snippet dashboard

build: snippet dashboard
	$(GO) build -o $(BIN) ./cmd/doorkeep

dev:
	$(GO) run ./cmd/doorkeep serve --config deploy/dev.yaml

test:
	$(GO) test -race -count=1 ./...
	pnpm -r test

e2e:
	pnpm --filter e2e test

lint:
	$(GO) vet ./...
	staticcheck ./...

snippet:
	pnpm --filter @doorkeep/snippet build

dashboard:
	pnpm --filter @doorkeep/dashboard build
