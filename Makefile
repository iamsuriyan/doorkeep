GO ?= go
BIN := bin/doorkeep

.PHONY: build dev test e2e lint snippet dashboard docs

build: snippet dashboard
	$(GO) build -o $(BIN) ./cmd/doorkeep

dev:
	$(GO) run ./cmd/doorkeep serve --config deploy/dev.yaml

test:
	$(GO) test -race -count=1 ./...
	pnpm --filter @doorkeep/snippet --filter @doorkeep/dashboard --filter @doorkeep/verify --filter @doorkeep/next test

docs:
	$(GO) run ./tools/docgen -out docs/reference

e2e: snippet
	xvfb-run -a -s "-screen 0 1920x1080x24" pnpm --filter e2e test

lint:
	$(GO) vet ./...
	staticcheck ./...

snippet:
	pnpm --filter @doorkeep/snippet build

dashboard:
	pnpm --filter @doorkeep/dashboard build
