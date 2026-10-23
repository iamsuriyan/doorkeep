GO ?= go
BIN := bin/doorkeep

.PHONY: build dev test e2e lint fuzz snippet dashboard docs wp-plugin

build: snippet dashboard
	$(GO) build -o $(BIN) ./cmd/doorkeep

dev:
	$(GO) run ./cmd/doorkeep serve --config deploy/dev.yaml

test:
	$(GO) test -race -count=1 ./...
	pnpm --filter @doorkeep/snippet --filter @doorkeep/dashboard --filter @doorkeep/verify --filter @doorkeep/next test

FUZZTIME ?= 30s
fuzz:
	$(GO) test -run='^$$' -fuzz=FuzzDecode -fuzztime=$(FUZZTIME) ./internal/signals/payload
	$(GO) test -run='^$$' -fuzz=FuzzOpen -fuzztime=$(FUZZTIME) ./internal/token
	$(GO) test -run='^$$' -fuzz=FuzzParse -fuzztime=$(FUZZTIME) ./internal/signals/h2fp
	$(GO) test -run='^$$' -fuzz=FuzzParseRecords -fuzztime=$(FUZZTIME) ./internal/signals/tlsfp

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

# Installable WordPress plugin zip (Plugins > Add New > Upload, or WordPress.org).
wp-plugin:
	mkdir -p dist
	rm -f dist/doorkeep-wordpress.zip
	cd integrations/wordpress && zip -qr ../../dist/doorkeep-wordpress.zip doorkeep -x '*.DS_Store'
	@echo dist/doorkeep-wordpress.zip
