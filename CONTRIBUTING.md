# Contributing

## Setup

- Go 1.24 or newer, Node 22 or newer, pnpm 9, Docker (for e2e and Postgres tests).
- `make dev` runs the server with SQLite and the static example form.
- `make test` runs Go unit tests and snippet unit tests. `make e2e` runs the
  Playwright matrix (Chromium subset).

## Ground rules

- Every rule change ships with golden test updates in the same PR.
- A new signal must document its false-positive risk for Brave, Firefox with
  resistFingerprinting, Tor and assistive technology in `docs/design/v1.md`.
- No signal may add risk simply because it is absent.
- Raw signals are never persisted or logged. If a PR writes a raw IP, UA,
  WebGL string or coordinate to disk, it will not be merged.
- Reason codes and feature keys are generated from Go sources with
  `go generate`; do not edit the generated files.

## Licence

By contributing you agree your work is licensed under Apache-2.0. No CLA.
