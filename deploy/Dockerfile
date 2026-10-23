# Build the snippet and dashboard, then a static Go binary, then a
# distroless image.
FROM node:25-alpine AS snippet
WORKDIR /src
RUN corepack enable
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
# Every workspace manifest must be present for --frozen-lockfile to match the
# lockfile; only the two web packages' dependencies are installed.
COPY web/snippet/package.json web/snippet/
COPY web/dashboard/package.json web/dashboard/
COPY integrations/node/package.json integrations/node/
COPY integrations/nextjs/package.json integrations/nextjs/
COPY examples/nextjs-signup/package.json examples/nextjs-signup/
COPY testing/e2e/package.json testing/e2e/
RUN pnpm install --frozen-lockfile --filter @doorkeep/snippet --filter @doorkeep/dashboard
COPY web/snippet web/snippet
COPY web/dashboard web/dashboard
COPY internal/api/assets internal/api/assets
RUN pnpm --filter @doorkeep/snippet build && pnpm --filter @doorkeep/dashboard build

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=snippet /src/internal/api/assets internal/api/assets
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /doorkeep ./cmd/doorkeep
# Pre-create the data dir owned by the distroless nonroot user (65532) so a
# fresh named volume inherits writable ownership.
RUN mkdir -p /data && chown 65532:65532 /data && chmod 0700 /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /doorkeep /usr/local/bin/doorkeep
COPY --from=build --chown=65532:65532 /data /data
ENV DOORKEEP_DATA_DIR=/data DOORKEEP_LISTEN=:8080 DOORKEEP_ADMIN_LISTEN=:8081
VOLUME /data
EXPOSE 8080 8081
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/doorkeep"]
CMD ["serve"]
