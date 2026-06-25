# syntax=docker/dockerfile:1
# Build on the NATIVE builder arch (no QEMU emulation), then cross-compile the Go
# binary to the target arch via GOARCH. Emulating `go mod download`/`go build` under
# QEMU is unstable (SIGSEGV in flate); Go cross-compiles cleanly instead.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/merlin ./cmd/merlin

# Trivy binary source (option b: copy static trivy binary from official image)
FROM aquasec/trivy:0.71.2 AS trivy

FROM registry.c3.ai/c3.ai/chainguard-base-fips:latest-202602172225
# Chainguard base already runs as nonroot (uid 65532) and ships CA certs.
COPY --from=build /out/merlin /usr/local/bin/merlin
# Merlin shells out to `trivy` at runtime for scanning. Without trivy on PATH,
# every scan fails infra-closed → 500. Copy the trivy binary from the official image.
# NOTE(Phase 8): trivy needs its vulnerability database. On first run, trivy downloads
# the DB from the internet (or via `trivy image --download-db-only`). The pod needs
# network egress for the DB, or configure TRIVY_CACHE_DIR / TRIVY_OFFLINE_SCAN / etc.
# Validate trivy runtime dependencies and DB access in Phase 8.
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
USER 65532:65532
ENV MERLIN_MODE=production MERLIN_CONFIG=/etc/merlin/config.yaml
ENTRYPOINT ["/usr/local/bin/merlin"]
