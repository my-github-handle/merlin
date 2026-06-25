# syntax=docker/dockerfile:1
# Runtime base. Defaults to the public Chainguard wolfi base (glibc, nonroot, CA
# certs). Override RUNTIME_BASE at build time to use an organization-specific base
# (e.g. a FIPS/hardened variant from a private registry):
#   docker build --build-arg RUNTIME_BASE=<your-registry>/<image>:<tag> .
# Declared in the global scope so it is usable in the runtime `FROM` below.
ARG RUNTIME_BASE=cgr.dev/chainguard/wolfi-base:latest

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

FROM ${RUNTIME_BASE}
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
