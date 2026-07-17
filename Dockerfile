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

# Grype binary source: copy the static grype binary from the official image.
FROM anchore/grype:v0.98.0 AS grype

FROM ${RUNTIME_BASE}
# Chainguard base already runs as nonroot (uid 65532) and ships CA certs.
COPY --from=build /out/merlin /usr/local/bin/merlin
# Merlin shells out to `grype` at runtime for scanning. Without grype on PATH,
# every scan fails infra-closed → 500. Copy the grype binary from the official image.
# NOTE: grype needs its vulnerability database. On first run it downloads the DB
# from anchore's endpoints (or via `grype db update`). The pod needs network
# egress for the DB; cache dir is GRYPE_DB_CACHE_DIR (default ~/.cache/grype/db).
COPY --from=grype /grype /usr/local/bin/grype
USER 65532:65532
ENV MERLIN_MODE=production MERLIN_CONFIG=/etc/merlin/config.yaml
ENTRYPOINT ["/usr/local/bin/merlin"]
