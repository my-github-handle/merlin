# Merlin

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Transparent Docker Registry V2 proxy that gates image publishing to ACR.

- **[docs/USAGE.md](docs/USAGE.md)** — how to publish an image and get Trivy scan results.
- **[docs/specs.md](docs/specs.md)** — design and requirements.
- **Built-in dashboard** — a read-only observability UI (activity, health,
  vulnerabilities, scan reports) served on `:8080` by default
  (`server.dashboard_addr`, or `off` to disable). See
  [docs/USAGE.md](docs/USAGE.md#observability-dashboard).

## Building

Merlin uses [Mage](https://magefile.org) for build automation. Run `mage -l` to list available targets:

- `mage build` - Compiles the merlin binary to `./bin/merlin`
- `mage test` - Runs the unit test suite
- `mage testCover` - Runs tests with coverage reporting
- `mage integration` - Runs integration tests (requires live backends; tests whose
  backend is missing **skip**, so a green run does not mean they ran)
- `mage testPromoteQueue` - Runs the promotion-queue integration suite against a
  throwaway **cluster-enabled** Valkey it starts in Docker. Cluster mode is required,
  not cosmetic: the queue's Claim/Recover are multi-key Lua scripts, and only a
  cluster enforces the same-slot rule that once made every claim fail with CROSSSLOT
- `mage lint` - Checks code formatting with gofmt
- `mage vet` - Runs go vet static analysis
- `mage tidy` - Tidies go.mod and go.sum
- `mage clean` - Removes build artifacts

## License

Licensed under the [Apache License 2.0](LICENSE).
