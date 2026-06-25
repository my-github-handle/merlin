# Merlin

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Transparent Docker Registry V2 proxy that gates image publishing to ACR.
See [docs/specs.md](docs/specs.md) for the design.

## Building

Merlin uses [Mage](https://magefile.org) for build automation. Run `mage -l` to list available targets:

- `mage build` - Compiles the merlin binary to `./bin/merlin`
- `mage test` - Runs the unit test suite
- `mage testCover` - Runs tests with coverage reporting
- `mage integration` - Runs integration tests (requires live backends)
- `mage lint` - Checks code formatting with gofmt
- `mage vet` - Runs go vet static analysis
- `mage tidy` - Tidies go.mod and go.sum
- `mage clean` - Removes build artifacts

## License

Licensed under the [Apache License 2.0](LICENSE).
