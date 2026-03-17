<p align="center">
  <img src="./docs/assets/Banner.png" alt="SBOMber banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/Xsamsx/SBOMber/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Xsamsx/SBOMber/actions/workflows/ci.yml/badge.svg" /></a>
  <img alt="Go version" src="https://img.shields.io/badge/Go-1.26-0f766e?style=flat-square&logo=go" />
  <img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-111827?style=flat-square" />
  <img alt="Platforms" src="https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20Windows-c2410c?style=flat-square" />
  <img alt="Targets" src="https://img.shields.io/badge/Stacks-npm%20%7C%20Python%20%7C%20Maven%20%7C%20Ruby%20%7C%20Go-1d4ed8?style=flat-square" />
</p>

<p align="center">
  <strong>Scan a folder full of repositories. Generate SBOMs without handholding.</strong>
</p>

SBOMber is an open-source Go CLI for scanning directories of locally cloned Git repositories and generating software bill of materials artifacts at scale.

The first milestone is clear: discover repositories, detect their ecosystems, and generate standards-based SBOMs. After that, the project expands into dependency metadata, outdated package analysis, vulnerability reporting, and supply-chain signals.

## What It Is Built For

- scanning a workspace that contains many Git repositories
- detecting repo stacks from manifests and lockfiles
- generating `CycloneDX` and `SPDX` output
- handling direct and transitive dependencies
- fitting into CI, scripts, and local security workflows

## Platform Targets

SBOMber is being built as a cross-platform Go CLI for:

- `macOS`
- `Linux`
- `Windows`

Current development is source-first. Planned distribution targets include:

- GitHub Releases binaries
- `go install`
- Homebrew formula
- Scoop package

## Ecosystem Targets

The current product direction is multi-stack support for repositories using:

- `npm` / `package-lock.json`
- `Python` / `requirements.txt`, `pyproject.toml`, lockfiles
- `Maven` / `pom.xml`
- `Ruby` / `Gemfile.lock`
- `Go` / `go.mod`, `go.sum`

## Current Status

The repo already has a clean foundation:

- working Go CLI entrypoint
- recursive Git repository discovery
- CI for formatting, vetting, and tests
- OSS community files for issues, PRs, contributions, and security reporting

SBOM extraction backends are the next implementation step.

## Quick Start

### Prerequisites

- Go `1.26` or newer

### Build from source

```bash
make tidy
make build
./bin/sbomber scan ../
```

### Run without building

```bash
go run ./cmd/sbomber scan ../
```

## Example Output

```text
Found 3 repositories under /workspace
- backend-api  /workspace/backend-api
- design-system  /workspace/design-system
- payments  /workspace/payments
```

## Roadmap

- repository discovery and workspace scanning
- ecosystem detection from manifests and lockfiles
- SBOM generation for supported stacks
- metadata and outdated dependency reporting
- vulnerability and supply-chain analysis

## Project Layout

```text
cmd/sbomber/        CLI entrypoint
internal/cli/       command parsing and execution
internal/discovery/ repository scanning logic
docs/assets/        branding and repository visuals
.github/            CI and community health files
```

## Development

```bash
make fmt
make test
make vet
make ci
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup and contribution workflow.

## License

Licensed under [Apache-2.0](./LICENSE).
