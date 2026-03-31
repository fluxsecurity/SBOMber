# SBOMber Development Status

Last updated: 2026-03-26 AEDT

## Current State

`SBOMber` is in active Phase 1 development.

Implemented so far:

- recursive discovery of local Git repositories
- ecosystem detection for:
  - `npm`
  - `python`
  - `maven`
  - `ruby`
  - `go`
- interactive CLI landing screen with:
  - scan current folder
  - scan custom folder
  - version
  - help
- path handling for normal paths and `~/...`
- export format selection in the CLI:
  - `CycloneDX`
  - `SPDX`
  - `Both`
- `npm` direct dependency parsing from `package.json`
- `npm` transitive dependency parsing from `yarn.lock`
- CLI summaries for npm repos showing:
  - direct dependencies from `package.json`
  - transitive dependencies from `yarn.lock`
  - total known dependencies
  - sample package names

## Verified Working

Tested commands:

```bash
make test
make run
make scan SCAN_PATH=/Users/trysudo/Documents/project/ICT_Project_A
make scan SCAN_PATH=/Users/trysudo/Documents/project/ICT_Project_A/prettier
make scan SCAN_PATH=/Users/trysudo/Documents/project/ICT_Project_A/prettier SCAN_ARGS='--format both'
```

Observed results:

- `SBOMber` is detected as `[go]`
- `prettier` is detected as `[npm]`
- `prettier` currently reports:
  - `146` direct dependencies from `package.json`
  - `953` transitive dependencies from `yarn.lock`
  - `1099` total known dependencies

## Important Files

- `cmd/sbomber/main.go`
- `internal/cli/cli.go`
- `internal/cli/cli_test.go`
- `internal/discovery/discovery.go`
- `internal/ecosystem/detect.go`
- `internal/ecosystem/detect_test.go`
- `internal/deps/model.go`
- `internal/npm/parse.go`
- `internal/npm/parse_test.go`
- `internal/npm/yarn_lock.go`
- `internal/npm/yarn_lock_test.go`
- `Makefile`

## What Is Not Done Yet

Still missing:

- actual SBOM file export
- actual `CycloneDX` output generation
- actual `SPDX` output generation
- output directory selection
- non-npm manifest parsing beyond ecosystem detection
- Go dependency extraction from `go.mod` / `go.sum`
- Python, Maven, Ruby dependency extraction
- vulnerability scanning integration
- reachability analysis research/prototype

## Next Recommended Step

The next sensible development step is:

1. implement the first real SBOM exporter
2. start with a minimal `CycloneDX` JSON file for npm repos
3. write the file to disk based on the selected export format
4. then repeat the same pattern for `SPDX`

## Resume Prompt

Next time, say:

`Open SBOMber/DEVELOPMENT_STATUS.md and continue from the next recommended step.`
