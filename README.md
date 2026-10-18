<p align="center">
  <img src="./docs/assets/Banner.png" alt="SBOMber banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/fluxsecurity/SBOMber/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/fluxsecurity/SBOMber/actions/workflows/ci.yml/badge.svg" /></a>
  <img alt="Go version" src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go" />
  <img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-blue?style=flat-square" />
</p>

<p align="center">
  <strong>Scan repositories. Generate SBOMs. Find vulnerabilities. Verify accuracy.</strong>
</p>

---

SBOMber is a high-performance, open-source CLI that scans local and remote Git repositories, extracts dependencies, generates SBOM artifacts (CycloneDX/SPDX), finds CVEs, and provides supply chain health insights.

## Highlights

- **Remote GitHub scanning** - Scan any public/private repo without cloning
- **Parallel processing** - Fetch manifests concurrently for 10x faster scans
- **Dependency chain tracking** - Trace how any package enters your project
- **SBOM verification** - Compare output against ground truth with precision/recall metrics
- **Supply chain health** - Risk scoring based on maintainer activity, contributors, and more
- **Supports** - npm, Python, Go, Maven, Ruby ecosystems

## Quick Start

```bash
# Build
make build

# Run interactive TUI
./bin/sbomber

# Scan local repos
./bin/sbomber scan /path/to/repos --format cyclonedx --include-vulnerabilities

# Scan GitHub repos directly (no clone needed!)
./bin/sbomber github https://github.com/expressjs/express
```

**Requirements:** Go 1.26.9+ and [Grype](https://github.com/anchore/grype) (for vulnerability scanning).
For GitHub scans, set `GITHUB_TOKEN` or just log in with the GitHub CLI (`gh auth login`); SBOMber uses that login automatically when `GITHUB_TOKEN` is unset.

## Features

| Feature | Status |
|---------|--------|
| Interactive TUI | done |
| Multi-repo Git scanning | done |
| npm/yarn dependencies | done |
| Python requirements.txt | done |
| Maven pom.xml | done |
| Ruby Gemfile.lock | done |
| Go go.mod | done |
| CycloneDX export | done |
| SPDX export | done |
| Grype vulnerability scan | done |
| HTML vulnerability report | done |
| Remote GitHub scanning | done |
| Parallel manifest fetching | done |
| Supply chain health metrics | done |
| Dependency chain tracing | done |
| SBOM accuracy verification | done |
| Direct/transitive filtering | done |

---

## Usage

### Interactive Mode

```bash
./bin/sbomber
```

Navigate with arrow keys, select with Enter. The TUI provides guided workflows for all features.

After a local scan of a single repo, the results screen offers **Check ground-truth accuracy** — point it at a ground-truth SBOM (see [Verified accuracy](#verified-accuracy) below) and it runs the same comparison `sbomber verify` does, inline. Only offered when the scan covered exactly one repo, since a comparison needs exactly one generated SBOM to be meaningful.

### Local Scanning

```bash
# Scan current directory
./bin/sbomber scan .

# Scan with both SBOM formats
./bin/sbomber scan /path/to/repos --format both

# Include vulnerability scanning
./bin/sbomber scan /path/to/repos --include-vulnerabilities
```

### GitHub Remote Scanning

Scan any GitHub repository directly via API - no cloning required.

```bash
# Basic scan
./bin/sbomber github https://github.com/expressjs/express

# With supply chain health metrics
./bin/sbomber github --health https://github.com/django/django

# With vulnerability scanning
./bin/sbomber github --include-vulnerabilities https://github.com/lodash/lodash

# Multiple repos at once
./bin/sbomber github https://github.com/org/repo1 https://github.com/org/repo2
```

**Authentication:** Set `GITHUB_TOKEN` for higher rate limits (5000 req/hr vs 60 req/hr).

```bash
export GITHUB_TOKEN=ghp_your_token_here
```

### Dependency Chain Tracing

Understand how dependencies enter your project.

```bash
# Trace a specific package
./bin/sbomber trace . lodash

# Show full dependency tree
./bin/sbomber trace . express --tree

# Filter by ecosystem
./bin/sbomber trace . --list --ecosystem npm

# Filter transitive dependencies only
./bin/sbomber trace . --list --type transitive

# Show potential false positives (test/example deps)
./bin/sbomber trace . --fp --list
```

### Vulnerable-function localisation

Work out which function an advisory actually implicates, so usage evidence
can be compared against it instead of against the whole package.

```bash
# Read the scan's canonical-scan.json, write localisation.json
./bin/sbomber localise --canonical-scan out/canonical-scan.json --out out/localisation.json

# Keep the per-method evidence trace and run every method for comparison
GITHUB_TOKEN=$(gh auth token) ./bin/sbomber localise --canonical-scan out/canonical-scan.json \
  --out out/localisation.json --trace out/localisation-trace.json --all-methods
```

Methods run in fallback order, cheapest and most reliable first: structured
advisory metadata, the fix commit the advisory links to, function names in the
advisory prose, and finally a diff of the vulnerable and fixed npm tarballs.
A finding no method can localise is reported as `unknown` and falls back to
package-level treatment; the unknown rate is a result, not a failure.

Downloaded package code is **never executed**. Tarballs are verified against
the registry's integrity value, read in memory, and every artefact records
`executed: false`. The output follows `contracts/localisation.schema.json`.
Measured behaviour on ten curated CVEs is in `spikes/localisation/`.

### Vulnerability Reachability (Go)

Uses govulncheck's call graph to find the vulnerable functions your code
actually calls, and scores only those, 0-100%: severity (CVSS from NVD, up
to 40) + exploit chance (EPSS, up to 25) + known exploited (CISA KEV, +20) +
call proximity (your code calls it +15, via a dependency +8).
0-20% Minimal priority, 21-39% Low, 40-69% Medium, 70-100% High.

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest   # one-time

./bin/sbomber reachability .          # call paths, file:line, score breakdown
./bin/sbomber reachability . --json   # for CI
```

Set `NVD_API_KEY` for faster CVSS lookups (results are cached for 24h).
See [docs/design/reachability.md](docs/design/reachability.md).

### SBOM Verification

Compare your generated SBOM against a ground truth to measure accuracy.

```bash
# Compare against a reference SBOM
./bin/sbomber verify reference.cdx.xml my-output.cdx.xml

# Output as JSON (for CI/CD)
./bin/sbomber verify reference.json generated.json --json
```

**Output format** (field layout only — these are placeholder digits, not a
measured result; see *Verified accuracy* below for a real one):
```
╔══════════════════════════════════════════════════════════════╗
║                    SBOM VERIFICATION REPORT                  ║
╚══════════════════════════════════════════════════════════════╝

│ Precision:        NN.N%  (correct / total reported)          │
│ Recall:           NN.N%  (found / total in ground truth)     │
│ F1 Score:         NN.N%  (harmonic mean)                     │

Overall Grade: <grade>
```

### Verified accuracy

No accuracy figure for SBOMber is quoted anywhere (README, report, poster,
client conversation) unless it has a committed ground-truth fixture and a
`sbomber verify` run behind it — an unsourced percentage is an integrity
problem, not just an accuracy one.

The one currently on record:
[`testdata/fixtures/ground-truth/npm-basic`](testdata/fixtures/ground-truth/npm-basic)
— method, fixture, and full `sbomber verify` output committed, run twice:
before and after the npm package-lock reconciliation fix
([`docs/design/npm-identity-reconciliation.md`](docs/design/npm-identity-reconciliation.md)).
Precision/Recall/F1 were 100% in both runs; **Version Accuracy went from 0%
to 100%** once the parser started reconciling `package.json` ranges against
`package-lock.json` resolutions instead of reporting the raw semver range.
See the fixture's `METHOD.md` for both runs' numbers and what's still not
covered by this one small fixture (the nested-version case, covered instead
by dedicated unit tests — see that same design doc).

That comparison is no longer just a one-time snapshot: `go test ./...`
reruns it automatically (`TestGroundTruthFixturesDoNotRegress`) and fails
the build if a future change drops any metric below what's committed —
the same mechanism that would have caught the bug above the moment it was
reintroduced, rather than requiring someone to notice.

---

## Performance

SBOMber uses **parallel processing** for maximum speed:

| Operation | Approach | Benefit |
|-----------|----------|---------|
| Manifest fetching | Concurrent goroutines | 10x faster for multi-manifest repos |
| Health resolution | Worker pool (10 workers) | Parallel API calls per dependency |
| File parsing | Streaming parsers | Low memory footprint |

**Example:** Scanning Facebook React (157 manifest files) completes in ~2 seconds.

---

## Output

Reports are saved to `~/.sbomber/reports/`:

```
~/.sbomber/reports/
├── my-project_abc123/
│   ├── sbom-cyclonedx.xml      # CycloneDX 1.5
│   ├── sbom.spdx               # SPDX 2.3
│   └── vulnerability-report.html
└── github-scan_def456/
    └── expressjs_express/
        ├── sbom-cyclonedx.xml
        └── vulnerability-report.html
```

### HTML Vulnerability Report

Interactive report with:
- Risk score (0-100%) for every vulnerability, with its breakdown: CVSS ÷ 10 × 40 + EPSS × 25 + CISA KEV 20 + direct dependency 15 / transitive 8.
  0-20% Minimal priority, 21-39% Low, 40-69% Medium, 70-100% High; overall project risk, per-band counts and a risk filter
- Severity breakdown (Critical/High/Medium/Low)
- Direct vs transitive dependency filtering
- Test data detection (auto-flags fixtures/examples)
- False positive marking
- CVE links to NVD/GitHub advisories

---

## Supply Chain Health

When scanning with `--health`, SBOMber evaluates each dependency:

| Metric | What it measures |
|--------|------------------|
| Last commit | Days since last activity |
| Contributors | Bus factor / maintainer risk |
| Stars | Community adoption |
| License | Compliance risk |

Risk levels: **Low** (healthy) / **Medium** (monitor) / **High** (investigate)

---

## Known Limitations

### JavaScript/TypeScript usage evidence and reachability (Component 2)

`sbomber usage` analyses local JavaScript/TypeScript application source and
matches imports and calls to npm package occurrences in `canonical-scan.json`.
Remote manifest scanning does not replace the local source checkout needed
for this analysis. The Go-only `sbomber reachability` command is a separate
capability; its results do not establish JavaScript/TypeScript reachability.

An import, a call site and a resolved call path are different levels of
evidence. A resolved path shows a statically traceable route from an entry
point to a dependency call; it does not prove that the path executes in
production or that a vulnerability is exploitable. `unknown` means the path
could not be established; `not_analysed` means reachability was not analysed.
Neither means the call cannot happen.

| Limitation | What it means when reviewing a finding |
|---|---|
| **Application source only** | Dependency source is not parsed, so `app -> A -> B` is not traced through A. If B is a transitive occurrence it is recorded as `nested_under_dependency` and stays unknown. If B is also a direct dependency with no application import, it can instead receive `not_imported_by_analysed_source` and a `no_usage_detected` / `lower_priority` decision even when A uses it. Check dependency behaviour manually before relying on that result. |
| **Dynamic calls and function references** | Runtime-computed member access can produce an unresolved call. Calls through copied function references, such as `const f = _.merge; f()` or `const {merge} = _; merge()`, can be missing from `callSites` entirely. The import may have evidence level 1 and lead to `no_usage_detected`; the current analyser does not emit `call_through_variable` for these examples. Inspect aliases and function references manually. |
| **Callbacks and framework invocation** | Calls into callbacks supplied to third-party code, dependency injection, decorators and framework lifecycle hooks may have no resolved path. Statically recognised route handlers are a limited supported case, not general framework support. |
| **Route factories and anonymous exports** | A factory call such as `app.use(path, route())` is not recognised as a route entry point. A default-exported anonymous function such as `export default async () => {}` has no named call target for the current graph. Check these entry points manually. |
| **Re-exports and dynamic import promises** | Do not assume re-export chains are followed to the dependency call. Promise-based uses such as `import('pkg').then(...)` remain unresolved; supported awaited imports do not make every dynamic-import pattern supported. |
| **Syntax errors and grammar gaps** | Files with a parser error yield no semantic usage evidence. They increase public `filesParsedWithErrors` and make analysis `partial`, but that counter does not name the file; `parseFailures` is reserved for failures without a usable parse tree. This can include valid syntax unsupported by the grammar, such as some Flow syntax. Unmatched packages receive `import_site_parse_failed`. Inspect the source or parser output to find the affected files. |
| **Unsupported source formats** | Vue, Svelte, Astro, MDX and Marko files make analysis `partial`. Internally they are skipped as `unsupported_source_format`; the public graph reports only the `filesSkipped` count, not their filenames or that skip reason. Unmatched packages can receive `excluded_by_limits`. Check these source files manually. |
| **TypeScript path aliases** | Only the root `tsconfig.json` is read. `extends` and nested configurations are not followed. Imports requiring an unavailable alias mapping can remain unresolved as `not_in_inventory`, with no resolved call path. Check configuration and target files; an unresolved import is not proof of no usage. |
| **Computed import scope** | A computed `require(variable)` or `import(variable)` in analysed source prevents unmatched packages in that repository from being treated as not imported. Excluded build/output trees do not participate. The summary detail names only the first computed import in lexicographic file order; inspect all `dynamic_computed` observations for the other locations. |
| **Excluded files and coverage** | Directories named `.git`, `node_modules`, `vendor`, `dist`, `build`, `out`, `coverage`, `.next` or `generated` are pruned wherever they appear. Even handwritten `src/out/server.js` is excluded. Analysis can still be `complete`, and unmatched packages can receive `not_imported_by_analysed_source`. Lines over 4,000 bytes also trigger the minified-file skip. Check the repository layout, counters and limits; a complete status covers only the declared scope. |

These are the current rules. Any changes to computed-import scope or MDX
handling are tracked in [issue #151](https://github.com/fluxsecurity/SBOMber/issues/151).
No usage evidence found within the analysed scope is not proof that a package
is unused or a vulnerability cannot be exploited. The current VEX exporter never automatically emits `not_affected`, regardless
of the usage evidence: both `no_usage_detected` and unknown decisions export as
`under_investigation`.

For implementation details, see the
[usage-graph architecture](docs/design/usage-graph-architecture.md#16-known-limitations).
Per-construct usage precision/recall ([#149](https://github.com/fluxsecurity/SBOMber/issues/149))
and reachability measurements ([#152](https://github.com/fluxsecurity/SBOMber/issues/152))
are separate evaluations. This section makes no accuracy or resolution-rate claim.

---

## Development

```bash
make fmt      # format code
make test     # run tests  
make vet      # run go vet
make build    # build binary
make ci       # run full CI pipeline
```

## License

[Apache-2.0](./LICENSE)
